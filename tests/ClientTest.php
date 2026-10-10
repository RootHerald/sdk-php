<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\CertifiedKey;
use Rootherald\Client;
use Rootherald\Exceptions\ActivationRefusedException;
use Rootherald\Exceptions\AdmissionRefusedException;
use Rootherald\Exceptions\ChallengeException;
use Rootherald\Exceptions\ExpectedNotEnforcedException;
use Rootherald\Exceptions\HttpException;
use Rootherald\Exceptions\InvalidAskException;
use Rootherald\Exceptions\InvalidEvidenceException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\Exceptions\QuotaExceededException;
use Rootherald\Exceptions\RateLimitedException;
use Rootherald\Exceptions\UnknownPolicyException;
use Rootherald\KeyChallenge;
use Rootherald\Verdict;

final class ClientTest extends TestCase
{
    private const NONCE = 'q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k';
    private const CHALLENGE = 'rhc1.' . self::NONCE . '.eyJhc2siOlsiaWRlbnRpdHkiLCJwb3N0dXJlIl19';
    private const KEY_CHALLENGE = 'rhk1c.' . self::NONCE . '.eyJwdXJwb3NlIjoic2lnbiJ9';

    private function bg(callable $transport): Client
    {
        return new Client(
            secretKey: 'rh_sk_test_xxx',
            baseUrl: 'https://api.example.test',
            httpTransport: $transport,
        );
    }

    /** @return array{status: int, body: string} */
    private static function challengeResponse(): array
    {
        return ['status' => 200, 'body' => json_encode([
            'nonce' => self::NONCE, 'challenge' => self::CHALLENGE, 'expiresAt' => '2030-01-01T00:00:00Z',
        ])];
    }

    /** @return array{status: int, body: string} */
    private static function keyChallengeResponse(): array
    {
        return ['status' => 200, 'body' => json_encode([
            'nonce' => self::NONCE, 'keyChallenge' => self::KEY_CHALLENGE, 'expiresAt' => '2030-01-01T00:00:00Z',
        ])];
    }

    /** @return array<string, mixed> */
    private static function certifiedEcKey(): array
    {
        return [
            'deviceId' => 'dev-9',
            'keyId' => 'key_1',
            'purpose' => 'sign',
            'alg' => 'ES256',
            'jwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'eHg', 'y' => 'eXk'],
            'hardwareBound' => true,
            'certifiedAt' => '2030-01-01T00:01:00Z',
        ];
    }

    /** @return array<string, mixed> */
    private static function tpmCertification(): array
    {
        return ['publicArea' => 'cHVi', 'attest' => 'YXR0', 'signature' => 'c2ln'];
    }

    public function testRejectsInvalidPrefixKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Client(secretKey: 'rh_bogus_abc');
    }

    public function testRejectsEmptyKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Client(secretKey: '');
    }

    // ── attest: issueChallenge ─────────────────────────────────────────────

    public function testCreateChallenge(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['auth'] = $headers['Authorization'] ?? null;
            return self::challengeResponse();
        });
        $challenge = $bg->issueChallenge();
        $this->assertSame(self::NONCE, $challenge->nonce);
        $this->assertSame(self::CHALLENGE, $challenge->challenge);
        $this->assertSame('2030-01-01T00:00:00Z', $challenge->expiresAt);
        $this->assertStringEndsWith('/api/v1/attest/challenge', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
    }

    public function testChallengeResponseMustCarryNonceChallengeAndExpiry(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'challengeId' => 'ch_1', 'nonce' => self::NONCE, 'expiresAt' => '2030-01-01T00:00:00Z',
        ])]);
        $this->expectException(HttpException::class);
        $bg->issueChallenge();
    }

    public function testIssueChallengeSendsTheAskAndTheBinding(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return self::challengeResponse();
        });
        $challenge = $bg->issueChallenge(
            ask: [Client::ASK_IDENTITY],
            expectedKey: 'key_1',
            expectedDevices: ['dev-9', 'dev-10'],
        );
        $this->assertSame(self::CHALLENGE, $challenge->challenge);
        $this->assertSame(
            ['ask' => ['identity'], 'expectedKey' => 'key_1', 'expectedDevices' => ['dev-9', 'dev-10']],
            $seen['body'],
        );
    }

    public function testIssueChallengeOmitsEveryUnsetField(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return self::challengeResponse();
        });
        $bg->issueChallenge();
        $this->assertSame([], $seen['body']);
        // An empty ask means the server default, so it is not sent either.
        $bg->issueChallenge(ask: []);
        $this->assertSame([], $seen['body']);
        // Nothing the 7.0 signature carried survives: no deviceHint, no keyPurpose.
        $bg->issueChallenge(ask: [Client::ASK_IDENTITY, Client::ASK_POSTURE]);
        $this->assertSame(['ask' => ['identity', 'posture']], $seen['body']);
    }

    /**
     * The 7.0 signature was (deviceHint, ask, keyPurpose). Each of those
     * positional values now meets a parameter of another type, so a 7.0
     * call fails before any request and nothing lands in expectedKey.
     *
     * @return array<string, array{list<mixed>}>
     */
    public static function sevenPointZeroPositionalCalls(): array
    {
        return [
            'deviceHint alone' => [['device-hint']],
            'deviceHint and ask' => [[null, ['identity']]],
            'ask and keyPurpose' => [[null, ['identity', 'key'], 'sign']],
            'keyPurpose alone' => [[null, null, 'sign']],
        ];
    }

    /**
     * @dataProvider sevenPointZeroPositionalCalls
     * @param list<mixed> $args
     */
    public function testASevenPointZeroPositionalCallCannotReachExpectedKey(array $args): void
    {
        $called = false;
        $bg = $this->bg(function () use (&$called): array {
            $called = true;
            return self::challengeResponse();
        });
        try {
            $bg->issueChallenge(...$args);
            $this->fail('expected TypeError');
        } catch (\TypeError) {
        }
        $this->assertFalse($called);
    }

    public function testIssueChallengeRefusesAnEmptyBindingBeforeCallingOut(): void
    {
        $called = false;
        $bg = $this->bg(function () use (&$called): array {
            $called = true;
            return self::challengeResponse();
        });
        foreach ([
            fn () => $bg->issueChallenge(expectedKey: ''),
            fn () => $bg->issueChallenge(expectedDevices: []),
            fn () => $bg->issueChallenge(expectedDevices: ['dev-9', '']),
            fn () => $bg->issueChallenge(expectedDevices: [7]),
        ] as $call) {
            try {
                $call();
                $this->fail('expected InvalidArgumentException');
            } catch (\InvalidArgumentException) {
            }
        }
        $this->assertFalse($called);
    }

    public function testAKeyAskIsAProgrammingErrorNotADeviceFailure(): void
    {
        $bg = $this->bg(fn () => ['status' => 400, 'body' => '{"error":"invalid_ask","message":"unknown ask: key"}']);
        try {
            $bg->issueChallenge(ask: ['identity', 'key']);
            $this->fail('expected InvalidAskException');
        } catch (InvalidAskException $e) {
            $this->assertNotInstanceOf(InvalidEvidenceException::class, $e);
            $this->assertSame('invalid_ask', $e->serverError);
            $this->assertSame('invalid_ask', $e->errorCode);
            $this->assertSame('unknown ask: key', $e->getMessage());
        }
    }

    public function testAnUnknownExpectedValueStaysAGenericHttpException(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => '{"error":"expected_unknown","message":"no such device"}']);
        try {
            $bg->issueChallenge(expectedDevices: ['dev-nope']);
            $this->fail('expected HttpException');
        } catch (HttpException $e) {
            $this->assertSame(HttpException::class, $e::class);
            $this->assertSame(422, $e->status);
            $this->assertSame('expected_unknown', $e->serverError);
        }
    }

    // ── attest: verify ─────────────────────────────────────────────────────

    public function testVerifyRequiresANonceBeforeCallingOut(): void
    {
        $called = false;
        $bg = $this->bg(function () use (&$called): array {
            $called = true;
            return ['status' => 200, 'body' => '{}'];
        });
        try {
            $bg->verify([], nonce: '');
            $this->fail('expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('nonce', $e->getMessage());
        }
        $this->assertFalse($called);
    }

    public function testAVerdictTokenOutsidePassWarnFailIsRefused(): void
    {
        foreach (['allow', 'review', '', null, 7] as $token) {
            $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
                'verdict' => ['device' => ['verdict' => $token]],
            ])]);
            try {
                $bg->verify([], nonce: self::NONCE);
                $this->fail('expected HttpException for ' . json_encode($token));
            } catch (HttpException $e) {
                $this->assertStringContainsString('verdict.device.verdict', $e->getMessage());
            }
        }
    }

    public function testWarnIsTheServersToken(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'warn']],
        ])]);
        $this->assertSame(Verdict::WARN, $bg->verify([], nonce: self::NONCE)->verdict);
    }

    public function testVerifyNoLongerReadsAKey(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass', 'ueid' => 'dev-9']],
            'key' => self::certifiedEcKey(),
        ])]);
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertSame(Verdict::PASS, $result->verdict);
        $this->assertFalse(method_exists($result, 'key'));
        $this->assertSame('dev-9', $result->deviceId());
    }

    public function testDefaultTimeoutIsThirtySeconds(): void
    {
        $this->assertSame(30.0, Client::DEFAULT_TIMEOUT_SECONDS);
        $this->assertSame(30.0, $this->bg(fn () => ['status' => 200, 'body' => '{}'])->timeoutSeconds);
    }

    public function testAttestPassVerdict(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'verdict' => [
                    'acr' => 'urn:rootherald:acr:hardware',
                    'device' => [
                        'verdict' => 'pass', 'ueid' => 'dev-9', 'earStatus' => 'affirming',
                        'tpmKind' => 'firmware-tpm', 'hardwareGenuine' => true, 'bootChangedStages' => [4],
                    ],
                ],
                'assuranceClaimsMet' => ['urn:rootherald:assurance:hardware-backed'],
                'enrollmentRequired' => false,
            ])];
        });
        $evidence = [
            'pcrValues' => ['sha256' => ['7' => 'ab']],
            'quote' => ['quoted' => 'cXVvdGVk', 'signature' => 'c2ln'],
            'logs' => ['srtm' => 'bG9n'],
        ];
        $result = $bg->verify($evidence, nonce: self::NONCE);
        $this->assertSame(Verdict::PASS, $result->verdict);
        $this->assertSame(['urn:rootherald:assurance:hardware-backed'], $result->assuranceClaimsMet);
        $this->assertFalse($result->enrollmentRequired);
        $this->assertNull($result->expected());
        $this->assertSame('firmware-tpm', $result->device()['tpmKind']);
        $this->assertSame([4], $result->device()['bootChangedStages']);
        $this->assertSame(self::NONCE, $seen['body']['nonce']);
        $this->assertSame($evidence, $seen['body']['evidence']);
        $this->assertArrayNotHasKey('challengeId', $seen['body']);
        $this->assertArrayNotHasKey('policy', $seen['body']);
    }

    public function testVerifySendsRequestedDisclosureClass(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'verdict' => ['device' => ['verdict' => 'pass']],
            ])];
        });
        $bg->verify([], nonce: self::NONCE, requestedDisclosureClass: 'pseudonymous');
        $this->assertSame('pseudonymous', $seen['body']['requestedDisclosureClass']);
    }

    public function testVerifyOmitsRequestedDisclosureClassWhenUnset(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'verdict' => ['device' => ['verdict' => 'pass']],
            ])];
        });
        $bg->verify([], nonce: self::NONCE);
        $this->assertArrayNotHasKey('requestedDisclosureClass', $seen['body']);
    }

    public function testEnrollmentRequiredIsSurfaced(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'fail']],
            'assuranceClaimsMet' => [],
            'enrollmentRequired' => true,
        ])]);
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertSame(Verdict::FAIL, $result->verdict);
        $this->assertTrue($result->enrollmentRequired);
        $this->assertArrayNotHasKey('ueid', $result->device());
        $this->assertNull($result->deviceId());
    }

    // ── attest: the verdict echoes the binding ─────────────────────────────

    /** @return array{status: int, body: string} */
    private static function boundVerdict(string $verdictToken, ?string $ueid, ?array $expected): array
    {
        $device = ['verdict' => $verdictToken];
        if ($ueid !== null) {
            $device['ueid'] = $ueid;
        }
        $verdict = ['device' => $device];
        if ($expected !== null) {
            $verdict['expected'] = $expected;
        }

        return ['status' => 200, 'body' => json_encode(['verdict' => $verdict])];
    }

    public function testVerifyAcceptsAVerdictThatEchoesTheBinding(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return self::boundVerdict('pass', 'dev-9', ['key' => 'key_1', 'devices' => ['dev-10', 'dev-9']]);
        });
        $result = $bg->verify([], nonce: self::NONCE, expectedKey: 'key_1', expectedDevices: ['dev-9', 'dev-10']);
        $this->assertSame(Verdict::PASS, $result->verdict);
        $this->assertSame(['key' => 'key_1', 'devices' => ['dev-10', 'dev-9']], $result->expected());
        // The binding was fixed at the challenge; verify sends nonce and evidence only.
        $this->assertSame(['nonce', 'evidence'], array_keys($seen['body']));
    }

    public function testVerifyRefusesAVerdictThatDoesNotEchoTheKey(): void
    {
        foreach ([null, [], ['key' => 'key_other'], ['devices' => ['dev-9']]] as $expected) {
            $bg = $this->bg(fn () => self::boundVerdict('pass', 'dev-9', $expected));
            try {
                $bg->verify([], nonce: self::NONCE, expectedKey: 'key_1');
                $this->fail('expected ExpectedNotEnforcedException for ' . json_encode($expected));
            } catch (ExpectedNotEnforcedException $e) {
                $this->assertSame('expected_not_enforced', $e->errorCode);
                $this->assertStringContainsString('expectedKey', $e->getMessage());
            }
        }
    }

    public function testVerifyRefusesAVerdictThatDoesNotEchoTheDevices(): void
    {
        foreach ([null, ['key' => 'key_1'], ['devices' => []], ['devices' => ['dev-9']], ['devices' => ['dev-9', 'dev-10', 'dev-11']]] as $expected) {
            $bg = $this->bg(fn () => self::boundVerdict('pass', 'dev-9', $expected));
            try {
                $bg->verify([], nonce: self::NONCE, expectedDevices: ['dev-9', 'dev-10']);
                $this->fail('expected ExpectedNotEnforcedException for ' . json_encode($expected));
            } catch (ExpectedNotEnforcedException $e) {
                $this->assertStringContainsString('expectedDevices', $e->getMessage());
            }
        }
    }

    public function testVerifyRefusesAPassingVerdictNamingADeviceOutsideTheBinding(): void
    {
        $bg = $this->bg(fn () => self::boundVerdict('pass', 'dev-99', ['devices' => ['dev-9']]));
        $this->expectException(ExpectedNotEnforcedException::class);
        $bg->verify([], nonce: self::NONCE, expectedDevices: ['dev-9']);
    }

    public function testVerifyAcceptsAFailingVerdictAgainstTheActualDevice(): void
    {
        // A mismatch is reported against the device that answered; that is the
        // server enforcing the binding, not ignoring it.
        $bg = $this->bg(fn () => self::boundVerdict('fail', 'dev-99', ['devices' => ['dev-9']]));
        $result = $bg->verify([], nonce: self::NONCE, expectedDevices: ['dev-9']);
        $this->assertSame(Verdict::FAIL, $result->verdict);
        $this->assertSame('dev-99', $result->deviceId());
    }

    public function testVerifyWithoutABindingIgnoresTheEcho(): void
    {
        $bg = $this->bg(fn () => self::boundVerdict('pass', 'dev-9', ['key' => 'key_1']));
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertSame(['key' => 'key_1'], $result->expected());
    }

    // ── mint a key: issueKeyChallenge / certifyKey ─────────────────────────

    public function testIssueKeyChallengeSendsThePurposeAndTheDevices(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['auth'] = $headers['Authorization'] ?? null;
            $seen['body'] = json_decode((string) $body, true);
            return self::keyChallengeResponse();
        });
        $challenge = $bg->issueKeyChallenge(Client::PURPOSE_SIGN, expectedDevices: ['dev-9']);
        $this->assertInstanceOf(KeyChallenge::class, $challenge);
        $this->assertSame(self::NONCE, $challenge->nonce);
        $this->assertSame(self::KEY_CHALLENGE, $challenge->keyChallenge);
        $this->assertSame('2030-01-01T00:00:00Z', $challenge->expiresAt);
        $this->assertSame($challenge->nonce, explode('.', $challenge->keyChallenge)[1]);
        $this->assertStringEndsWith('/api/v1/keys/challenge', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
        $this->assertSame(['purpose' => 'sign', 'expectedDevices' => ['dev-9']], $seen['body']);

        $bg->issueKeyChallenge(Client::PURPOSE_DECRYPT);
        $this->assertSame(['purpose' => 'decrypt'], $seen['body']);
    }

    public function testIssueKeyChallengeRefusesAnUnknownPurposeBeforeCallingOut(): void
    {
        $called = false;
        $bg = $this->bg(function () use (&$called): array {
            $called = true;
            return self::keyChallengeResponse();
        });
        try {
            $bg->issueKeyChallenge('key');
            $this->fail('expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('purpose', $e->getMessage());
        }
        $this->assertFalse($called);
    }

    public function testKeyChallengeResponseMustCarryNonceKeyChallengeAndExpiry(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'nonce' => self::NONCE, 'challenge' => self::CHALLENGE, 'expiresAt' => '2030-01-01T00:00:00Z',
        ])]);
        $this->expectException(HttpException::class);
        $bg->issueKeyChallenge(Client::PURPOSE_SIGN);
    }

    public function testKeyDisclosureTooLowStaysAGenericHttpException(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => '{"error":"key_disclosure_too_low"}']);
        try {
            $bg->issueKeyChallenge(Client::PURPOSE_SIGN);
            $this->fail('expected HttpException');
        } catch (HttpException $e) {
            $this->assertSame(HttpException::class, $e::class);
            $this->assertSame('key_disclosure_too_low', $e->serverError);
        }
    }

    public function testCertifyKeyRelaysTheCertificationAndReturnsTheKey(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode(self::certifiedEcKey())];
        });
        $key = $bg->certifyKey(self::tpmCertification(), self::NONCE);
        $this->assertInstanceOf(CertifiedKey::class, $key);
        $this->assertSame('dev-9', $key->deviceId);
        $this->assertSame('key_1', $key->keyId);
        $this->assertSame('sign', $key->purpose);
        $this->assertSame(CertifiedKey::ALG_ES256, $key->alg);
        $this->assertSame(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'eHg', 'y' => 'eXk'], $key->jwk);
        $this->assertTrue($key->hardwareBound);
        $this->assertNull($key->format);
        $this->assertSame('2030-01-01T00:01:00Z', $key->certifiedAt);
        $this->assertStringEndsWith('/api/v1/keys/certify', $seen['url']);
        $this->assertSame(['nonce' => self::NONCE, 'certification' => self::tpmCertification()], $seen['body']);
    }

    public function testCertifyKeyReadsAnRsaKey(): void
    {
        $wire = self::certifiedEcKey();
        $wire['alg'] = 'RS256';
        $wire['jwk'] = ['kty' => 'RSA', 'n' => 'bW9k', 'e' => 'AQAB'];
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode($wire)]);
        $key = $bg->certifyKey(self::tpmCertification(), self::NONCE);
        $this->assertSame(CertifiedKey::ALG_RS256, $key->alg);
        $this->assertSame(['kty' => 'RSA', 'n' => 'bW9k', 'e' => 'AQAB'], $key->jwk);
    }

    public function testCertifyKeyReadsADecryptKeyWithItsFormat(): void
    {
        $wire = self::certifiedEcKey();
        $wire['purpose'] = 'decrypt';
        $wire['alg'] = 'ECDH-ES';
        $wire['format'] = 'jwe';
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode($wire)]);
        $key = $bg->certifyKey(self::tpmCertification(), self::NONCE);
        $this->assertSame('decrypt', $key->purpose);
        $this->assertSame(CertifiedKey::ALG_ECDH_ES, $key->alg);
        $this->assertSame('jwe', $key->format);
    }

    public function testCertifyKeyRelaysTheApplePlatformFormsVerbatim(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            $wire = self::certifiedEcKey();
            $wire['hardwareBound'] = false;
            return ['status' => 200, 'body' => json_encode($wire)];
        });
        $macos = ['platform' => 'macos', 'publicKey' => 'BJ4=', 'signature' => 'c2ln'];
        $this->assertFalse($bg->certifyKey($macos, self::NONCE)->hardwareBound);
        $this->assertSame($macos, $seen['body']['certification']);

        $ios = ['platform' => 'ios', 'keyId' => 'a2V5', 'assertion' => 'Y2Jvcg=='];
        $bg->certifyKey($ios, self::NONCE);
        $this->assertSame($ios, $seen['body']['certification']);
    }

    public function testCertifyKeyRefusesBadInputBeforeCallingOut(): void
    {
        $called = false;
        $bg = $this->bg(function () use (&$called): array {
            $called = true;
            return ['status' => 200, 'body' => json_encode(self::certifiedEcKey())];
        });
        foreach ([
            fn () => $bg->certifyKey(self::tpmCertification(), ''),
            fn () => $bg->certifyKey([], self::NONCE),
            fn () => $bg->certifyKey(['publicArea' => 'cHVi', 'attest' => 'YXR0'], self::NONCE),
        ] as $call) {
            try {
                $call();
                $this->fail('expected InvalidArgumentException');
            } catch (\InvalidArgumentException) {
            }
        }
        $this->assertFalse($called);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function malformedCertifiedKeys(): array
    {
        $good = self::certifiedEcKey();
        $rsa = ['kty' => 'RSA', 'n' => 'bW9k', 'e' => 'AQAB'];

        return [
            'no deviceId' => [array_diff_key($good, ['deviceId' => 1])],
            'no keyId' => [['keyId' => ''] + $good],
            'unknown purpose' => [['purpose' => 'key'] + $good],
            'no hardwareBound' => [array_diff_key($good, ['hardwareBound' => 1])],
            'hardwareBound as a string' => [['hardwareBound' => 'true'] + $good],
            'no certifiedAt' => [array_diff_key($good, ['certifiedAt' => 1])],
            'RSA alg on an EC key' => [['alg' => 'RS256'] + $good],
            'EC alg on an RSA key' => [['jwk' => $rsa] + $good],
            'P-384 jwk' => [['jwk' => ['kty' => 'EC', 'crv' => 'P-384', 'x' => 'eHg', 'y' => 'eXk']] + $good],
            'jwk missing y' => [['jwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'eHg']] + $good],
            'unknown format' => [['format' => 'pem'] + $good],
            'unknown alg' => [['alg' => 'HS256'] + $good],
        ];
    }

    /**
     * @dataProvider malformedCertifiedKeys
     * @param array<string, mixed> $wire
     */
    public function testCertifyKeyRefusesAMalformedKeyRatherThanReturningItHalfParsed(array $wire): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode($wire)]);
        $this->expectException(HttpException::class);
        $bg->certifyKey(self::tpmCertification(), self::NONCE);
    }

    public function testAKeyRotationConflictIsNotAChallengeError(): void
    {
        $bg = $this->bg(fn () => ['status' => 409, 'body' => '{"error":"key_rotation_conflict","message":"rotation collided"}']);
        try {
            $bg->certifyKey(self::tpmCertification(), self::NONCE);
            $this->fail('expected HttpException');
        } catch (HttpException $e) {
            $this->assertNotInstanceOf(ChallengeException::class, $e);
            $this->assertSame(409, $e->status);
            $this->assertSame('key_rotation_conflict', $e->serverError);
        }
    }

    // ── errors ─────────────────────────────────────────────────────────────

    public function testA401ActivationRefusedIsNotAnInvalidKey(): void
    {
        $bg = $this->bg(fn () => ['status' => 401, 'body' => '{"error":"activation_refused","message":"Invalid credential activation response"}']);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail('expected ActivationRefusedException');
        } catch (ActivationRefusedException $e) {
            $this->assertSame('activation_refused', $e->serverError);
            $this->assertSame('Invalid credential activation response', $e->getMessage());
        }
        $bare = $this->bg(fn () => ['status' => 401, 'body' => '']);
        $this->expectException(InvalidSecretKeyException::class);
        $bare->verify([], nonce: self::NONCE);
    }

    public function testALimiter429IsRateLimitedWithRetryAfter(): void
    {
        $bg = $this->bg(fn () => [
            'status' => 429,
            'body' => '{"error":"rate_limited","message":"Too many requests","retryAfterSeconds":60}',
            'headers' => ['Retry-After' => '17'],
        ]);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail('expected RateLimitedException');
        } catch (RateLimitedException $e) {
            $this->assertSame(17, $e->retryAfterSeconds);
            $this->assertSame('rate_limited', $e->serverError);
        }

        $fromBody = $this->bg(fn () => ['status' => 429, 'body' => '{"error":"rate_limited","retryAfterSeconds":60}']);
        try {
            $fromBody->verify([], nonce: self::NONCE);
            $this->fail('expected RateLimitedException');
        } catch (RateLimitedException $e) {
            $this->assertSame(60, $e->retryAfterSeconds);
        }

        $bare = $this->bg(fn () => ['status' => 429, 'body' => '']);
        try {
            $bare->verify([], nonce: self::NONCE);
            $this->fail('expected RateLimitedException');
        } catch (RateLimitedException $e) {
            $this->assertNull($e->retryAfterSeconds);
        }
    }

    public function testABudgetExhausted429NamesTheBudget(): void
    {
        $bg = $this->bg(fn () => [
            'status' => 429,
            'body' => '{"error":"budget_exhausted","message":"budget exhausted","budget":{"id":"bud_1","name":"Production"}}',
            'headers' => ['X-RootHerald-Quota' => 'budget-exhausted'],
        ]);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail('expected QuotaExceededException');
        } catch (QuotaExceededException $e) {
            $this->assertSame('budget_exhausted', $e->errorCode);
            $this->assertSame('budget_exhausted', $e->serverError);
            $this->assertSame(['id' => 'bud_1', 'name' => 'Production'], $e->budget);
            $this->assertSame('Production', $e->budget['name']);
        }
    }

    public function testA429WithTheQuotaHeaderIsTheQuotaWhateverTheBody(): void
    {
        $bg = $this->bg(fn () => ['status' => 429, 'body' => '{}', 'headers' => ['X-RootHerald-Quota' => 'budget-exhausted']]);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail('expected QuotaExceededException');
        } catch (QuotaExceededException $e) {
            $this->assertNull($e->budget);
        }
    }

    public function testA422OrA402WithACodeNoClassCoversStaysGeneric(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => '{"error":"posture_not_bound","message":"no posture policy"}']);
        try {
            $bg->issueChallenge(ask: [Client::ASK_POSTURE]);
            $this->fail('expected HttpException');
        } catch (HttpException $e) {
            $this->assertNotInstanceOf(UnknownPolicyException::class, $e);
            $this->assertSame(422, $e->status);
            $this->assertSame('posture_not_bound', $e->serverError);
            $this->assertSame('no posture policy', $e->getMessage());
        }
        $bg = $this->bg(fn () => ['status' => 402, 'body' => '{"error":"plan_lapsed","message":"plan lapsed"}']);
        try {
            $bg->issueChallenge(ask: [Client::ASK_POSTURE]);
            $this->fail('expected HttpException');
        } catch (HttpException $e) {
            $this->assertSame(402, $e->status);
            $this->assertSame('plan_lapsed', $e->serverError);
        }
    }

    public function testServerErrorCodeRidesOnEveryTypedException(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => '{"error":"unknown_policy"}']);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail('expected UnknownPolicyException');
        } catch (UnknownPolicyException $e) {
            $this->assertSame('unknown_policy', $e->serverError);
        }

        $bg = $this->bg(fn () => ['status' => 409, 'body' => '{"error":"challenge_expired_or_used","detail":"used"}']);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail('expected ChallengeException');
        } catch (ChallengeException $e) {
            $this->assertSame('challenge_expired_or_used', $e->serverError);
            $this->assertSame('used', $e->getMessage());
        }
    }

    public function testCohortFieldsAreExposed(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => [
                'device' => [
                    'verdict' => 'pass',
                    'ueid' => 'dev-9',
                    'cohortKey' => 'tpm20:win11:sb1:abc123',
                    'cohortScope' => 'tenant-fleet',
                    'cohortPrevalence' => 0.042,
                    'cohortPrevalencePerPcr' => ['0' => 0.9, '7' => 0.5],
                    'cohortSampleSize' => 1287,
                    'novelProfile' => false,
                ],
            ],
        ])]);
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertSame('tpm20:win11:sb1:abc123', $result->cohortKey());
        $this->assertSame('tenant-fleet', $result->cohortScope());
        $this->assertSame(0.042, $result->cohortPrevalence());
        $this->assertSame(0.5, $result->cohortPrevalencePerPcr()['7']);
        $this->assertSame(1287, $result->cohortSampleSize());
        $this->assertFalse($result->novelProfile());
    }

    public function testCohortFieldsAbsentWhenServerOmitsThem(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass', 'ueid' => 'dev-9']],
        ])]);
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertNull($result->cohortKey());
        $this->assertNull($result->cohortPrevalence());
        $this->assertNull($result->novelProfile());
        $this->assertSame([], $result->cohortPrevalencePerPcr());
    }

    public function testFailVerdictIsNotAnError(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'fail']],
        ])]);
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertSame(Verdict::FAIL, $result->verdict);
    }

    /** @return array<string, array{int, string, class-string<\Throwable>}> */
    public static function errorCases(): array
    {
        return [
            '401' => [401, 'invalid_secret_key', InvalidSecretKeyException::class],
            '401 activation_refused' => [401, 'activation_refused', ActivationRefusedException::class],
            '422' => [422, 'unknown_policy', UnknownPolicyException::class],
            '422 admission_refused' => [422, 'admission_refused', AdmissionRefusedException::class],
            '422 expected_unknown' => [422, 'expected_unknown', HttpException::class],
            '422 key_disclosure_too_low' => [422, 'key_disclosure_too_low', HttpException::class],
            '409' => [409, 'x', ChallengeException::class],
            '409 key_rotation_conflict' => [409, 'key_rotation_conflict', HttpException::class],
            '400' => [400, 'x', InvalidEvidenceException::class],
            '400 wire_version_unsupported' => [400, 'wire_version_unsupported', InvalidEvidenceException::class],
            '400 invalid_enroll_shape' => [400, 'invalid_enroll_shape', InvalidEvidenceException::class],
            '400 invalid_ask' => [400, 'invalid_ask', InvalidAskException::class],
            '429 budget_exhausted' => [429, 'budget_exhausted', QuotaExceededException::class],
            '429 rate_limited' => [429, 'rate_limited', RateLimitedException::class],
        ];
    }

    /** @dataProvider errorCases */
    public function testErrorMapping(int $status, string $code, string $exception): void
    {
        $bg = $this->bg(fn () => ['status' => $status, 'body' => json_encode(['error' => $code, 'message' => 'boom'])]);
        try {
            $bg->verify([], nonce: self::NONCE);
            $this->fail("expected {$exception}");
        } catch (HttpException $e) {
            $this->assertSame($exception, $e::class);
            $this->assertSame($code, $e->serverError);
        }
    }
}
