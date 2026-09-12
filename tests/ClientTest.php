<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\CertifiedKey;
use Rootherald\Client;
use Rootherald\Exceptions\ChallengeException;
use Rootherald\Exceptions\HttpException;
use Rootherald\Exceptions\InvalidEvidenceException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\Exceptions\QuotaExceededException;
use Rootherald\Exceptions\UnknownPolicyException;
use Rootherald\Verdict;

final class ClientTest extends TestCase
{
    private const NONCE = 'q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k';
    private const CHALLENGE = 'rhc1.' . self::NONCE . '.eyJhc2siOlsiaWRlbnRpdHkiLCJwb3N0dXJlIl19';

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

    public function testCreateChallenge(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['auth'] = $headers['Authorization'] ?? null;
            return self::challengeResponse();
        });
        $challenge = $bg->issueChallenge('device-hint');
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

    // ── the challenge carries the ask ──────────────────────────────────────

    public function testIssueChallengeSendsTheAsk(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return self::challengeResponse();
        });
        $challenge = $bg->issueChallenge(
            deviceHint: 'hint',
            ask: [Client::ASK_IDENTITY, Client::ASK_KEY],
            keyPurpose: Client::KEY_PURPOSE_SIGN,
        );
        $this->assertSame(self::CHALLENGE, $challenge->challenge);
        $this->assertSame(self::NONCE, $challenge->nonce);
        $this->assertSame(['identity', 'key'], $seen['body']['ask']);
        $this->assertSame('sign', $seen['body']['keyPurpose']);
        $this->assertSame('hint', $seen['body']['deviceHint']);
        // Policies bind to the API key; the server refuses the field with 400.
        $this->assertArrayNotHasKey('policy', $seen['body']);
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
    }

    /** @return array<string, mixed> */
    private static function passingVerdictWithKey(): array
    {
        return [
            'verdict' => ['device' => ['verdict' => 'pass', 'ueid' => 'dev-9']],
            'assuranceClaimsMet' => [],
            'enrollmentRequired' => false,
            'key' => [
                'keyId' => 'key_1',
                'jwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'eHg', 'y' => 'eXk'],
                'purpose' => 'sign',
                'authPolicy' => 'cG9saWN5',
                'certifiedAt' => '2030-01-01T00:01:00Z',
            ],
        ];
    }

    public function testVerifyExposesTheCertifiedKeyFromTheResponseRoot(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode(self::passingVerdictWithKey())]);
        $result = $bg->verify([], nonce: self::NONCE);
        $this->assertSame(Verdict::ALLOW, $result->verdict);
        $key = $result->key();
        $this->assertInstanceOf(CertifiedKey::class, $key);
        $this->assertSame('key_1', $key->keyId);
        $this->assertSame(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'eHg', 'y' => 'eXk'], $key->jwk);
        $this->assertSame('sign', $key->purpose);
        $this->assertSame('cG9saWN5', $key->authPolicy);
        $this->assertSame('2030-01-01T00:01:00Z', $key->certifiedAt);
    }

    public function testVerifyKeyIsNullWhenAbsent(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass']],
        ])]);
        $this->assertNull($bg->verify([], nonce: self::NONCE)->key());

        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass']], 'key' => null,
        ])]);
        $this->assertNull($bg->verify([], nonce: self::NONCE)->key());
    }

    public function testVerifyKeyAuthPolicyIsOptional(): void
    {
        $wire = self::passingVerdictWithKey();
        unset($wire['key']['authPolicy']);
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode($wire)]);
        $this->assertNull($bg->verify([], nonce: self::NONCE)->key()?->authPolicy);
    }

    public function testVerifyRejectsAMalformedKey(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass']], 'key' => ['keyId' => 'key_1'],
        ])]);
        $this->expectException(HttpException::class);
        $bg->verify([], nonce: self::NONCE);
    }

    public function testVerifyRequiresANonceBeforeCallingOut(): void
    {
        $called = false;
        $bg = $this->bg(function () use (&$called): array {
            $called = true;
            return ['status' => 200, 'body' => '{}'];
        });
        try {
            $bg->verify([], nonce: '');
            $this->fail('expected ChallengeException');
        } catch (ChallengeException $e) {
            $this->assertStringContainsString('nonce', $e->getMessage());
        }
        $this->assertFalse($called);
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

    public function testAttestPassVerdict(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'verdict' => [
                    'acr' => 'urn:rootherald:acr:hardware',
                    'device' => ['verdict' => 'pass', 'ueid' => 'dev-9', 'earStatus' => 'affirming'],
                ],
                'assuranceClaimsMet' => ['urn:rootherald:assurance:hardware-backed'],
                'enrollmentRequired' => false,
            ])];
        });
        $evidence = [
            'pcrValues' => ['sha256' => ['7' => 'ab']],
            'quote' => ['quoted' => 'cXVvdGVk', 'signature' => 'c2ln'],
        ];
        $result = $bg->verify($evidence, nonce: self::NONCE);
        $this->assertSame(Verdict::ALLOW, $result->verdict);
        $this->assertSame(['urn:rootherald:assurance:hardware-backed'], $result->assuranceClaimsMet);
        $this->assertFalse($result->enrollmentRequired);
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
        $this->assertSame(Verdict::DENY, $result->verdict);
        $this->assertTrue($result->enrollmentRequired);
        $this->assertArrayNotHasKey('ueid', $result->device());
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
        $this->assertSame(Verdict::DENY, $result->verdict);
    }

    /** @return array<string, array{int, class-string<\Throwable>}> */
    public static function errorCases(): array
    {
        return [
            '401' => [401, InvalidSecretKeyException::class],
            '422' => [422, UnknownPolicyException::class],
            '409' => [409, ChallengeException::class],
            '400' => [400, InvalidEvidenceException::class],
            '429' => [429, QuotaExceededException::class],
        ];
    }

    /** @dataProvider errorCases */
    public function testErrorMapping(int $status, string $exception): void
    {
        $bg = $this->bg(fn () => ['status' => $status, 'body' => '{"error":"x","message":"boom"}']);
        $this->expectException($exception);
        $bg->verify([], nonce: self::NONCE);
    }
}
