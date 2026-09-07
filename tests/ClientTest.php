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
use Rootherald\Exceptions\PolicyDowngradeException;
use Rootherald\Exceptions\QuotaExceededException;
use Rootherald\Exceptions\UnknownPolicyException;
use Rootherald\Verdict;

final class ClientTest extends TestCase
{
    private function bg(callable $transport): Client
    {
        return new Client(
            secretKey: 'rh_sk_test_xxx',
            baseUrl: 'https://api.example.test',
            httpTransport: $transport,
        );
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
            return ['status' => 200, 'body' => json_encode([
                'challengeId' => 'ch_1', 'nonce' => 'n_1', 'expiresAt' => '2030-01-01T00:00:00Z',
            ])];
        });
        $challenge = $bg->issueChallenge('device-hint');
        $this->assertSame('ch_1', $challenge->challengeId);
        $this->assertSame('n_1', $challenge->nonce);
        $this->assertNull($challenge->challenge);
        $this->assertStringEndsWith('/api/v1/attest/challenge', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
    }

    // ── the challenge carries the ask ──────────────────────────────────────

    public function testIssueChallengeSendsTheAsk(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'challengeId' => 'ch_1',
                'challenge' => 'rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19',
                'nonce' => 'n_1',
                'expiresAt' => '2030-01-01T00:00:00Z',
            ])];
        });
        $challenge = $bg->issueChallenge(
            deviceHint: 'hint',
            ask: [Client::ASK_IDENTITY, Client::ASK_KEY],
            policy: 'rootherald:builtin:strict-hardware',
            keyPurpose: Client::KEY_PURPOSE_SIGN,
        );
        $this->assertSame('rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19', $challenge->challenge);
        $this->assertSame('n_1', $challenge->nonce);
        $this->assertSame(['identity', 'key'], $seen['body']['ask']);
        $this->assertSame('rootherald:builtin:strict-hardware', $seen['body']['policy']);
        $this->assertSame('sign', $seen['body']['keyPurpose']);
        $this->assertSame('hint', $seen['body']['deviceHint']);
    }

    public function testIssueChallengeOmitsEveryUnsetField(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'challengeId' => 'ch_1', 'nonce' => 'n_1', 'expiresAt' => '2030-01-01T00:00:00Z',
            ])];
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
        $result = $bg->verify([], challengeId: 'ch_1');
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
        $this->assertNull($bg->verify([], challengeId: 'ch_1')->key());

        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass']], 'key' => null,
        ])]);
        $this->assertNull($bg->verify([], challengeId: 'ch_1')->key());
    }

    public function testVerifyKeyAuthPolicyIsOptional(): void
    {
        $wire = self::passingVerdictWithKey();
        unset($wire['key']['authPolicy']);
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode($wire)]);
        $this->assertNull($bg->verify([], challengeId: 'ch_1')->key()?->authPolicy);
    }

    public function testVerifyRejectsAMalformedKey(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'pass']], 'key' => ['keyId' => 'key_1'],
        ])]);
        $this->expectException(HttpException::class);
        $bg->verify([], challengeId: 'ch_1');
    }

    public function testMaps422PolicyDowngrade(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => json_encode([
            'error' => 'policy_downgrade', 'message' => 'verify policy is looser than the challenge',
        ])]);
        try {
            $bg->verify([], challengeId: 'ch_1', policy: 'loose');
            $this->fail('expected PolicyDowngradeException');
        } catch (PolicyDowngradeException $e) {
            $this->assertSame('policy_downgrade', $e->errorCode);
            $this->assertSame('policy_downgrade', $e->serverError);
            $this->assertSame(422, $e->status);
            $this->assertSame('verify policy is looser than the challenge', $e->getMessage());
        }
    }

    public function testServerErrorCodeRidesOnEveryTypedException(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => '{"error":"unknown_policy"}']);
        try {
            $bg->verify([], challengeId: 'ch_1');
            $this->fail('expected UnknownPolicyException');
        } catch (UnknownPolicyException $e) {
            $this->assertSame('unknown_policy', $e->serverError);
        }

        $bg = $this->bg(fn () => ['status' => 409, 'body' => '{"error":"challenge_expired_or_used","detail":"used"}']);
        try {
            $bg->verify([], challengeId: 'ch_1');
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
        $result = $bg->verify(['quote' => '...'], challengeId: 'ch_1');
        $this->assertSame(Verdict::ALLOW, $result->verdict);
        $this->assertSame(['urn:rootherald:assurance:hardware-backed'], $result->assuranceClaimsMet);
        $this->assertFalse($result->enrollmentRequired);
        $this->assertSame('ch_1', $seen['body']['challengeId']);
        $this->assertSame('...', $seen['body']['evidence']['quote']);
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
        $bg->verify([], challengeId: 'ch_1', requestedDisclosureClass: 'pseudonymous');
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
        $bg->verify([], challengeId: 'ch_1');
        $this->assertArrayNotHasKey('requestedDisclosureClass', $seen['body']);
    }

    public function testEnrollmentRequiredIsSurfaced(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['device' => ['verdict' => 'fail']],
            'assuranceClaimsMet' => [],
            'enrollmentRequired' => true,
        ])]);
        $result = $bg->verify([], challengeId: 'ch_1');
        $this->assertSame(Verdict::DENY, $result->verdict);
        $this->assertTrue($result->enrollmentRequired);
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
        $result = $bg->verify([], challengeId: 'ch_1');
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
        $result = $bg->verify([], challengeId: 'ch_1');
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
        $result = $bg->verify([], challengeId: 'ch_1');
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
        $bg->verify([], challengeId: 'ch_1');
    }
}
