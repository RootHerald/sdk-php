<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\Client;
use Rootherald\Exceptions\ChallengeException;
use Rootherald\Exceptions\InvalidEvidenceException;
use Rootherald\Exceptions\InvalidSecretKeyException;
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
        $this->assertStringEndsWith('/api/v1/attest/challenge', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
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
