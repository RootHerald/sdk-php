<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\BackgroundCheck;
use Rootherald\Exceptions\ChallengeException;
use Rootherald\Exceptions\InvalidEvidenceException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\Exceptions\QuotaExceededException;
use Rootherald\Exceptions\UnknownPolicyException;
use Rootherald\Verdict;

final class BackgroundCheckTest extends TestCase
{
    private function bg(callable $transport): BackgroundCheck
    {
        return new BackgroundCheck(
            secretKey: 'rh_sk_test_xxx',
            baseUrl: 'https://api.example.test',
            httpTransport: $transport,
        );
    }

    public function testRejectsInvalidPrefixKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new BackgroundCheck(secretKey: 'rh_bogus_abc');
    }

    public function testRejectsEmptyKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new BackgroundCheck(secretKey: '');
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
        $challenge = $bg->createChallenge('device-hint');
        $this->assertSame('ch_1', $challenge->challengeId);
        $this->assertSame('n_1', $challenge->nonce);
        $this->assertStringEndsWith('/api/v1/attestations/challenge', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
    }

    public function testAttestPassVerdict(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'verdict' => ['verdict' => 'pass', 'ueid' => 'dev-9'],
            ])];
        });
        $result = $bg->attest(['quote' => '...'], challengeId: 'ch_1');
        $this->assertSame(Verdict::ALLOW, $result->verdict);
        $this->assertSame('ch_1', $seen['body']['challengeId']);
        $this->assertSame('...', $seen['body']['evidence']['quote']);
    }

    public function testCohortFieldsAreExposed(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => [
                'verdict' => 'pass',
                'ueid' => 'dev-9',
                'device' => [
                    'cohortKey' => 'tpm20:win11:sb1:abc123',
                    'cohortScope' => 'tenant-fleet',
                    'cohortPrevalence' => 0.042,
                    'cohortPrevalencePerPcr' => ['0' => 0.9, '7' => 0.5],
                    'cohortSampleSize' => 1287,
                    'novelProfile' => false,
                ],
            ],
        ])]);
        $result = $bg->attest([], challengeId: 'ch_1');
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
            'verdict' => ['verdict' => 'pass', 'ueid' => 'dev-9'],
        ])]);
        $result = $bg->attest([], challengeId: 'ch_1');
        $this->assertNull($result->cohortKey());
        $this->assertNull($result->cohortPrevalence());
        $this->assertNull($result->novelProfile());
        $this->assertSame([], $result->cohortPrevalencePerPcr());
    }

    public function testFailVerdictIsNotAnError(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode([
            'verdict' => ['verdict' => 'fail'],
        ])]);
        $result = $bg->attest([], challengeId: 'ch_1');
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
        $bg->attest([], challengeId: 'ch_1');
    }
}
