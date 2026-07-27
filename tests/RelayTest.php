<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\BackgroundCheck;
use Rootherald\EnrollChallenge;
use Rootherald\Exceptions\HttpException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\RelayActivateResult;
use Rootherald\RelayEnrollResult;
use Rootherald\Verdict;

/**
 * Tests for the Client ABI 2.0 backend-relay helpers: relayEnroll (incl. the
 * 201 vs 409 split), relayActivate, and the issueChallenge/verify renames with
 * their deprecated createChallenge/attest aliases.
 */
final class RelayTest extends TestCase
{
    private function bg(callable $transport): BackgroundCheck
    {
        return new BackgroundCheck(
            secretKey: 'rh_sk_test_xxx',
            baseUrl: 'https://api.example.test',
            httpTransport: $transport,
        );
    }

    // ── relayEnroll ────────────────────────────────────────────────────────

    public function testRelayEnrollFresh201ReturnsChallenge(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['auth'] = $headers['Authorization'] ?? null;
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 201, 'body' => json_encode([
                'deviceId' => 'dev-1',
                'credentialBlob' => 'cred==',
                'encryptedSecret' => 'enc==',
            ])];
        });

        $result = $bg->relayEnroll([
            'ekPublicKey' => 'ekpub==',
            'akPublicArea' => 'akpub==',
            'platform' => 'windows',
            'ekCertPem' => '-----BEGIN CERTIFICATE-----',
        ]);

        $this->assertInstanceOf(RelayEnrollResult::class, $result);
        $this->assertFalse($result->alreadyEnrolled);
        $this->assertSame('dev-1', $result->deviceId);
        $this->assertInstanceOf(EnrollChallenge::class, $result->challenge);
        $this->assertSame('cred==', $result->challenge->credentialBlob);
        $this->assertSame('enc==', $result->challenge->encryptedSecret);
        // wire shape: endpoint, auth, pass-through body
        $this->assertStringEndsWith('/api/v1/devices/enroll', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
        $this->assertSame('ekpub==', $seen['body']['ekPublicKey']);
        $this->assertSame('windows', $seen['body']['platform']);
        // challenge round-trips back to the wire shape the client consumes
        $this->assertSame(
            ['deviceId' => 'dev-1', 'credentialBlob' => 'cred==', 'encryptedSecret' => 'enc=='],
            $result->challenge->toArray(),
        );
    }

    public function testRelayEnrollAlreadyEnrolled409SkipsActivate(): void
    {
        $bg = $this->bg(fn () => ['status' => 409, 'body' => json_encode(['deviceId' => 'dev-existing'])]);

        $result = $bg->relayEnroll(['ekPublicKey' => 'ek==', 'akPublicArea' => 'ak==']);

        $this->assertTrue($result->alreadyEnrolled);
        $this->assertSame('dev-existing', $result->deviceId);
        $this->assertNull($result->challenge);
    }

    public function testRelayEnroll409MissingDeviceIdThrows(): void
    {
        $bg = $this->bg(fn () => ['status' => 409, 'body' => json_encode(['note' => 'no id'])]);
        $this->expectException(HttpException::class);
        $bg->relayEnroll(['ekPublicKey' => 'ek==', 'akPublicArea' => 'ak==']);
    }

    public function testRelayEnrollMissingFieldsThrowsInvalidArgument(): void
    {
        $bg = $this->bg(fn () => ['status' => 201, 'body' => '{}']);
        $this->expectException(\InvalidArgumentException::class);
        $bg->relayEnroll(['ekPublicKey' => 'ek==']); // missing akPublicArea
    }

    public function testRelayEnrollMalformed201ResponseThrows(): void
    {
        $bg = $this->bg(fn () => ['status' => 201, 'body' => json_encode(['deviceId' => 'dev-1'])]); // no credentialBlob/encryptedSecret
        $this->expectException(HttpException::class);
        $bg->relayEnroll(['ekPublicKey' => 'ek==', 'akPublicArea' => 'ak==']);
    }

    public function testRelayEnrollAuthErrorIsMapped(): void
    {
        $bg = $this->bg(fn () => ['status' => 401, 'body' => '{"error":"x","message":"bad key"}']);
        $this->expectException(InvalidSecretKeyException::class);
        $bg->relayEnroll(['ekPublicKey' => 'ek==', 'akPublicArea' => 'ak==']);
    }

    // ── relayActivate ──────────────────────────────────────────────────────

    public function testRelayActivateSuccess(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode([
                'deviceId' => 'dev-1',
                'status' => 'enrolled',
                'enrolledAt' => '2026-06-30T00:00:00Z',
            ])];
        });

        $result = $bg->relayActivate([
            'deviceId' => 'dev-1',
            'decryptedSecret' => 'secret==',
        ]);

        $this->assertInstanceOf(RelayActivateResult::class, $result);
        $this->assertSame('dev-1', $result->deviceId);
        $this->assertSame('enrolled', $result->status);
        $this->assertSame('2026-06-30T00:00:00Z', $result->enrolledAt);
        $this->assertStringEndsWith('/api/v1/devices/activate', $seen['url']);
        $this->assertSame('secret==', $seen['body']['decryptedSecret']);
    }

    public function testRelayActivateMissingFieldsThrowsInvalidArgument(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => '{}']);
        $this->expectException(\InvalidArgumentException::class);
        $bg->relayActivate(['deviceId' => 'dev-1']); // missing decryptedSecret
    }

    public function testRelayActivateMissingDeviceIdInResponseThrows(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode(['status' => 'enrolled'])]);
        $this->expectException(HttpException::class);
        $bg->relayActivate(['deviceId' => 'dev-1', 'decryptedSecret' => 's==']);
    }

    public function testRelayActivateOptionalFieldsDefaultToNull(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode(['deviceId' => 'dev-1'])]);
        $result = $bg->relayActivate(['deviceId' => 'dev-1', 'decryptedSecret' => 's==']);
        $this->assertSame('dev-1', $result->deviceId);
        $this->assertNull($result->status);
        $this->assertNull($result->enrolledAt);
    }

    // ── rename + deprecated aliases ────────────────────────────────────────

    public function testIssueChallengeHitsChallengeEndpoint(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            return ['status' => 200, 'body' => json_encode([
                'challengeId' => 'ch_1', 'nonce' => 'n_1', 'expiresAt' => '2030-01-01T00:00:00Z',
            ])];
        });
        $challenge = $bg->issueChallenge('hint');
        $this->assertSame('ch_1', $challenge->challengeId);
        $this->assertStringEndsWith('/api/v1/attestations/challenge', $seen['url']);
    }

    public function testVerifyHitsVerifyEndpoint(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            return ['status' => 200, 'body' => json_encode(['verdict' => ['device' => ['verdict' => 'pass']]])];
        });
        $result = $bg->verify(['quote' => '...'], challengeId: 'ch_1');
        $this->assertSame(Verdict::ALLOW, $result->verdict);
        $this->assertStringEndsWith('/api/v1/attestations/verify', $seen['url']);
    }

    public function testDeprecatedAliasesStillWork(): void
    {
        $bg = $this->bg(fn (string $m, string $url) => str_ends_with($url, '/challenge')
            ? ['status' => 200, 'body' => json_encode(['challengeId' => 'ch', 'nonce' => 'n', 'expiresAt' => 'z'])]
            : ['status' => 200, 'body' => json_encode(['verdict' => ['device' => ['verdict' => 'pass']]])]);

        $this->assertSame('ch', $bg->createChallenge()->challengeId);
        $this->assertSame(Verdict::ALLOW, $bg->attest([], challengeId: 'ch')->verdict);
    }
}
