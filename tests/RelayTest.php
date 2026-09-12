<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\Client;
use Rootherald\EnrollChallenge;
use Rootherald\Exceptions\AdmissionRefusedException;
use Rootherald\Exceptions\HttpException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\RelayActivateResult;
use Rootherald\RelayEnrollResult;
use Rootherald\Verdict;

/**
 * Tests for the backend-relay helpers: relayEnroll per platform,
 * relayActivate, and the issueChallenge/verify primaries.
 */
final class RelayTest extends TestCase
{
    private const NONCE = 'q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k';
    private const CHALLENGE = 'rhc1.' . self::NONCE . '.eyJhc2siOlsiaWRlbnRpdHkiXX0';
    private const ENROLLMENT_ID = '0b6d3c1a-7f2e-4c9b-9d3a-5e1f2a3b4c5d';

    private function bg(callable $transport): Client
    {
        return new Client(
            secretKey: 'rh_sk_test_xxx',
            baseUrl: 'https://api.example.test',
            httpTransport: $transport,
        );
    }

    // ── relayEnroll ────────────────────────────────────────────────────────

    public function testRelayEnrollTpm201ReturnsMakeCredentialChallenge(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            $seen['auth'] = $headers['Authorization'] ?? null;
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 201, 'body' => json_encode([
                'enrollmentId' => self::ENROLLMENT_ID,
                'credentialBlob' => 'cred==',
                'encryptedSecret' => 'enc==',
            ])];
        });

        $blob = [
            'ekPublicKey' => 'ekpub==',
            'akPublicArea' => 'akpub==',
            'platform' => 'windows',
            'ekCertPem' => '-----BEGIN CERTIFICATE-----',
            'tpmSelfReport' => ['manufacturer' => 'INTC', 'vendorString' => 'Intel'],
        ];
        $result = $bg->relayEnroll($blob);

        $this->assertInstanceOf(RelayEnrollResult::class, $result);
        $this->assertInstanceOf(EnrollChallenge::class, $result->challenge);
        $this->assertSame(self::ENROLLMENT_ID, $result->challenge->enrollmentId);
        $this->assertSame('cred==', $result->challenge->credentialBlob);
        $this->assertSame('enc==', $result->challenge->encryptedSecret);
        $this->assertNull($result->challenge->challengeNonce);
        // wire shape: endpoint with no query string, auth, pass-through body
        $this->assertStringEndsWith('/api/v1/attest/enroll', $seen['url']);
        $this->assertStringNotContainsString('?', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
        $this->assertSame($blob, $seen['body']);
        // the challenge round-trips to exactly the 201 body the client consumes
        $this->assertSame(
            ['enrollmentId' => self::ENROLLMENT_ID, 'credentialBlob' => 'cred==', 'encryptedSecret' => 'enc=='],
            $result->challenge->toArray(),
        );
    }

    public function testRelayEnrollMacos201ReturnsChallengeNonce(): void
    {
        $bg = $this->bg(fn () => ['status' => 201, 'body' => json_encode([
            'enrollmentId' => self::ENROLLMENT_ID,
            'challengeNonce' => 'bm9uY2U=',
        ])]);

        $result = $bg->relayEnroll(['ekPublicKey' => 'BJ4=', 'akPublicArea' => 'BJ4=', 'platform' => 'macos']);

        $this->assertSame(self::ENROLLMENT_ID, $result->challenge?->enrollmentId);
        $this->assertSame('bm9uY2U=', $result->challenge?->challengeNonce);
        $this->assertNull($result->challenge?->credentialBlob);
        $this->assertSame(
            ['enrollmentId' => self::ENROLLMENT_ID, 'challengeNonce' => 'bm9uY2U='],
            $result->challenge?->toArray(),
        );
    }

    public function testRelayEnrollIosAcceptsAnEmpty201(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 201, 'body' => '{}'];
        });

        $blob = [
            'platform' => 'ios',
            'iosKeyId' => 'a2V5',
            'iosAttestationObject' => 'Y2Jvcg==',
            'nonce' => self::NONCE,
        ];
        $result = $bg->relayEnroll($blob);

        $this->assertNull($result->challenge);
        $this->assertSame($blob, $seen['body']);
    }

    public function testRelayEnrollIosBlobMustCarryItsOwnFields(): void
    {
        $bg = $this->bg(fn () => ['status' => 201, 'body' => '{}']);
        $this->expectException(\InvalidArgumentException::class);
        $bg->relayEnroll(['platform' => 'ios', 'iosKeyId' => 'a2V5', 'iosAttestationObject' => 'Y2Jvcg==']); // missing nonce
    }

    public function testRelayEnrollMaps422AdmissionRefused(): void
    {
        $bg = $this->bg(fn () => ['status' => 422, 'body' => json_encode([
            'error' => 'admission_refused', 'detail' => 'firmware TPM under a discrete-only policy',
        ])]);
        try {
            $bg->relayEnroll(['ekPublicKey' => 'ek==', 'akPublicArea' => 'ak==']);
            $this->fail('expected AdmissionRefusedException');
        } catch (AdmissionRefusedException $e) {
            $this->assertSame('admission_refused', $e->errorCode);
            $this->assertSame('admission_refused', $e->serverError);
            $this->assertSame('firmware TPM under a discrete-only policy', $e->getMessage());
        }
    }

    public function testRelayEnrollMissingFieldsThrowsInvalidArgument(): void
    {
        $bg = $this->bg(fn () => ['status' => 201, 'body' => '{}']);
        $this->expectException(\InvalidArgumentException::class);
        $bg->relayEnroll(['ekPublicKey' => 'ek==']); // missing akPublicArea
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function malformedEnroll201s(): array
    {
        return [
            'empty for a TPM blob' => [[]],
            'no proof material' => [['enrollmentId' => self::ENROLLMENT_ID]],
            'half a MakeCredential' => [['enrollmentId' => self::ENROLLMENT_ID, 'credentialBlob' => 'cred==']],
            'empty enrollmentId' => [['enrollmentId' => '', 'challengeNonce' => 'bm9uY2U=']],
            'deviceId instead of enrollmentId' => [[
                'deviceId' => 'dev-1', 'credentialBlob' => 'cred==', 'encryptedSecret' => 'enc==',
            ]],
        ];
    }

    /**
     * @dataProvider malformedEnroll201s
     * @param array<string, mixed> $body
     */
    public function testRelayEnrollMalformed201ResponseThrows(array $body): void
    {
        $bg = $this->bg(fn () => ['status' => 201, 'body' => json_encode($body)]);
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

    public function testRelayActivateTpmSuccess(): void
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
            'enrollmentId' => self::ENROLLMENT_ID,
            'decryptedSecret' => 'secret==',
        ]);

        $this->assertInstanceOf(RelayActivateResult::class, $result);
        $this->assertSame('dev-1', $result->deviceId);
        $this->assertSame('enrolled', $result->status);
        $this->assertSame('2026-06-30T00:00:00Z', $result->enrolledAt);
        $this->assertStringEndsWith('/api/v1/attest/activate', $seen['url']);
        $this->assertStringNotContainsString('?', $seen['url']);
        $this->assertSame(
            ['enrollmentId' => self::ENROLLMENT_ID, 'decryptedSecret' => 'secret=='],
            $seen['body'],
        );
    }

    public function testRelayActivateMacosSendsTheSignature(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['body'] = json_decode((string) $body, true);
            return ['status' => 200, 'body' => json_encode(['deviceId' => 'dev-1'])];
        });

        $result = $bg->relayActivate(['enrollmentId' => self::ENROLLMENT_ID, 'signature' => 'c2ln']);

        $this->assertSame('dev-1', $result->deviceId);
        $this->assertSame(['enrollmentId' => self::ENROLLMENT_ID, 'signature' => 'c2ln'], $seen['body']);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function malformedActivationBlobs(): array
    {
        return [
            'no proof' => [['enrollmentId' => self::ENROLLMENT_ID]],
            'empty enrollmentId' => [['enrollmentId' => '', 'decryptedSecret' => 's==']],
            'deviceId instead of enrollmentId' => [['deviceId' => 'dev-1', 'decryptedSecret' => 's==']],
        ];
    }

    /**
     * @dataProvider malformedActivationBlobs
     * @param array<string, mixed> $blob
     */
    public function testRelayActivateMissingFieldsThrowsInvalidArgument(array $blob): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => '{}']);
        $this->expectException(\InvalidArgumentException::class);
        $bg->relayActivate($blob);
    }

    public function testRelayActivateMissingDeviceIdInResponseThrows(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode(['status' => 'enrolled'])]);
        $this->expectException(HttpException::class);
        $bg->relayActivate(['enrollmentId' => self::ENROLLMENT_ID, 'decryptedSecret' => 's==']);
    }

    public function testRelayActivateOptionalFieldsDefaultToNull(): void
    {
        $bg = $this->bg(fn () => ['status' => 200, 'body' => json_encode(['deviceId' => 'dev-1'])]);
        $result = $bg->relayActivate(['enrollmentId' => self::ENROLLMENT_ID, 'decryptedSecret' => 's==']);
        $this->assertSame('dev-1', $result->deviceId);
        $this->assertNull($result->status);
        $this->assertNull($result->enrolledAt);
    }

    public function testRelayActivateWrongProofIsOne401(): void
    {
        $bg = $this->bg(fn () => ['status' => 401, 'body' => '{"error":"Invalid credential activation response"}']);
        $this->expectException(InvalidSecretKeyException::class);
        $bg->relayActivate(['enrollmentId' => self::ENROLLMENT_ID, 'decryptedSecret' => 'wrong==']);
    }

    // ── the primaries ──────────────────────────────────────────────────────

    public function testIssueChallengeHitsChallengeEndpoint(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            return ['status' => 200, 'body' => json_encode([
                'nonce' => self::NONCE, 'challenge' => self::CHALLENGE, 'expiresAt' => '2030-01-01T00:00:00Z',
            ])];
        });
        $challenge = $bg->issueChallenge('hint');
        $this->assertSame(self::NONCE, $challenge->nonce);
        $this->assertStringEndsWith('/api/v1/attest/challenge', $seen['url']);
    }

    public function testVerifyHitsVerifyEndpoint(): void
    {
        $seen = [];
        $bg = $this->bg(function (string $m, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['url'] = $url;
            return ['status' => 200, 'body' => json_encode(['verdict' => ['device' => ['verdict' => 'pass']]])];
        });
        $result = $bg->verify(['quote' => ['quoted' => 'cQ==', 'signature' => 'cw==']], nonce: self::NONCE);
        $this->assertSame(Verdict::ALLOW, $result->verdict);
        $this->assertStringEndsWith('/api/v1/attest/verify', $seen['url']);
    }

    public function testPrimariesRoundTripAgainstOneTransport(): void
    {
        $bg = $this->bg(fn (string $m, string $url) => str_ends_with($url, '/challenge')
            ? ['status' => 200, 'body' => json_encode(['nonce' => self::NONCE, 'challenge' => self::CHALLENGE, 'expiresAt' => 'z'])]
            : ['status' => 200, 'body' => json_encode(['verdict' => ['device' => ['verdict' => 'pass']]])]);

        $challenge = $bg->issueChallenge();
        // The handle is the second segment of the string the device receives.
        $this->assertSame($challenge->nonce, explode('.', $challenge->challenge)[1]);
        $this->assertSame(Verdict::ALLOW, $bg->verify([], nonce: $challenge->nonce)->verdict);
    }
}
