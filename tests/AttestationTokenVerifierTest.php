<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\AttestationTokenVerifier;
use Rootherald\Exceptions\TokenExpiredException;
use Rootherald\Exceptions\VerificationException;
use Rootherald\Verdict;

final class AttestationTokenVerifierTest extends TestCase
{
    private function verifier(?string $audience = Fixtures::AUDIENCE): AttestationTokenVerifier
    {
        return new AttestationTokenVerifier(
            issuer: Fixtures::ISSUER,
            jwks: Fixtures::jwksFetcher(),
            audience: $audience,
        );
    }

    public function testHappyPathAllow(): void
    {
        $claims = $this->verifier()->verify(Fixtures::makeToken());
        $this->assertSame(Verdict::ALLOW, $claims->verdict);
        $this->assertSame('device-uuid-1234', $claims->deviceId);
        $this->assertSame('urn:rootherald:user:phr', $claims->acr);
        $this->assertSame('windows', $claims->platform);
    }

    public function testWarnMapsFromWarningEarStatus(): void
    {
        $claims = $this->verifier()->verify(Fixtures::makeToken(earStatus: 'warning'));
        $this->assertSame(Verdict::WARN, $claims->verdict);
    }

    public function testDenyMapsFromContraindicated(): void
    {
        $claims = $this->verifier()->verify(Fixtures::makeToken(earStatus: 'contraindicated'));
        $this->assertSame(Verdict::DENY, $claims->verdict);
    }

    public function testExpiredTokenRaisesTokenExpired(): void
    {
        $this->expectException(TokenExpiredException::class);
        $token = Fixtures::makeToken(iat: time() - 3600, expIn: -600);
        $this->verifier()->verify($token);
    }

    public function testWrongIssuerRejected(): void
    {
        $this->expectException(VerificationException::class);
        $this->verifier()->verify(Fixtures::makeToken(issuer: 'https://evil.example.com'));
    }

    public function testWrongAudienceRejected(): void
    {
        $this->expectException(VerificationException::class);
        $this->verifier()->verify(Fixtures::makeToken(audience: 'not-our-aud'));
    }

    public function testMissingUeidRejected(): void
    {
        $this->expectException(VerificationException::class);
        $this->verifier()->verify(Fixtures::makeToken(deviceOverrides: ['ueid' => '']));
    }

    public function testWrongEatProfileRejected(): void
    {
        $this->expectException(VerificationException::class);
        $this->verifier()->verify(Fixtures::makeToken(eatProfile: 'tag:bogus:v0'));
    }

    public function testUnknownKidRejected(): void
    {
        $this->expectException(VerificationException::class);
        $this->verifier()->verify(Fixtures::makeToken(kid: 'some-other-kid'));
    }

    public function testNoneAlgorithmRejected(): void
    {
        $this->expectException(VerificationException::class);
        $header = self::b64url('{"alg":"none","kid":"test-key-1","typ":"JWT"}');
        $body = self::b64url(json_encode([
            'iss' => Fixtures::ISSUER,
            'sub' => 'u',
            'exp' => time() + 60,
        ]));
        $this->verifier()->verify("{$header}.{$body}.");
    }

    public function testTamperedSignatureRejected(): void
    {
        $this->expectException(VerificationException::class);
        $token = Fixtures::makeToken();
        [$h, $b, $s] = explode('.', $token);
        $b2 = $b[0] === 'X' ? 'Y' . substr($b, 1) : 'X' . substr($b, 1);
        $this->verifier()->verify("{$h}.{$b2}.{$s}");
    }

    public function testNullAudienceSkipsCheck(): void
    {
        $claims = $this->verifier(audience: null)->verify(Fixtures::makeToken(audience: 'whatever'));
        $this->assertSame('device-uuid-1234', $claims->deviceId);
    }

    public function testRawPayloadPreserved(): void
    {
        $claims = $this->verifier()->verify(Fixtures::makeToken());
        $this->assertSame(Fixtures::ISSUER, $claims->raw['iss']);
        $this->assertArrayHasKey('rootherald_device', $claims->raw);
    }

    private static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
