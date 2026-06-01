<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\Exceptions\WebhookSignatureException;
use Rootherald\WebhookVerifier;

final class WebhookVerifierTest extends TestCase
{
    private function verifier(?string $audience = null): WebhookVerifier
    {
        return new WebhookVerifier(
            issuer: Fixtures::ISSUER,
            jwks: Fixtures::jwksFetcher(),
            audience: $audience,
        );
    }

    public function testHappyPathDecodesEvent(): void
    {
        $event = $this->verifier()->verifySet(Fixtures::makeSet());
        $this->assertSame(Fixtures::ISSUER, $event->issuer);
        $this->assertSame('device-uuid-1234', $event->deviceId);
        $this->assertStringStartsWith(
            'https://schemas.openid.net/secevent/caep/',
            $event->eventType,
        );
        $this->assertArrayHasKey('current_status', $event->eventPayload);
    }

    public function testWrongTypRejected(): void
    {
        $this->expectException(WebhookSignatureException::class);
        $this->verifier()->verifySet(Fixtures::makeSet(typ: 'JWT'));
    }

    public function testNonCompactJwtRejected(): void
    {
        $this->expectException(WebhookSignatureException::class);
        $this->verifier()->verifySet('not.a.jwt.body');
    }

    public function testEmptyBodyRejected(): void
    {
        $this->expectException(WebhookSignatureException::class);
        $this->verifier()->verifySet('');
    }

    public function testWrongIssuerRejected(): void
    {
        $this->expectException(WebhookSignatureException::class);
        $this->verifier()->verifySet(Fixtures::makeSet(issuer: 'https://attacker.example/myorg'));
    }

    public function testAudienceValidatedWhenProvided(): void
    {
        $event = $this->verifier(audience: 'my-stream')->verifySet(
            Fixtures::makeSet(audience: 'my-stream'),
        );
        $this->assertSame('my-stream', $event->audience);
    }

    public function testWrongAudienceRejected(): void
    {
        $this->expectException(WebhookSignatureException::class);
        $this->verifier(audience: 'my-stream')->verifySet(Fixtures::makeSet(audience: 'other'));
    }

    public function testTamperedSignatureRejected(): void
    {
        $this->expectException(WebhookSignatureException::class);
        $body = Fixtures::makeSet();
        [$h, $p, $s] = explode('.', $body);
        $s2 = $s[0] === 'A' ? 'B' . substr($s, 1) : 'A' . substr($s, 1);
        $this->verifier()->verifySet("{$h}.{$p}.{$s2}");
    }
}
