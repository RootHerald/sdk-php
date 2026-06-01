<?php

declare(strict_types=1);

namespace Rootherald;

use Firebase\JWT\JWT;
use Rootherald\Exceptions\JwksException;
use Rootherald\Exceptions\WebhookSignatureException;

/**
 * Verifies CAEP Security Event Token (SET) JWTs sent by the Root Herald
 * webhook subsystem.
 */
final class WebhookVerifier
{
    public const ALLOWED_ALGORITHMS = ['RS256', 'ES256'];

    public function __construct(
        public readonly string $issuer,
        public readonly JwksFetcher $jwks,
        public readonly ?string $audience = null,
        public readonly int $leewaySeconds = 30,
    ) {
    }

    public function verifySet(string $signedJwt): WebhookEvent
    {
        $body = trim($signedJwt);
        if (substr_count($body, '.') !== 2) {
            throw new WebhookSignatureException('Body is not a compact JWT');
        }

        $parts = explode('.', $body);
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]));
        if (!is_object($header)) {
            throw new WebhookSignatureException('Malformed SET header');
        }
        if (($header->typ ?? null) !== 'secevent+jwt') {
            throw new WebhookSignatureException(
                "SET typ must be 'secevent+jwt'; got " . ($header->typ ?? 'null'),
            );
        }
        $kid = (string) ($header->kid ?? '');
        if ($kid === '') {
            throw new WebhookSignatureException('SET header missing "kid"');
        }
        $alg = (string) ($header->alg ?? '');
        if (!in_array($alg, self::ALLOWED_ALGORITHMS, true)) {
            throw new WebhookSignatureException("Unsupported SET alg={$alg}");
        }

        try {
            $key = $this->jwks->getKey($kid);
        } catch (JwksException $e) {
            throw new WebhookSignatureException('JWKS lookup failed: ' . $e->getMessage(), 0, $e);
        }

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->leewaySeconds;
        try {
            try {
                $decoded = JWT::decode($body, $key);
            } catch (\Throwable $e) {
                throw new WebhookSignatureException('SET signature verification failed: ' . $e->getMessage(), 0, $e);
            }
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        $payload = json_decode(json_encode($decoded), associative: true);
        if (!is_array($payload)) {
            throw new WebhookSignatureException('Decoded SET payload is not an object');
        }

        $iss = (string) ($payload['iss'] ?? '');
        if ($iss !== $this->issuer) {
            throw new WebhookSignatureException("SET issuer mismatch: got {$iss}");
        }
        if ($this->audience !== null) {
            $aud = $payload['aud'] ?? null;
            if ($aud !== $this->audience) {
                throw new WebhookSignatureException('SET audience mismatch');
            }
        }

        $events = $payload['events'] ?? null;
        if (!is_array($events) || count($events) === 0) {
            throw new WebhookSignatureException("SET 'events' map missing or empty");
        }

        $eventType = array_key_first($events);
        $eventPayload = is_array($events[$eventType]) ? $events[$eventType] : [];

        $subId = is_array($payload['sub_id'] ?? null) ? $payload['sub_id'] : [];

        return new WebhookEvent(
            issuer: $iss,
            audience: isset($payload['aud']) ? (string) $payload['aud'] : null,
            issuedAt: (int) ($payload['iat'] ?? 0),
            jwtId: (string) ($payload['jti'] ?? ''),
            subjectIdFormat: (string) ($subId['format'] ?? 'opaque'),
            deviceId: (string) ($subId['id'] ?? ''),
            eventType: (string) $eventType,
            eventPayload: $eventPayload,
            raw: $payload,
        );
    }
}
