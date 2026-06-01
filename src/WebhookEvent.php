<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Decoded CAEP Security Event Token envelope.
 *
 * The SET carries exactly one event; that event's type URI and body are
 * exposed via {@see $eventType} / {@see $eventPayload}.
 */
final class WebhookEvent
{
    /**
     * @param array<string, mixed> $eventPayload
     * @param array<string, mixed> $raw  Full verified payload.
     */
    public function __construct(
        public readonly string $issuer,
        public readonly ?string $audience,
        public readonly int $issuedAt,
        public readonly string $jwtId,
        public readonly string $subjectIdFormat,
        public readonly string $deviceId,
        public readonly string $eventType,
        public readonly array $eventPayload,
        public readonly array $raw,
    ) {
    }
}
