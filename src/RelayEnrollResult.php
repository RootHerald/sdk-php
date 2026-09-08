<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Result of the enroll relay leg ({@see Client::relayEnroll}).
 *
 * Enrollment always issues a challenge, including for a device already known —
 * re-enrollment is how a device rotates its attestation key, so short-circuiting
 * it would make rotation impossible. Relay {@see $challenge} to the client's
 * `EnrollComplete`, then call {@see Client::relayActivate}.
 *
 * {@see $deviceId} is THIS tenant's alias for the device, not a global
 * identifier: another tenant enrolling the same silicon is told a different one.
 */
final class RelayEnrollResult
{
    private function __construct(
        public readonly string $deviceId,
        public readonly EnrollChallenge $challenge,
        /** The attestation challenge id this enrollment was admitted against, when the server echoed one. */
        public readonly ?string $challengeId = null,
    ) {
    }

    /** The device must complete activation with $challenge. */
    public static function fresh(EnrollChallenge $challenge, ?string $challengeId = null): self
    {
        return new self($challenge->deviceId, $challenge, $challengeId);
    }
}
