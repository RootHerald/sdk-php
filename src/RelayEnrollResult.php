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
 * The result carries no device identifier. The backend learns its alias for
 * the device from activation, or from the first verdict on iOS.
 */
final class RelayEnrollResult
{
    public function __construct(
        /**
         * The activation challenge to relay to the client; null for an iOS
         * enrollment, which has no activation leg.
         */
        public readonly ?EnrollChallenge $challenge,
    ) {
    }
}
