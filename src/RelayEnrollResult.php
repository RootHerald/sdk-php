<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Resolved result of the enroll relay leg ({@see BackgroundCheck::relayEnroll}),
 * normalizing the enroll endpoint's asymmetric HTTP outcome into one value so
 * callers branch on {@see $alreadyEnrolled} instead of re-parsing HTTP status.
 *
 *  - **`alreadyEnrolled === false`** — a fresh `201` enroll: {@see $challenge}
 *    (the {@see EnrollChallenge}) is present. Relay it to the client's
 *    `EnrollComplete`, then call {@see BackgroundCheck::relayActivate}.
 *  - **`alreadyEnrolled === true`** — the `409` short-circuit: the device is
 *    already bound, so SKIP the activate leg and just use {@see $deviceId}.
 *    {@see $challenge} is null.
 *
 * Either way {@see $deviceId} is resolved.
 */
final class RelayEnrollResult
{
    private function __construct(
        public readonly string $deviceId,
        public readonly bool $alreadyEnrolled,
        public readonly ?EnrollChallenge $challenge,
    ) {
    }

    /** Fresh `201` enroll: the device must complete activation with $challenge. */
    public static function fresh(EnrollChallenge $challenge): self
    {
        return new self($challenge->deviceId, false, $challenge);
    }

    /** `409` short-circuit: the device is already bound; skip the activate leg. */
    public static function alreadyEnrolled(string $deviceId): self
    {
        return new self($deviceId, true, null);
    }
}
