<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Terminal result of the activate relay leg
 * ({@see BackgroundCheck::relayActivate}, `POST /api/v1/devices/activate`).
 *
 * Mirrors the contract's `RelayActivateResponse`. {@see $deviceId} is the
 * load-bearing field the backend maps to its user/account; {@see $status} and
 * {@see $enrolledAt} are advisory lifecycle metadata when the server supplies
 * them.
 */
final class RelayActivateResult
{
    public function __construct(
        /** The enrolled device id (UUID). */
        public readonly string $deviceId,
        /** Lifecycle status, e.g. "enrolled"; null if the server omits it. */
        public readonly ?string $status = null,
        /** ISO 8601 timestamp the device was enrolled; null if omitted. */
        public readonly ?string $enrolledAt = null,
    ) {
    }
}
