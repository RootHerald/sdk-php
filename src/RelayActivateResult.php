<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Terminal result of the activate relay leg
 * ({@see Client::relayActivate}, `POST /api/v1/attest/activate`).
 *
 * Mirrors the contract's `RelayActivateResponse`. {@see $deviceId} is the
 * load-bearing field the backend maps to its user/account; {@see $status} and
 * {@see $enrolledAt} are advisory lifecycle metadata when the server supplies
 * them.
 */
final class RelayActivateResult
{
    public function __construct(
        /**
         * This tenant's alias for the enrolled device (UUID), not a global
         * identifier. For the backend only; never relay it to the device.
         */
        public readonly string $deviceId,
        /** Lifecycle status, e.g. "enrolled"; null if the server omits it. */
        public readonly ?string $status = null,
        /** ISO 8601 timestamp the device was enrolled; null if omitted. */
        public readonly ?string $enrolledAt = null,
    ) {
    }
}
