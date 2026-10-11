<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * A key challenge minted by {@see Client::issueKeyChallenge}.
 *
 * Relay {@see $keyChallenge} to the client verbatim; its `MintKey` creates
 * the key and has the installation's attestation key certify it over the
 * nonce. Submit the certification to {@see Client::certifyKey} using
 * {@see $nonce}.
 */
final class KeyChallenge
{
    public function __construct(
        /**
         * The backend's handle for this key challenge: 32 random bytes,
         * base64url without padding. Keep it for certifyKey; never relay it
         * on its own.
         */
        public readonly string $nonce,
        /** The opaque `rhk1c.<nonce>.<purpose>` string to relay to the client. */
        public readonly string $keyChallenge,
        /** ISO 8601 expiry instant. */
        public readonly string $expiresAt,
    ) {
    }
}
