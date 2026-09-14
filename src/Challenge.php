<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * A challenge minted by {@see Client::issueChallenge}.
 *
 * Relay {@see $challenge} to the dumb client verbatim; it carries the nonce and
 * the ask the server bound to this challenge. The client quotes over it and
 * returns an opaque evidence blob, which the server submits to
 * {@see Client::verify} using {@see $nonce}.
 */
final class Challenge
{
    public function __construct(
        /**
         * The backend's handle for this challenge: 32 random bytes, base64url
         * without padding. The proof is made over these bytes, and the server
         * finds the challenge by them. Keep it for verify; never relay it on
         * its own.
         */
        public readonly string $nonce,
        /** The opaque `rhc1.<nonce>.<ask>` string to relay to the client. */
        public readonly string $challenge,
        /** ISO 8601 expiry instant. */
        public readonly string $expiresAt,
    ) {
    }
}
