<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * A challenge minted by {@see Client::issueChallenge}.
 *
 * Relay {@see $challenge} to the dumb client verbatim; it carries the nonce and
 * the ask the server bound to this challenge. The client quotes over it and
 * returns an opaque evidence blob, which the server submits to
 * {@see Client::verify} using {@see $challengeId}.
 */
final class Challenge
{
    public function __construct(
        /** Single-use challenge id. */
        public readonly string $challengeId,
        /** The bare nonce the TPM signs over. */
        public readonly string $nonce,
        /** ISO 8601 expiry instant. */
        public readonly string $expiresAt,
        /** The opaque challenge string to relay to the client; null if the server omitted it. */
        public readonly ?string $challenge = null,
    ) {
    }
}
