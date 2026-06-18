<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * A relay-friendly nonce minted by {@see BackgroundCheck::createChallenge}.
 *
 * Relay {@see $nonce} to the dumb client; it quotes over it and returns an
 * opaque evidence blob, which the server submits to
 * {@see BackgroundCheck::attest} using {@see $challengeId}.
 */
final class Challenge
{
    public function __construct(
        public readonly string $challengeId,
        public readonly string $nonce,
        public readonly string $expiresAt,
    ) {
    }
}
