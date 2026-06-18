<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The result of {@see BackgroundCheck::attest}: the device verdict plus, when
 * requested, the signed EAT (JWT). The token is itself verifiable offline with
 * {@see AttestationTokenVerifier}.
 */
final class AttestResult
{
    /**
     * @param array<string, mixed> $verdictData the full decoded verdict object
     */
    public function __construct(
        public readonly Verdict $verdict,
        public readonly array $verdictData,
        public readonly ?string $token = null,
    ) {
    }
}
