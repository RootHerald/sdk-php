<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * A TPM-resident signing key the appraisal certified. Returned by
 * {@see AttestResult::key()} when the challenge asked for "key" and the
 * verdict passed.
 *
 * Store it against the user; verify later signatures from the device with
 * {@see KeySignatures::verify}. The private half never leaves the TPM that
 * made it, and Root Herald never holds it.
 */
final class CertifiedKey
{
    /**
     * @param array{kty: string, crv: string, x: string, y: string} $jwk the public key as a JWK
     */
    public function __construct(
        /** Root Herald's id for this key; stable for the key's lifetime. */
        public readonly string $keyId,
        /** The public key: kty "EC", crv "P-256" | "P-384", base64url x / y. */
        public readonly array $jwk,
        /** What the key is certified for; echoes the challenge's keyPurpose ("sign"). */
        public readonly ?string $purpose,
        /** base64 authPolicy digest from the key's public area; null for a key without one. */
        public readonly ?string $authPolicy,
        /** ISO 8601 timestamp of the certification. */
        public readonly string $certifiedAt,
    ) {
    }

    /**
     * Build from the wire shape at the verify response root, or return null
     * when it is not a well-formed certified key.
     *
     * @param mixed $data
     */
    public static function fromWire(mixed $data): ?self
    {
        if (!is_array($data)) {
            return null;
        }
        $jwk = $data['jwk'] ?? null;
        if (
            !is_string($data['keyId'] ?? null)
            || !is_string($data['certifiedAt'] ?? null)
            || !is_array($jwk)
            || !is_string($jwk['kty'] ?? null)
            || !is_string($jwk['crv'] ?? null)
            || !is_string($jwk['x'] ?? null)
            || !is_string($jwk['y'] ?? null)
        ) {
            return null;
        }

        return new self(
            $data['keyId'],
            ['kty' => $jwk['kty'], 'crv' => $jwk['crv'], 'x' => $jwk['x'], 'y' => $jwk['y']],
            is_string($data['purpose'] ?? null) ? $data['purpose'] : null,
            is_string($data['authPolicy'] ?? null) ? $data['authPolicy'] : null,
            $data['certifiedAt'],
        );
    }
}
