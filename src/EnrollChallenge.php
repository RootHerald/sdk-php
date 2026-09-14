<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The activation challenge returned by the enroll relay leg
 * (`POST /api/v1/attest/enroll`, HTTP 201) — the input the customer's backend
 * hands to the dumb client's `EnrollComplete()`.
 *
 * Mirrors the contract's `EnrollActivationChallenge`. A TPM device gets
 * {@see $credentialBlob} and {@see $encryptedSecret}, the (TPM2B-framed)
 * TPM2_MakeCredential outputs it feeds straight into TPM2_ActivateCredential;
 * a macOS device gets {@see $challengeNonce} to sign with its enclave key.
 * Either way the client answers with {@see $enrollmentId} and its proof, which
 * goes to {@see Client::relayActivate}.
 *
 * Nothing here names the device: the enrollment id is the server's handle
 * for this open enrollment, not a device identifier.
 */
final class EnrollChallenge
{
    public function __construct(
        /** The server's handle for this open enrollment (UUID). */
        public readonly string $enrollmentId,
        /** base64 TPM2_MakeCredential credential blob (`id-object`); TPM only. */
        public readonly ?string $credentialBlob = null,
        /** base64 TPM2_MakeCredential encrypted secret (`encrypted-secret`); TPM only. */
        public readonly ?string $encryptedSecret = null,
        /** base64 nonce for the enclave key to sign; macOS only. */
        public readonly ?string $challengeNonce = null,
    ) {
    }

    /**
     * Build from the 201 body, or return null when it is not a well-formed
     * activation challenge: an enrollmentId plus either both MakeCredential
     * outputs or a challengeNonce.
     *
     * @param mixed $data
     */
    public static function fromWire(mixed $data): ?self
    {
        if (!is_array($data) || !is_string($data['enrollmentId'] ?? null) || $data['enrollmentId'] === '') {
            return null;
        }
        $credentialBlob = is_string($data['credentialBlob'] ?? null) ? $data['credentialBlob'] : null;
        $encryptedSecret = is_string($data['encryptedSecret'] ?? null) ? $data['encryptedSecret'] : null;
        $challengeNonce = is_string($data['challengeNonce'] ?? null) ? $data['challengeNonce'] : null;

        $tpm = $credentialBlob !== null && $encryptedSecret !== null;
        if (!$tpm && $challengeNonce === null) {
            return null;
        }

        return new self($data['enrollmentId'], $credentialBlob, $encryptedSecret, $challengeNonce);
    }

    /**
     * The activation challenge as the wire-shaped associative array the
     * client's `EnrollComplete()` consumes; absent fields are omitted.
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return array_filter([
            'enrollmentId' => $this->enrollmentId,
            'credentialBlob' => $this->credentialBlob,
            'encryptedSecret' => $this->encryptedSecret,
            'challengeNonce' => $this->challengeNonce,
        ], static fn (?string $v): bool => $v !== null);
    }
}
