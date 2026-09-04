<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The TPM2_MakeCredential challenge returned by the enroll relay leg
 * (`POST /api/v1/attest/enroll`, HTTP 201) — the input the customer's backend
 * hands to the dumb client's `EnrollComplete()`.
 *
 * Mirrors the contract's `EnrollActivationChallenge`. {@see $credentialBlob} and
 * {@see $encryptedSecret} are the (TPM2B-framed) MakeCredential outputs; the
 * client feeds them straight into TPM2_ActivateCredential, then returns the
 * decrypted secret for {@see Client::relayActivate}.
 */
final class EnrollChallenge
{
    public function __construct(
        /** The deterministic device id (UUID), derived server-side from the EK. */
        public readonly string $deviceId,
        /** base64 TPM2_MakeCredential credential blob (`id-object`). */
        public readonly string $credentialBlob,
        /** base64 TPM2_MakeCredential encrypted secret (`encrypted-secret`). */
        public readonly string $encryptedSecret,
    ) {
    }

    /**
     * The MakeCredential challenge as the wire-shaped associative array the
     * client's `EnrollComplete()` consumes.
     *
     * @return array{deviceId: string, credentialBlob: string, encryptedSecret: string}
     */
    public function toArray(): array
    {
        return [
            'deviceId' => $this->deviceId,
            'credentialBlob' => $this->credentialBlob,
            'encryptedSecret' => $this->encryptedSecret,
        ];
    }
}
