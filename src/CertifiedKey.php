<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The key Root Herald registered against the installation that certified it,
 * as {@see Client::certifyKey} returns it.
 *
 * Store {@see $keyId} and {@see $jwk} against {@see $deviceId}; verify later
 * signatures from the device with {@see KeySignatures::verify}. The private
 * half never leaves the chip that made it, and Root Herald never holds it.
 *
 * The key is P-256 or RSA-2048, chosen by the device, never by the caller.
 * {@see $keyId} identifies an installation's credential, never a device:
 * bind accounts to the alias. Minting again for the same purpose rotates the
 * key under the same id; a re-enrolled installation gets new ids.
 */
final class CertifiedKey
{
    public const ALG_ES256 = 'ES256';
    public const ALG_RS256 = 'RS256';
    public const ALG_ECDH_ES = 'ECDH-ES';
    public const ALG_RSA_OAEP_256 = 'RSA-OAEP-256';

    private const EC_ALGS = [self::ALG_ES256, self::ALG_ECDH_ES];
    private const RSA_ALGS = [self::ALG_RS256, self::ALG_RSA_OAEP_256];
    private const PURPOSES = ['sign', 'decrypt'];
    private const FORMATS = ['jwe', 'apple-ecies'];

    /**
     * @param array{kty: 'EC', crv: 'P-256', x: string, y: string}|array{kty: 'RSA', n: string, e: string} $jwk
     */
    public function __construct(
        /** This tenant's alias for the device that holds the key (`verdict.device.ueid`); never relay it to the device. */
        public readonly string $deviceId,
        /** Root Herald's id for this key; stable across rotations of the same purpose. */
        public readonly string $keyId,
        /** What the key is for: "sign" or "decrypt". */
        public readonly string $purpose,
        /** ES256 / RS256 for a sign key; ECDH-ES / RSA-OAEP-256 for a decrypt key. */
        public readonly string $alg,
        /** The public key: kty "EC" (crv P-256, base64url x / y) or kty "RSA" (base64url n / e). */
        public readonly array $jwk,
        /** True when the key lives in a TPM and was certified by the installation's AK; false on macOS, where the certification proves possession only. */
        public readonly bool $hardwareBound,
        /** ISO 8601 timestamp of the certification. */
        public readonly string $certifiedAt,
        /** Present for a decrypt key: the envelope to produce, "jwe" or "apple-ecies". */
        public readonly ?string $format = null,
    ) {
    }

    /**
     * Build from the `/keys/certify` response body, or return null when it is
     * not a well-formed certified key. The JWK family must fit `alg`: an EC
     * key signs ES256 or agrees ECDH-ES, an RSA key signs RS256 or wraps
     * RSA-OAEP-256. Anything else is refused rather than surfaced half-parsed.
     *
     * @param mixed $data
     */
    public static function fromWire(mixed $data): ?self
    {
        if (!is_array($data)) {
            return null;
        }
        $deviceId = $data['deviceId'] ?? null;
        $keyId = $data['keyId'] ?? null;
        $purpose = $data['purpose'] ?? null;
        $alg = $data['alg'] ?? null;
        $hardwareBound = $data['hardwareBound'] ?? null;
        $certifiedAt = $data['certifiedAt'] ?? null;
        $format = $data['format'] ?? null;
        if (
            !is_string($deviceId) || $deviceId === ''
            || !is_string($keyId) || $keyId === ''
            || !in_array($purpose, self::PURPOSES, true)
            || !is_string($alg)
            || !is_bool($hardwareBound)
            || !is_string($certifiedAt) || $certifiedAt === ''
            || ($format !== null && !in_array($format, self::FORMATS, true))
        ) {
            return null;
        }
        $jwk = self::readJwk($data['jwk'] ?? null);
        if ($jwk === null) {
            return null;
        }
        $algs = $jwk['kty'] === 'EC' ? self::EC_ALGS : self::RSA_ALGS;
        if (!in_array($alg, $algs, true)) {
            return null;
        }

        return new self($deviceId, $keyId, $purpose, $alg, $jwk, $hardwareBound, $certifiedAt, $format);
    }

    /**
     * @param mixed $value
     * @return array{kty: 'EC', crv: 'P-256', x: string, y: string}|array{kty: 'RSA', n: string, e: string}|null
     */
    private static function readJwk(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }
        if (
            ($value['kty'] ?? null) === 'EC'
            && ($value['crv'] ?? null) === 'P-256'
            && is_string($value['x'] ?? null)
            && is_string($value['y'] ?? null)
        ) {
            return ['kty' => 'EC', 'crv' => 'P-256', 'x' => $value['x'], 'y' => $value['y']];
        }
        if (
            ($value['kty'] ?? null) === 'RSA'
            && is_string($value['n'] ?? null)
            && is_string($value['e'] ?? null)
        ) {
            return ['kty' => 'RSA', 'n' => $value['n'], 'e' => $value['e']];
        }

        return null;
    }
}
