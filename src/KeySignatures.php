<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Verifies signatures made by a {@see CertifiedKey} on the device, using only
 * ext-openssl.
 *
 * The device signs with the TPM-resident key; the backend checks the signature
 * against the JWK it stored from the attestation. ECDSA over SHA-256 for
 * P-256 and SHA-384 for P-384. The signature may be either the raw r||s the
 * TPM emits (64 bytes for P-256, 96 for P-384) or ASN.1 DER.
 */
final class KeySignatures
{
    /**
     * SubjectPublicKeyInfo prefix per curve: SEQUENCE { AlgorithmIdentifier
     * { ecPublicKey, namedCurve }, BIT STRING (0 unused bits) } up to and
     * including the 0x04 uncompressed-point tag. Fixed because the point
     * length is fixed per curve.
     */
    private const CURVES = [
        'P-256' => [
            'prefix' => '3059301306072a8648ce3d020106082a8648ce3d030107034200',
            'coordinate' => 32,
            'algo' => OPENSSL_ALGO_SHA256,
        ],
        'P-384' => [
            'prefix' => '3076301006072a8648ce3d020106052b81040022036200',
            'coordinate' => 48,
            'algo' => OPENSSL_ALGO_SHA384,
        ],
    ];

    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $jwk       the certified key's public half (kty, crv, x, y)
     * @param string               $message   the bytes that were signed (hashed here; do not pre-hash)
     * @param string               $signature raw r||s or DER-encoded ECDSA signature
     *
     * @return bool true only when the signature verifies; false for any
     *              malformed or non-matching signature, never an exception for one
     *
     * @throws \InvalidArgumentException when the JWK itself is not a P-256 /
     *         P-384 EC key with decodable coordinates
     */
    public static function verify(array $jwk, string $message, string $signature): bool
    {
        if (($jwk['kty'] ?? null) !== 'EC') {
            throw new \InvalidArgumentException('jwk.kty must be EC');
        }
        $crv = $jwk['crv'] ?? null;
        if (!is_string($crv) || !isset(self::CURVES[$crv])) {
            throw new \InvalidArgumentException('jwk.crv must be P-256 or P-384');
        }
        $curve = self::CURVES[$crv];
        $x = self::coordinate($jwk['x'] ?? null, 'x', $curve['coordinate']);
        $y = self::coordinate($jwk['y'] ?? null, 'y', $curve['coordinate']);

        if ($signature === '') {
            return false;
        }

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode(hex2bin($curve['prefix']) . "\x04" . $x . $y), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            self::drainErrors();
            throw new \InvalidArgumentException('jwk is not a usable EC public key');
        }

        $rawLength = 2 * $curve['coordinate'];
        if (strlen($signature) === $rawLength) {
            if (self::verifyDer($message, self::rawToDer($signature), $key, $curve['algo'])) {
                return true;
            }
            // A DER signature is very unlikely to be exactly this long, but it
            // is possible; try it as DER before giving up.
            return $signature[0] === "\x30" && self::verifyDer($message, $signature, $key, $curve['algo']);
        }

        return self::verifyDer($message, $signature, $key, $curve['algo']);
    }

    private static function verifyDer(string $message, string $der, \OpenSSLAsymmetricKey $key, int $algo): bool
    {
        $result = @openssl_verify($message, $der, $key, $algo);
        self::drainErrors();

        return $result === 1;
    }

    private static function coordinate(mixed $value, string $field, int $length): string
    {
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException("jwk.{$field} is required");
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \InvalidArgumentException("jwk.{$field} is not base64url");
        }
        // Left-pad a short coordinate; a longer one cannot be on the curve.
        if (strlen($decoded) > $length) {
            throw new \InvalidArgumentException("jwk.{$field} is too long for {$length}-byte coordinates");
        }

        return str_pad($decoded, $length, "\x00", STR_PAD_LEFT);
    }

    /** Encode raw r||s as the DER SEQUENCE { INTEGER r, INTEGER s } OpenSSL expects. */
    public static function rawToDer(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);
        $body = self::derInteger(substr($raw, 0, $half)) . self::derInteger(substr($raw, $half));

        return "\x30" . self::derLength(strlen($body)) . $body;
    }

    private static function derInteger(string $bytes): string
    {
        $trimmed = ltrim($bytes, "\x00");
        if ($trimmed === '') {
            $trimmed = "\x00";
        }
        if ((ord($trimmed[0]) & 0x80) !== 0) {
            $trimmed = "\x00" . $trimmed;
        }

        return "\x02" . self::derLength(strlen($trimmed)) . $trimmed;
    }

    private static function derLength(int $length): string
    {
        // Two P-384 integers fit in one length byte; the long form is only
        // reachable with a longer curve than this class accepts.
        return $length < 0x80 ? chr($length) : "\x81" . chr($length);
    }

    private static function drainErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard; a failed verify must not leak into a later unrelated call
        }
    }
}
