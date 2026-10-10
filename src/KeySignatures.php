<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Verifies signatures made by a {@see CertifiedKey} on the device, using only
 * ext-openssl.
 *
 * The device signs with the chip-resident key; the backend checks the
 * signature against the JWK it stored from {@see Client::certifyKey}. An EC
 * P-256 key checks ES256 (ECDSA over SHA-256), with the signature either the
 * raw r||s the TPM emits (64 bytes) or ASN.1 DER. An RSA key checks RS256
 * (PKCS#1 v1.5 over SHA-256), with the signature exactly the modulus length
 * (256 bytes for RSA-2048); a modulus under 2048 bits is refused.
 *
 * A signature proves possession of the key at that moment, not how the
 * machine booted; run an attest challenge for that.
 */
final class KeySignatures
{
    /**
     * SubjectPublicKeyInfo prefix for P-256: SEQUENCE { AlgorithmIdentifier
     * { ecPublicKey, prime256v1 }, BIT STRING (0 unused bits) } up to and
     * including the 0x04 uncompressed-point tag. Fixed because the point
     * length is fixed for the curve.
     */
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';
    private const P256_COORDINATE = 32;

    /** AlgorithmIdentifier { rsaEncryption, NULL }. */
    private const RSA_ALGORITHM_IDENTIFIER = '300d06092a864886f70d0101010500';
    private const MIN_RSA_MODULUS_BITS = 2048;

    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $jwk       the certified key's public half, as certifyKey returned it
     * @param string               $message   the bytes that were signed (hashed here; do not pre-hash)
     * @param string               $signature raw r||s or DER-encoded ECDSA signature; PKCS#1 v1.5 RSA signature
     *
     * @return bool true only when the signature verifies; false for any
     *              malformed or non-matching signature, never an exception for one
     *
     * @throws \InvalidArgumentException when the JWK itself is not a P-256 EC key
     *         or an RSA key of at least 2048 bits with decodable components
     */
    public static function verify(array $jwk, string $message, string $signature): bool
    {
        return match ($jwk['kty'] ?? null) {
            'EC' => self::verifyEs256($jwk, $message, $signature),
            'RSA' => self::verifyRs256($jwk, $message, $signature),
            default => throw new \InvalidArgumentException('jwk.kty must be EC or RSA'),
        };
    }

    /** @param array<string, mixed> $jwk */
    private static function verifyEs256(array $jwk, string $message, string $signature): bool
    {
        if (($jwk['crv'] ?? null) !== 'P-256') {
            throw new \InvalidArgumentException('jwk.crv must be P-256');
        }
        $x = self::component($jwk['x'] ?? null, 'x', self::P256_COORDINATE);
        $y = self::component($jwk['y'] ?? null, 'y', self::P256_COORDINATE);
        $key = self::publicKey(hex2bin(self::P256_SPKI_PREFIX) . "\x04" . $x . $y, 'EC');

        if ($signature === '') {
            return false;
        }
        if (strlen($signature) === 2 * self::P256_COORDINATE) {
            if (self::verifyWith($message, self::rawToDer($signature), $key)) {
                return true;
            }
            // A DER signature is very unlikely to be exactly this long, but it
            // is possible; try it as DER before giving up.
            return $signature[0] === "\x30" && self::verifyWith($message, $signature, $key);
        }

        return self::verifyWith($message, $signature, $key);
    }

    /** @param array<string, mixed> $jwk */
    private static function verifyRs256(array $jwk, string $message, string $signature): bool
    {
        $n = self::component($jwk['n'] ?? null, 'n');
        $e = self::component($jwk['e'] ?? null, 'e');
        $rsaPublicKey = "\x30" . self::derLength(strlen(self::derInteger($n) . self::derInteger($e)))
            . self::derInteger($n) . self::derInteger($e);
        $bitString = "\x03" . self::derLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $spkiBody = hex2bin(self::RSA_ALGORITHM_IDENTIFIER) . $bitString;
        $key = self::publicKey("\x30" . self::derLength(strlen($spkiBody)) . $spkiBody, 'RSA');

        $details = openssl_pkey_get_details($key);
        $bits = is_array($details) && is_int($details['bits'] ?? null) ? $details['bits'] : 0;
        if ($bits < self::MIN_RSA_MODULUS_BITS) {
            throw new \InvalidArgumentException('jwk RSA modulus must be at least 2048 bits');
        }
        if (strlen($signature) !== intdiv($bits + 7, 8)) {
            return false;
        }

        return self::verifyWith($message, $signature, $key);
    }

    private static function publicKey(string $spkiDer, string $expectedType): \OpenSSLAsymmetricKey
    {
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spkiDer), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            self::drainErrors();
            throw new \InvalidArgumentException("jwk is not a usable {$expectedType} public key");
        }

        return $key;
    }

    private static function verifyWith(string $message, string $signature, \OpenSSLAsymmetricKey $key): bool
    {
        $result = @openssl_verify($message, $signature, $key, OPENSSL_ALGO_SHA256);
        self::drainErrors();

        return $result === 1;
    }

    /**
     * Decode a base64url JWK component. With a fixed length (EC coordinates)
     * a short value is left-padded and a longer one refused; without one
     * (RSA n / e) the bytes are returned as decoded.
     */
    private static function component(mixed $value, string $field, ?int $length = null): string
    {
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException("jwk.{$field} is required");
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false || $decoded === '') {
            throw new \InvalidArgumentException("jwk.{$field} is not base64url");
        }
        if ($length === null) {
            return $decoded;
        }
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
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function drainErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard; a failed verify must not leak into a later unrelated call
        }
    }
}
