<?php

declare(strict_types=1);

namespace Rootherald;

use Rootherald\Exceptions\EnvelopeFormatNotSupportedException;

/**
 * Encrypts to a {@see CertifiedKey} minted with {@see Client::PURPOSE_DECRYPT},
 * using only ext-openssl.
 *
 * The result is the one JWE compact serialization the device's
 * RootHeraldDecrypt opens: ECDH-ES with the Concat KDF (RFC 7518 §4.6:
 * AlgorithmID the enc name, PartyU and PartyV empty, 256-bit key) and a fresh
 * ephemeral P-256 key per call for an EC key, RSA-OAEP-256 (OAEP SHA-256,
 * MGF1-SHA-256) wrapping a random 32-byte CEK for an RSA key, A256GCM for
 * both with the protected header as the additional data. The header carries
 * alg, enc and (ECDH-ES only) epk, nothing else, because the device refuses
 * any other member rather than ignoring it.
 *
 * Encryption uses the public half, so anyone holding the JWK can encrypt to
 * the device; what the chip guarantees is that only it can open the result.
 */
final class DeviceEncryption
{
    public const FORMAT_JWE = 'jwe';

    private const ENC = 'A256GCM';
    private const COORDINATE_BYTES = 32;
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;
    private const CEK_BYTES = 32;
    private const SHA256_BYTES = 32;
    private const MIN_RSA_MODULUS_BITS = 2048;

    private function __construct()
    {
    }

    /**
     * @param CertifiedKey $key       the decrypt key, as {@see Client::certifyKey} returned it
     * @param string       $plaintext the bytes only the device may read
     *
     * @return string the JWE compact serialization to send to the device
     *
     * @throws \InvalidArgumentException for a key that cannot open the result: a
     *         sign key, a key without a format, a curve other than P-256, a
     *         coordinate that is not 32 bytes, or an RSA modulus under 2048 bits
     * @throws EnvelopeFormatNotSupportedException for an apple-ecies key, which a
     *         macOS enclave opens and needs an Apple-side encryptor
     */
    public static function encryptToDevice(CertifiedKey $key, string $plaintext): string
    {
        return self::encryptToDeviceWith(
            $key,
            $plaintext,
            static fn (): \OpenSSLAsymmetricKey => self::freshEphemeral(),
            static fn (int $n): string => random_bytes($n),
        );
    }

    /**
     * The seam the known-answer tests inject the ephemeral key, CEK, OAEP
     * seed and IV through: $random is asked for the CEK (32 bytes, RSA only),
     * then the OAEP seed (32 bytes, RSA only), then the IV (12 bytes).
     *
     * @internal
     *
     * @param callable(): \OpenSSLAsymmetricKey $ephemeral
     * @param callable(int): string             $random
     */
    public static function encryptToDeviceWith(CertifiedKey $key, string $plaintext, callable $ephemeral, callable $random): string
    {
        if ($key->purpose !== Client::PURPOSE_DECRYPT) {
            throw new \InvalidArgumentException("key purpose is \"{$key->purpose}\"; only a decrypt key opens an envelope");
        }
        if ($key->format === null) {
            throw new \InvalidArgumentException('key has no envelope format; a decrypt key names jwe or apple-ecies');
        }
        if ($key->format !== self::FORMAT_JWE) {
            throw new EnvelopeFormatNotSupportedException($key->format);
        }
        $kty = $key->jwk['kty'] ?? null;
        if ($kty === 'EC' && $key->alg === CertifiedKey::ALG_ECDH_ES) {
            return self::encryptEcdhEs($key->jwk, $plaintext, $ephemeral, $random);
        }
        if ($kty === 'RSA' && $key->alg === CertifiedKey::ALG_RSA_OAEP_256) {
            return self::encryptRsaOaep($key->jwk, $plaintext, $random);
        }

        throw new \InvalidArgumentException(
            "key alg \"{$key->alg}\" with kty \"{$kty}\" is not ECDH-ES on an EC key or RSA-OAEP-256 on an RSA key"
        );
    }

    /**
     * @param array<string, mixed>              $jwk
     * @param callable(): \OpenSSLAsymmetricKey $ephemeral
     * @param callable(int): string             $random
     */
    private static function encryptEcdhEs(array $jwk, string $plaintext, callable $ephemeral, callable $random): string
    {
        if (($jwk['crv'] ?? null) !== 'P-256') {
            $crv = is_string($jwk['crv'] ?? null) ? $jwk['crv'] : '';
            throw new \InvalidArgumentException("jwk.crv \"{$crv}\" is not P-256; no device certifies another curve");
        }
        $x = self::coordinate($jwk['x'] ?? null, 'x');
        $y = self::coordinate($jwk['y'] ?? null, 'y');
        $recipient = KeySignatures::ecPublicKey($x, $y);

        $eph = $ephemeral();
        $z = @openssl_pkey_derive($recipient, $eph, self::COORDINATE_BYTES);
        self::drainErrors();
        if (!is_string($z) || strlen($z) !== self::COORDINATE_BYTES) {
            throw new \InvalidArgumentException('jwk is not a usable P-256 public key');
        }
        $cek = self::concatKdf($z);

        $details = openssl_pkey_get_details($eph);
        if (!is_array($details) || !isset($details['ec']['x'], $details['ec']['y'])) {
            throw new \RuntimeException('ephemeral key has no EC coordinates');
        }
        $epkX = str_pad($details['ec']['x'], self::COORDINATE_BYTES, "\x00", STR_PAD_LEFT);
        $epkY = str_pad($details['ec']['y'], self::COORDINATE_BYTES, "\x00", STR_PAD_LEFT);
        $header = '{"alg":"' . CertifiedKey::ALG_ECDH_ES . '","enc":"' . self::ENC
            . '","epk":{"kty":"EC","crv":"P-256","x":"' . self::b64url($epkX) . '","y":"' . self::b64url($epkY) . '"}}';

        return self::seal($header, '', $cek, $plaintext, $random);
    }

    /**
     * @param array<string, mixed>  $jwk
     * @param callable(int): string $random
     */
    private static function encryptRsaOaep(array $jwk, string $plaintext, callable $random): string
    {
        $n = self::component($jwk['n'] ?? null, 'n');
        $e = self::component($jwk['e'] ?? null, 'e');
        $recipient = KeySignatures::rsaPublicKey($n, $e);
        $details = openssl_pkey_get_details($recipient);
        $bits = is_array($details) && is_int($details['bits'] ?? null) ? $details['bits'] : 0;
        if ($bits < self::MIN_RSA_MODULUS_BITS) {
            throw new \InvalidArgumentException('jwk.n must be a modulus of at least ' . self::MIN_RSA_MODULUS_BITS . " bits (got {$bits})");
        }
        $k = intdiv($bits + 7, 8);

        $cek = $random(self::CEK_BYTES);
        $encryptedKey = '';
        $ok = @openssl_public_encrypt(self::oaepEncode($cek, $k, $random(self::SHA256_BYTES)), $encryptedKey, $recipient, OPENSSL_NO_PADDING);
        self::drainErrors();
        if (!$ok || strlen($encryptedKey) !== $k) {
            throw new \RuntimeException('RSA-OAEP-256 wrap failed');
        }
        $header = '{"alg":"' . CertifiedKey::ALG_RSA_OAEP_256 . '","enc":"' . self::ENC . '"}';

        return self::seal($header, $encryptedKey, $cek, $plaintext, $random);
    }

    /** @param callable(int): string $random */
    private static function seal(string $header, string $encryptedKey, string $cek, string $plaintext, callable $random): string
    {
        $protected = self::b64url($header);
        $iv = $random(self::IV_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $protected, self::TAG_BYTES);
        if ($ciphertext === false || strlen($tag) !== self::TAG_BYTES) {
            throw new \RuntimeException('aes-256-gcm seal failed');
        }

        return $protected . '.' . self::b64url($encryptedKey) . '.' . self::b64url($iv) . '.' . self::b64url($ciphertext) . '.' . self::b64url($tag);
    }

    /**
     * RSAES-OAEP encoding (RFC 8017 §7.1.1) with SHA-256 and MGF1-SHA-256 and
     * an empty label. openssl_public_encrypt's OAEP padding is SHA-1 only, so
     * the encoding is done here and the key operation runs with no padding.
     */
    private static function oaepEncode(string $message, int $k, string $seed): string
    {
        $hLen = self::SHA256_BYTES;
        $lHash = hash('sha256', '', true);
        $ps = str_repeat("\x00", $k - strlen($message) - 2 * $hLen - 2);
        $db = $lHash . $ps . "\x01" . $message;
        $maskedDb = $db ^ self::mgf1($seed, $k - $hLen - 1);
        $maskedSeed = $seed ^ self::mgf1($maskedDb, $hLen);

        return "\x00" . $maskedSeed . $maskedDb;
    }

    private static function mgf1(string $seed, int $length): string
    {
        $out = '';
        for ($counter = 0; strlen($out) < $length; $counter++) {
            $out .= hash('sha256', $seed . pack('N', $counter), true);
        }

        return substr($out, 0, $length);
    }

    /**
     * Concat KDF, one round: SHA-256(counter ‖ Z ‖ AlgorithmID ‖ PartyUInfo ‖
     * PartyVInfo ‖ SuppPubInfo), each info field length-prefixed, keydatalen 256.
     */
    private static function concatKdf(string $z): string
    {
        return hash(
            'sha256',
            pack('N', 1) . $z . pack('N', strlen(self::ENC)) . self::ENC . pack('N', 0) . pack('N', 0) . pack('N', 256),
            true
        );
    }

    private static function freshEphemeral(): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false) {
            self::drainErrors();
            throw new \RuntimeException('P-256 is unavailable');
        }

        return $key;
    }

    private static function coordinate(mixed $value, string $field): string
    {
        $raw = self::component($value, $field);
        if (strlen($raw) !== self::COORDINATE_BYTES) {
            throw new \InvalidArgumentException("jwk.{$field} must decode to exactly " . self::COORDINATE_BYTES . ' bytes (got ' . strlen($raw) . ')');
        }

        return $raw;
    }

    private static function component(mixed $value, string $field): string
    {
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException("jwk.{$field} is required");
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false || $decoded === '') {
            throw new \InvalidArgumentException("jwk.{$field} is not base64url");
        }

        return $decoded;
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function drainErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard; a failed derive must not leak into a later unrelated call
        }
    }
}
