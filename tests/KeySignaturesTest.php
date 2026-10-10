<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\KeySignatures;

/**
 * The backend checks device signatures against the JWK it stored from the
 * certification, so the verifier must accept what a TPM emits (raw r||s for
 * ECDSA, PKCS#1 v1.5 for RSA) and what most libraries emit (DER), and must
 * refuse everything else quietly.
 */
final class KeySignaturesTest extends TestCase
{
    private const MESSAGE = 'transfer 100 to acct-42';

    /**
     * @return array{key: \OpenSSLAsymmetricKey, jwk: array<string, string>}
     */
    private static function ecFixture(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertNotFalse($details);

        return [
            'key' => $key,
            'jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => self::b64url(str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT)),
                'y' => self::b64url(str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT)),
            ],
        ];
    }

    /**
     * @return array{key: \OpenSSLAsymmetricKey, jwk: array<string, string>, bytes: int}
     */
    private static function rsaFixture(int $bits = 2048): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertNotFalse($details);

        return [
            'key' => $key,
            'jwk' => [
                'kty' => 'RSA',
                'n' => self::b64url($details['rsa']['n']),
                'e' => self::b64url($details['rsa']['e']),
            ],
            'bytes' => intdiv($bits + 7, 8),
        ];
    }

    /** @param array{key: \OpenSSLAsymmetricKey} $f */
    private static function sign(array $f, string $message): string
    {
        $sig = '';
        self::assertTrue(openssl_sign($message, $sig, $f['key'], OPENSSL_ALGO_SHA256));

        return $sig;
    }

    /** DER SEQUENCE { INTEGER r, INTEGER s } to fixed-width r||s. */
    private static function derToRaw(string $der, int $size): string
    {
        $i = 2;
        if ((ord($der[1]) & 0x80) !== 0) {
            $i = 2 + (ord($der[1]) & 0x7F);
        }
        $rLen = ord($der[$i + 1]);
        $r = substr($der, $i + 2, $rLen);
        $j = $i + 2 + $rLen;
        $sLen = ord($der[$j + 1]);
        $s = substr($der, $j + 2, $sLen);

        return str_pad(ltrim($r, "\x00"), $size, "\x00", STR_PAD_LEFT)
            . str_pad(ltrim($s, "\x00"), $size, "\x00", STR_PAD_LEFT);
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    // ── ES256 ──────────────────────────────────────────────────────────────

    public function testAcceptsDerSignatureP256(): void
    {
        $f = self::ecFixture();
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, self::sign($f, self::MESSAGE)));
    }

    public function testAcceptsRawSignatureP256(): void
    {
        $f = self::ecFixture();
        $raw = self::derToRaw(self::sign($f, self::MESSAGE), 32);
        $this->assertSame(64, strlen($raw));
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, $raw));
    }

    public function testRejectsTamperedMessage(): void
    {
        $f = self::ecFixture();
        $sig = self::sign($f, self::MESSAGE);
        $this->assertFalse(KeySignatures::verify($f['jwk'], 'transfer 999 to acct-42', $sig));
        $this->assertFalse(KeySignatures::verify($f['jwk'], 'transfer 999 to acct-42', self::derToRaw($sig, 32)));
    }

    public function testRejectsTamperedSignature(): void
    {
        $f = self::ecFixture();
        $raw = self::derToRaw(self::sign($f, self::MESSAGE), 32);
        $raw[10] = chr(ord($raw[10]) ^ 0x01);
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, $raw));
    }

    public function testRejectsSignatureFromAnotherKey(): void
    {
        $signer = self::ecFixture();
        $other = self::ecFixture();
        $this->assertFalse(KeySignatures::verify($other['jwk'], self::MESSAGE, self::sign($signer, self::MESSAGE)));
    }

    public function testMalformedSignaturesAreFalseNotThrown(): void
    {
        $f = self::ecFixture();
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, ''));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, "\x30\x01"));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, str_repeat("\x00", 64)));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, str_repeat("\x00", 96)));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, 'not a signature'));
    }

    // ── RS256 ──────────────────────────────────────────────────────────────

    public function testAcceptsAnRsa2048Signature(): void
    {
        $f = self::rsaFixture();
        $sig = self::sign($f, self::MESSAGE);
        $this->assertSame(256, strlen($sig));
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, $sig));
    }

    public function testRsaRejectsTamperedMessageAndSignature(): void
    {
        $f = self::rsaFixture();
        $sig = self::sign($f, self::MESSAGE);
        $this->assertFalse(KeySignatures::verify($f['jwk'], 'transfer 999 to acct-42', $sig));
        $sig[10] = chr(ord($sig[10]) ^ 0x01);
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, $sig));
    }

    public function testRsaRejectsSignatureFromAnotherKey(): void
    {
        $signer = self::rsaFixture();
        $other = self::rsaFixture();
        $this->assertFalse(KeySignatures::verify($other['jwk'], self::MESSAGE, self::sign($signer, self::MESSAGE)));
    }

    public function testRsaSignatureMustBeExactlyTheModulusLength(): void
    {
        $f = self::rsaFixture();
        $sig = self::sign($f, self::MESSAGE);
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, ''));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, substr($sig, 1)));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, "\x00" . $sig));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, str_repeat("\x00", 256)));
    }

    public function testAnRsaKeyUnder2048BitsIsACallerError(): void
    {
        $f = self::rsaFixture(1024);
        $this->expectException(\InvalidArgumentException::class);
        KeySignatures::verify($f['jwk'], self::MESSAGE, self::sign($f, self::MESSAGE));
    }

    public function testAnEcSignatureNeverVerifiesUnderAnRsaKeyOrTheReverse(): void
    {
        $ec = self::ecFixture();
        $rsa = self::rsaFixture();
        $this->assertFalse(KeySignatures::verify($rsa['jwk'], self::MESSAGE, self::sign($ec, self::MESSAGE)));
        $this->assertFalse(KeySignatures::verify($ec['jwk'], self::MESSAGE, self::sign($rsa, self::MESSAGE)));
    }

    // ── unusable keys ──────────────────────────────────────────────────────

    /** @return array<string, array{array<string, string>}> */
    public static function unusableJwks(): array
    {
        $ec = self::ecFixture()['jwk'];
        $rsa = self::rsaFixture()['jwk'];

        return [
            'oct kty'        => [['kty' => 'oct'] + $ec],
            'p-384'          => [['crv' => 'P-384'] + $ec],
            'p-521'          => [['crv' => 'P-521'] + $ec],
            'missing x'      => [['x' => ''] + $ec],
            'not base64'     => [['x' => '!!not-base64url!!'] + $ec],
            'x too long'     => [['x' => self::b64url(str_repeat("\x01", 33))] + $ec],
            'rsa missing n'  => [['n' => ''] + $rsa],
            'rsa missing e'  => [array_diff_key($rsa, ['e' => 1])],
            'rsa n not base64' => [['n' => '!!'] + $rsa],
        ];
    }

    /**
     * @dataProvider unusableJwks
     * @param array<string, string> $jwk
     */
    public function testUnusableJwkIsACallerError(array $jwk): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KeySignatures::verify($jwk, self::MESSAGE, str_repeat("\x01", 64));
    }

    public function testRawToDerRoundTripsThroughOpenssl(): void
    {
        $f = self::ecFixture();
        $raw = self::derToRaw(self::sign($f, self::MESSAGE), 32);
        // OpenSSL 3 refuses to verify with a private-key object, so hand it the public half.
        $public = openssl_pkey_get_public(openssl_pkey_get_details($f['key'])['key']);
        self::assertNotFalse($public);
        $this->assertSame(1, openssl_verify(self::MESSAGE, KeySignatures::rawToDer($raw), $public, OPENSSL_ALGO_SHA256));
    }
}
