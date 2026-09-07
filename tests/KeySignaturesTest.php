<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\KeySignatures;

/**
 * The backend checks device signatures against the JWK it stored from the
 * attestation, so the verifier must accept what a TPM emits (raw r||s) and
 * what most libraries emit (DER), and must refuse everything else quietly.
 */
final class KeySignaturesTest extends TestCase
{
    private const MESSAGE = 'transfer 100 to acct-42';

    /**
     * @return array{key: \OpenSSLAsymmetricKey, jwk: array<string, string>, algo: int, size: int}
     */
    private static function fixture(string $crv): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $crv === 'P-256' ? 'prime256v1' : 'secp384r1',
        ]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertNotFalse($details);
        $size = $crv === 'P-256' ? 32 : 48;

        return [
            'key' => $key,
            'jwk' => [
                'kty' => 'EC',
                'crv' => $crv,
                'x' => self::b64url(str_pad($details['ec']['x'], $size, "\x00", STR_PAD_LEFT)),
                'y' => self::b64url(str_pad($details['ec']['y'], $size, "\x00", STR_PAD_LEFT)),
            ],
            'algo' => $crv === 'P-256' ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA384,
            'size' => $size,
        ];
    }

    /** @param array{key: \OpenSSLAsymmetricKey, algo: int} $f */
    private static function signDer(array $f, string $message): string
    {
        $sig = '';
        self::assertTrue(openssl_sign($message, $sig, $f['key'], $f['algo']));

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

    public function testAcceptsDerSignatureP256(): void
    {
        $f = self::fixture('P-256');
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, self::signDer($f, self::MESSAGE)));
    }

    public function testAcceptsRawSignatureP256(): void
    {
        $f = self::fixture('P-256');
        $raw = self::derToRaw(self::signDer($f, self::MESSAGE), $f['size']);
        $this->assertSame(64, strlen($raw));
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, $raw));
    }

    public function testAcceptsDerAndRawP384(): void
    {
        $f = self::fixture('P-384');
        $der = self::signDer($f, self::MESSAGE);
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, $der));
        $raw = self::derToRaw($der, $f['size']);
        $this->assertSame(96, strlen($raw));
        $this->assertTrue(KeySignatures::verify($f['jwk'], self::MESSAGE, $raw));
    }

    public function testRejectsTamperedMessage(): void
    {
        $f = self::fixture('P-256');
        $sig = self::signDer($f, self::MESSAGE);
        $this->assertFalse(KeySignatures::verify($f['jwk'], 'transfer 999 to acct-42', $sig));
        $this->assertFalse(KeySignatures::verify($f['jwk'], 'transfer 999 to acct-42', self::derToRaw($sig, 32)));
    }

    public function testRejectsTamperedSignature(): void
    {
        $f = self::fixture('P-256');
        $raw = self::derToRaw(self::signDer($f, self::MESSAGE), 32);
        $raw[10] = chr(ord($raw[10]) ^ 0x01);
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, $raw));
    }

    public function testRejectsSignatureFromAnotherKey(): void
    {
        $signer = self::fixture('P-256');
        $other = self::fixture('P-256');
        $this->assertFalse(KeySignatures::verify($other['jwk'], self::MESSAGE, self::signDer($signer, self::MESSAGE)));
    }

    public function testMalformedSignaturesAreFalseNotThrown(): void
    {
        $f = self::fixture('P-256');
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, ''));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, "\x30\x01"));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, str_repeat("\x00", 64)));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, str_repeat("\x00", 96)));
        $this->assertFalse(KeySignatures::verify($f['jwk'], self::MESSAGE, 'not a signature'));
    }

    public function testRawSignatureOfTheWrongCurveWidthIsFalse(): void
    {
        $p256 = self::fixture('P-256');
        $p384 = self::fixture('P-384');
        $raw384 = self::derToRaw(self::signDer($p384, self::MESSAGE), 48);
        $this->assertFalse(KeySignatures::verify($p256['jwk'], self::MESSAGE, $raw384));
    }

    /** @return array<string, array{array<string, string>}> */
    public static function unusableJwks(): array
    {
        $good = self::fixture('P-256')['jwk'];

        return [
            'rsa kty'      => [['kty' => 'RSA'] + $good],
            'p-521'        => [['crv' => 'P-521'] + $good],
            'missing x'    => [['x' => ''] + $good],
            'not base64'   => [['x' => '!!not-base64url!!'] + $good],
            'x too long'   => [['x' => self::b64url(str_repeat("\x01", 33))] + $good],
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
        $f = self::fixture('P-256');
        $raw = self::derToRaw(self::signDer($f, self::MESSAGE), 32);
        // OpenSSL 3 refuses to verify with a private-key object, so hand it the public half.
        $public = openssl_pkey_get_public(openssl_pkey_get_details($f['key'])['key']);
        self::assertNotFalse($public);
        $this->assertSame(1, openssl_verify(self::MESSAGE, KeySignatures::rawToDer($raw), $public, OPENSSL_ALGO_SHA256));
    }
}
