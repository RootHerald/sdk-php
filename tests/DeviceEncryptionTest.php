<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\CertifiedKey;
use Rootherald\Client;
use Rootherald\DeviceEncryption;
use Rootherald\Exceptions\EnvelopeFormatNotSupportedException;

/**
 * The envelope must be exactly what the device's whitelist parser opens: one
 * header shape, the header as AAD, a fresh ephemeral key per call; and every
 * key that cannot open it is refused before anything is encrypted.
 */
final class DeviceEncryptionTest extends TestCase
{
    private const PLAINTEXT = '{"session":"s-1","exp":1893456000}';

    /** @param array<string, string> $jwk */
    private static function key(string $purpose, string $alg, ?string $format, array $jwk): CertifiedKey
    {
        return new CertifiedKey('dev-alias', 'key-1', $purpose, $alg, $jwk, true, '2026-01-01T00:00:00Z', $format);
    }

    /** @return array{key: CertifiedKey, priv: \OpenSSLAsymmetricKey} */
    private static function ec(): array
    {
        $priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($priv);
        $d = openssl_pkey_get_details($priv);
        self::assertNotFalse($d);
        $jwk = [
            'kty' => 'EC', 'crv' => 'P-256',
            'x' => self::b64url(str_pad($d['ec']['x'], 32, "\x00", STR_PAD_LEFT)),
            'y' => self::b64url(str_pad($d['ec']['y'], 32, "\x00", STR_PAD_LEFT)),
        ];

        return ['key' => self::key(Client::PURPOSE_DECRYPT, 'ECDH-ES', 'jwe', $jwk), 'priv' => $priv];
    }

    /** @return array{key: CertifiedKey, priv: \OpenSSLAsymmetricKey} */
    private static function rsa(int $bits = 2048): array
    {
        $priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        self::assertNotFalse($priv);
        $d = openssl_pkey_get_details($priv);
        self::assertNotFalse($d);
        $jwk = ['kty' => 'RSA', 'n' => self::b64url($d['rsa']['n']), 'e' => self::b64url($d['rsa']['e'])];

        return ['key' => self::key(Client::PURPOSE_DECRYPT, 'RSA-OAEP-256', 'jwe', $jwk), 'priv' => $priv];
    }

    /** @param array<string, string>|null $jwk */
    private static function with(CertifiedKey $k, ?string $purpose = null, ?string $alg = null, ?string $format = null, ?array $jwk = null, bool $clearFormat = false): CertifiedKey
    {
        return new CertifiedKey(
            $k->deviceId,
            $k->keyId,
            $purpose ?? $k->purpose,
            $alg ?? $k->alg,
            $jwk ?? $k->jwk,
            $k->hardwareBound,
            $k->certifiedAt,
            $clearFormat ? null : ($format ?? $k->format),
        );
    }

    // ── ECDH-ES ────────────────────────────────────────────────────────────

    public function testEcKeyTwoEncryptionsDifferAndBothOpen(): void
    {
        $f = self::ec();
        $a = DeviceEncryption::encryptToDevice($f['key'], self::PLAINTEXT);
        $b = DeviceEncryption::encryptToDevice($f['key'], self::PLAINTEXT);

        self::assertNotSame($a, $b);
        self::assertSame(self::PLAINTEXT, self::open($a, $f['priv']));
        self::assertSame(self::PLAINTEXT, self::open($b, $f['priv']));
    }

    public function testEcHeaderIsExactlyAlgEncEpk(): void
    {
        $parts = explode('.', DeviceEncryption::encryptToDevice(self::ec()['key'], self::PLAINTEXT));
        self::assertCount(5, $parts);
        $header = self::decode($parts[0]);
        $h = json_decode($header, true, 8, JSON_THROW_ON_ERROR);

        self::assertSame(['alg', 'enc', 'epk'], array_keys($h));
        self::assertSame(['kty', 'crv', 'x', 'y'], array_keys($h['epk']));
        self::assertSame(
            '{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"' . $h['epk']['x'] . '","y":"' . $h['epk']['y'] . '"}}',
            $header
        );
        self::assertSame(32, strlen(self::decode($h['epk']['x'])));
        self::assertSame(32, strlen(self::decode($h['epk']['y'])));
        self::assertSame('', $parts[1]);
        self::assertSame(12, strlen(self::decode($parts[2])));
        self::assertSame(strlen(self::PLAINTEXT), strlen(self::decode($parts[3])));
        self::assertSame(16, strlen(self::decode($parts[4])));
    }

    // ── RSA-OAEP-256 ───────────────────────────────────────────────────────

    public function testRsaKeyTwoEncryptionsDifferAndBothOpen(): void
    {
        $f = self::rsa();
        $a = DeviceEncryption::encryptToDevice($f['key'], self::PLAINTEXT);
        $b = DeviceEncryption::encryptToDevice($f['key'], self::PLAINTEXT);

        self::assertNotSame($a, $b);
        self::assertSame(self::PLAINTEXT, self::open($a, $f['priv']));
        self::assertSame(self::PLAINTEXT, self::open($b, $f['priv']));
    }

    public function testRsaHeaderAndOaepSha256WithMgf1Sha256(): void
    {
        $f = self::rsa();
        $parts = explode('.', DeviceEncryption::encryptToDevice($f['key'], self::PLAINTEXT));

        self::assertSame('{"alg":"RSA-OAEP-256","enc":"A256GCM"}', self::decode($parts[0]));
        $encryptedKey = self::decode($parts[1]);
        self::assertSame(256, strlen($encryptedKey));
        self::assertSame(32, strlen(self::unwrap($encryptedKey, $f['priv'])));

        // The SHA-1 OAEP decode openssl offers must not open it.
        $out = '';
        self::assertFalse(@openssl_private_decrypt($encryptedKey, $out, $f['priv'], OPENSSL_PKCS1_OAEP_PADDING));
        while (openssl_error_string() !== false) {
        }
    }

    // ── AAD is the protected header ────────────────────────────────────────

    public function testHeaderEditedAfterSealingDoesNotOpen(): void
    {
        foreach ([self::ec(), self::rsa()] as $f) {
            $parts = explode('.', DeviceEncryption::encryptToDevice($f['key'], self::PLAINTEXT));
            // Equivalent JSON, different bytes: the AAD must be the bytes.
            $parts[0] = self::b64url(str_replace('"enc":', '"enc": ', self::decode($parts[0])));
            self::assertNull(self::open(implode('.', $parts), $f['priv'], false), $f['key']->alg);
        }
    }

    // ── Refusals ───────────────────────────────────────────────────────────

    public function testASignKeyIsRefused(): void
    {
        $dec = self::ec()['key'];
        foreach ([
            self::with($dec, Client::PURPOSE_SIGN, 'ES256', clearFormat: true),
            self::with($dec, Client::PURPOSE_SIGN, 'ES256'),
            self::with($dec, alg: 'ES256'),
        ] as $key) {
            try {
                DeviceEncryption::encryptToDevice($key, self::PLAINTEXT);
                self::fail('a sign key was encrypted to');
            } catch (\InvalidArgumentException $e) {
                self::assertNotInstanceOf(EnvelopeFormatNotSupportedException::class, $e);
            }
        }
    }

    public function testAnAppleEciesKeyIsRefusedByName(): void
    {
        $apple = self::with(self::ec()['key'], format: 'apple-ecies');
        try {
            DeviceEncryption::encryptToDevice($apple, self::PLAINTEXT);
            self::fail('an apple-ecies key was encrypted to');
        } catch (EnvelopeFormatNotSupportedException $e) {
            self::assertSame('apple-ecies', $e->format);
            self::assertStringContainsString('apple-ecies', $e->getMessage());
            self::assertInstanceOf(\InvalidArgumentException::class, $e);
        }
    }

    public function testADecryptKeyWithoutAFormatIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        DeviceEncryption::encryptToDevice(self::with(self::ec()['key'], clearFormat: true), self::PLAINTEXT);
    }

    public function testAP384KeyIsRefused(): void
    {
        $priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        self::assertNotFalse($priv);
        $d = openssl_pkey_get_details($priv);
        self::assertNotFalse($d);
        $jwk = [
            'kty' => 'EC', 'crv' => 'P-384',
            'x' => self::b64url(str_pad($d['ec']['x'], 48, "\x00", STR_PAD_LEFT)),
            'y' => self::b64url(str_pad($d['ec']['y'], 48, "\x00", STR_PAD_LEFT)),
        ];

        $this->expectException(\InvalidArgumentException::class);
        DeviceEncryption::encryptToDevice(self::key(Client::PURPOSE_DECRYPT, 'ECDH-ES', 'jwe', $jwk), self::PLAINTEXT);
    }

    /** @return iterable<string, array{int}> */
    public static function coordinateLengths(): iterable
    {
        yield '31 bytes' => [31];
        yield '33 bytes' => [33];
    }

    /** @dataProvider coordinateLengths */
    public function testEcCoordinatesThatAreNot32BytesAreRefused(int $length): void
    {
        $dec = self::ec()['key'];
        $jwk = $dec->jwk;
        $jwk['x'] = self::b64url(str_repeat("\x00", $length));

        $this->expectException(\InvalidArgumentException::class);
        DeviceEncryption::encryptToDevice(self::with($dec, jwk: $jwk), self::PLAINTEXT);
    }

    public function testAnEcPointOffTheCurveIsRefused(): void
    {
        $dec = self::ec()['key'];
        $jwk = $dec->jwk;
        $y = self::decode($jwk['y']);
        $y[31] = chr(ord($y[31]) ^ 1);
        $jwk['y'] = self::b64url($y);

        $this->expectException(\InvalidArgumentException::class);
        DeviceEncryption::encryptToDevice(self::with($dec, jwk: $jwk), self::PLAINTEXT);
    }

    public function testAShortRsaModulusIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        DeviceEncryption::encryptToDevice(self::rsa(1024)['key'], self::PLAINTEXT);
    }

    /** @return iterable<string, array{string}> */
    public static function smallExponents(): iterable
    {
        yield 'zero' => ["\x00"];
        yield 'one' => ["\x01"];
        yield 'two with a leading zero' => ["\x00\x02"];
    }

    /** @dataProvider smallExponents */
    public function testAnRsaExponentBelow3IsRefused(string $e): void
    {
        $rsa = self::rsa()['key'];
        $jwk = $rsa->jwk;
        $jwk['e'] = self::b64url($e);

        $this->expectException(\InvalidArgumentException::class);
        DeviceEncryption::encryptToDevice(self::with($rsa, jwk: $jwk), self::PLAINTEXT);
    }

    public function testAMismatchedAlgAndKtyIsRefused(): void
    {
        $ec = self::ec()['key'];
        $rsa = self::rsa()['key'];
        foreach ([self::with($ec, alg: 'RSA-OAEP-256'), self::with($rsa, alg: 'ECDH-ES')] as $key) {
            try {
                DeviceEncryption::encryptToDevice($key, self::PLAINTEXT);
                self::fail('a mismatched key was encrypted to');
            } catch (\InvalidArgumentException $e) {
                self::assertNotInstanceOf(EnvelopeFormatNotSupportedException::class, $e);
            }
        }
    }

    // ── Determinism through the seam ───────────────────────────────────────

    public function testTheSeamMakesTheEnvelopeReproducible(): void
    {
        $eph = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($eph);
        $counting = static fn (int $n): string => implode('', array_map('chr', range(1, $n)));
        foreach ([self::ec(), self::rsa()] as $f) {
            $a = DeviceEncryption::encryptToDeviceWith($f['key'], self::PLAINTEXT, static fn () => $eph, $counting);
            $b = DeviceEncryption::encryptToDeviceWith($f['key'], self::PLAINTEXT, static fn () => $eph, $counting);

            self::assertSame($a, $b, $f['key']->alg);
            self::assertSame(self::PLAINTEXT, self::open($a, $f['priv']));
        }
    }

    // ── Known-answer vectors from platform Fixtures/envelope ───────────────
    //
    // ECDH-ES replays byte for byte with the vector's ephemeral key and IV.
    // RSA-OAEP-256 draws its OAEP seed through the seam between the CEK and
    // the IV and the vector does not record it, so the header, IV, ciphertext
    // and tag are byte-equal and the encrypted key must unwrap to the
    // vector's CEK.

    /** @return array<string, mixed> */
    private static function vector(string $file): array
    {
        $json = file_get_contents(__DIR__ . '/fixtures/envelope/' . $file);
        self::assertNotFalse($json);

        return json_decode($json, true, 8, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, string> $private
     * @return array<string, string>
     */
    private static function publicJwk(array $private): array
    {
        return $private['kty'] === 'EC'
            ? ['kty' => 'EC', 'crv' => $private['crv'], 'x' => $private['x'], 'y' => $private['y']]
            : ['kty' => 'RSA', 'n' => $private['n'], 'e' => $private['e']];
    }

    /** SEC1 ECPrivateKey DER for P-256 from the private JWK's d, x and y. */
    private static function ecPrivateKey(array $jwk): \OpenSSLAsymmetricKey
    {
        $der = "\x30\x77\x02\x01\x01\x04\x20" . self::decode($jwk['d'])
            . "\xa0\x0a" . hex2bin('06082a8648ce3d030107')
            . "\xa1\x44\x03\x42\x00\x04" . self::decode($jwk['x']) . self::decode($jwk['y']);
        $key = openssl_pkey_get_private("-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n");
        self::assertNotFalse($key);

        return $key;
    }

    /** @param string[] $chunks served one per call, in order */
    private static function scripted(array $chunks): callable
    {
        return static function (int $n) use (&$chunks): string {
            $next = array_shift($chunks);
            self::assertNotNull($next, 'drew more random bytes than the vector records');
            self::assertSame($n, strlen($next));

            return $next;
        };
    }

    public function testEcdhEsVectorReplaysByteForByte(): void
    {
        $v = self::vector('ecdh-es-a256gcm.json');
        $eph = self::ecPrivateKey($v['ephemeral']);
        $key = self::key(Client::PURPOSE_DECRYPT, 'ECDH-ES', 'jwe', self::publicJwk($v['recipient']));

        $jwe = DeviceEncryption::encryptToDeviceWith(
            $key,
            self::decode($v['plaintext']),
            static fn () => $eph,
            self::scripted([self::decode($v['iv'])]),
        );

        self::assertSame($v['jwe'], $jwe);
    }

    public function testRsaOaep256VectorReplaysExceptTheOaepSeed(): void
    {
        $v = self::vector('rsa-oaep-256-a256gcm.json');
        $r = $v['recipient'];
        $key = self::key(Client::PURPOSE_DECRYPT, 'RSA-OAEP-256', 'jwe', self::publicJwk($r));

        $jwe = DeviceEncryption::encryptToDeviceWith(
            $key,
            self::decode($v['plaintext']),
            static fn () => self::fail('RSA drew an ephemeral key'),
            self::scripted([self::decode($v['cek']), str_repeat("\x00", 32), self::decode($v['iv'])]),
        );

        $expected = explode('.', $v['jwe']);
        $actual = explode('.', $jwe);
        foreach ([0, 2, 3, 4] as $i) {
            self::assertSame($expected[$i], $actual[$i], "segment {$i}");
        }
        $priv = openssl_pkey_new(['rsa' => [
            'n' => self::decode($r['n']), 'e' => self::decode($r['e']), 'd' => self::decode($r['d']),
            'p' => self::decode($r['p']), 'q' => self::decode($r['q']),
            'dmp1' => self::decode($r['dp']), 'dmq1' => self::decode($r['dq']), 'iqmp' => self::decode($r['qi']),
        ]]);
        self::assertNotFalse($priv);
        self::assertSame(self::decode($v['cek']), self::unwrap(self::decode($actual[1]), $priv));
    }

    // ── The device's parser, in software ───────────────────────────────────

    /**
     * A whitelist over the header, fixed sizes, the header as AAD, and the
     * same Concat KDF. Returns null when the envelope does not open. With
     * $strict false the header members are not checked, so an edited header
     * can be tried against the tag.
     */
    private static function open(string $compact, \OpenSSLAsymmetricKey $recipient, bool $strict = true): ?string
    {
        $parts = explode('.', $compact);
        self::assertCount(5, $parts);
        $header = json_decode(self::decode($parts[0]), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('A256GCM', $header['enc']);
        $iv = self::decode($parts[2]);
        $ciphertext = self::decode($parts[3]);
        $tag = self::decode($parts[4]);
        self::assertSame(12, strlen($iv));
        self::assertSame(16, strlen($tag));

        $details = openssl_pkey_get_details($recipient);
        self::assertNotFalse($details);
        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            if ($strict) {
                self::assertSame(['alg', 'enc', 'epk'], array_keys($header));
                self::assertSame(['kty', 'crv', 'x', 'y'], array_keys($header['epk']));
            }
            self::assertSame('ECDH-ES', $header['alg']);
            self::assertSame('', $parts[1]);
            self::assertSame('EC', $header['epk']['kty']);
            self::assertSame('P-256', $header['epk']['crv']);
            $x = self::decode($header['epk']['x']);
            $y = self::decode($header['epk']['y']);
            self::assertSame(32, strlen($x));
            self::assertSame(32, strlen($y));
            $spki = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
            $eph = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n");
            self::assertNotFalse($eph);
            $z = openssl_pkey_derive($eph, $recipient, 32);
            self::assertIsString($z);
            $cek = hash('sha256', pack('N', 1) . $z . pack('N', 7) . 'A256GCM' . pack('N', 0) . pack('N', 0) . pack('N', 256), true);
        } else {
            if ($strict) {
                self::assertSame(['alg', 'enc'], array_keys($header));
            }
            self::assertSame('RSA-OAEP-256', $header['alg']);
            $cek = self::unwrap(self::decode($parts[1]), $recipient);
        }

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $parts[0]);

        return $plaintext === false ? null : $plaintext;
    }

    /** RSAES-OAEP decoding with SHA-256 and MGF1-SHA-256, over a no-padding private decrypt. */
    private static function unwrap(string $encryptedKey, \OpenSSLAsymmetricKey $priv): string
    {
        $em = '';
        self::assertTrue(openssl_private_decrypt($encryptedKey, $em, $priv, OPENSSL_NO_PADDING));
        $k = strlen($em);
        self::assertSame("\x00", $em[0]);
        $maskedSeed = substr($em, 1, 32);
        $maskedDb = substr($em, 33);
        $seed = $maskedSeed ^ self::mgf1($maskedDb, 32);
        $db = $maskedDb ^ self::mgf1($seed, $k - 33);
        self::assertSame(hash('sha256', '', true), substr($db, 0, 32));
        $rest = ltrim(substr($db, 32), "\x00");
        self::assertSame("\x01", $rest[0]);

        return substr($rest, 1);
    }

    private static function mgf1(string $seed, int $length): string
    {
        $out = '';
        for ($i = 0; strlen($out) < $length; $i++) {
            $out .= hash('sha256', $seed . pack('N', $i), true);
        }

        return substr($out, 0, $length);
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function decode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        self::assertNotFalse($decoded);

        return $decoded;
    }
}
