<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use Firebase\JWT\JWT;
use Rootherald\JwksFetcher;

/**
 * Shared test fixtures: an RSA keypair, a JWKS document, and helpers for
 * minting composite EAT and SET JWTs.
 */
final class Fixtures
{
    public const ISSUER = 'https://rootherald.io/testorg';
    public const AUDIENCE = 'client-abc';
    public const JWKS_URI = 'https://rootherald.io/.well-known/jwks.json';
    public const KID = 'test-key-1';

    private static ?array $cache = null;

    /**
     * @return array{private: string, public: string, jwks: array<string, mixed>}
     */
    public static function keys(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }
        $res = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($res === false) {
            throw new \RuntimeException('Failed to generate RSA key');
        }
        openssl_pkey_export($res, $private);
        $details = openssl_pkey_get_details($res);
        $public = $details['key'];

        // Construct a JWK from the RSA public key components.
        $n = self::base64url($details['rsa']['n']);
        $e = self::base64url($details['rsa']['e']);
        $jwks = [
            'keys' => [[
                'kty' => 'RSA',
                'kid' => self::KID,
                'use' => 'sig',
                'alg' => 'RS256',
                'n' => $n,
                'e' => $e,
            ]],
        ];

        self::$cache = ['private' => $private, 'public' => $public, 'jwks' => $jwks];
        return self::$cache;
    }

    public static function jwksFetcher(): JwksFetcher
    {
        $jwks = self::keys()['jwks'];
        return new JwksFetcher(
            jwksUri: self::JWKS_URI,
            httpFetcher: static fn (string $url): string => json_encode($jwks, JSON_THROW_ON_ERROR),
        );
    }

    /**
     * @param array<string, mixed> $deviceOverrides
     * @param array<string, mixed> $topOverrides
     */
    public static function makeToken(
        ?string $issuer = null,
        ?string $audience = null,
        string $subject = 'user-uuid',
        int $expIn = 300,
        ?int $iat = null,
        string $acr = 'urn:rootherald:user:phr',
        string $eatProfile = 'tag:rootherald.io,2026:tpm20-v1',
        string $ueid = 'device-uuid-1234',
        string $earStatus = 'affirming',
        array $deviceOverrides = [],
        array $topOverrides = [],
        string $algorithm = 'RS256',
        string $kid = self::KID,
    ): string {
        $now = $iat ?? time();
        $device = array_merge([
            'eat_profile' => $eatProfile,
            'ueid' => $ueid,
            'ear_status' => $earStatus,
            'verdict' => 'pass',
            'attestation_type' => 'tpm20',
            'attested_at' => $now - 10,
            'quote_verified' => true,
            'secure_boot_verified' => true,
            'platform' => 'windows',
            'hardware_model' => 'TPM 2.0',
            'tpm_class' => 'hardware-discrete-infineon',
        ], $deviceOverrides);

        $payload = array_merge([
            'iss' => $issuer ?? self::ISSUER,
            'sub' => $subject,
            'aud' => $audience ?? self::AUDIENCE,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $expIn,
            'jti' => "jti-{$now}",
            'acr' => $acr,
            'amr' => ['pwd', 'hwk', 'user', 'mfa'],
            'auth_time' => $now - 30,
            'requested_acr_values' => [$acr],
            'rootherald_device' => $device,
        ], $topOverrides);

        return JWT::encode($payload, self::keys()['private'], $algorithm, $kid);
    }

    /**
     * @param array<string, array<string, mixed>>|null $events
     */
    public static function makeSet(
        ?string $issuer = null,
        ?string $audience = null,
        string $subId = 'device-uuid-1234',
        ?array $events = null,
        ?int $iat = null,
        ?string $jti = null,
        string $typ = 'secevent+jwt',
        string $algorithm = 'RS256',
        string $kid = self::KID,
    ): string {
        $now = $iat ?? time();
        $body = [
            'iss' => $issuer ?? self::ISSUER,
            'iat' => $now,
            'jti' => $jti ?? "set-{$now}",
            'sub_id' => ['format' => 'opaque', 'id' => $subId],
            'events' => $events ?? [
                'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change' => [
                    'current_status' => 'compliant',
                    'previous_status' => 'non-compliant',
                ],
            ],
        ];
        if ($audience !== null) {
            $body['aud'] = $audience;
        }
        $head = ['typ' => $typ];
        return JWT::encode($body, self::keys()['private'], $algorithm, $kid, $head);
    }

    private static function base64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
