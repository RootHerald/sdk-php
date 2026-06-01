<?php

declare(strict_types=1);

namespace Rootherald;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Rootherald\Exceptions\JwksException;
use Rootherald\Exceptions\TokenExpiredException;
use Rootherald\Exceptions\VerificationException;

/**
 * Verifies Root Herald composite attestation token JWTs.
 *
 * Supports RS256 and ES256 (the algorithms emitted by `JwtTokenService`).
 * `none` is rejected — the allowed-algorithms list passed to `JWT::decode`
 * does not include it.
 */
final class AttestationTokenVerifier
{
    public const EXPECTED_EAT_PROFILE = 'tag:rootherald.io,2026:tpm20-v1';
    public const ALLOWED_ALGORITHMS = ['RS256', 'ES256'];

    public function __construct(
        public readonly string $issuer,
        public readonly JwksFetcher $jwks,
        public readonly ?string $audience = null,
        public readonly int $leewaySeconds = 5,
    ) {
    }

    public function verify(string $token): AttestationClaims
    {
        // Pre-set leeway on the static (firebase/php-jwt API)
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->leewaySeconds;
        try {
            // Decode the header to learn the kid so we know which key to use.
            $header = $this->decodeHeader($token);
            $kid = (string) ($header->kid ?? '');
            if ($kid === '') {
                throw new VerificationException('JWT header missing "kid"');
            }
            $alg = (string) ($header->alg ?? '');
            if (!in_array($alg, self::ALLOWED_ALGORITHMS, true)) {
                throw new VerificationException(
                    "Unsupported JWT alg={$alg}; allowed: " . implode(',', self::ALLOWED_ALGORITHMS),
                );
            }

            try {
                $key = $this->jwks->getKey($kid);
            } catch (JwksException $e) {
                throw new VerificationException('JWKS lookup failed: ' . $e->getMessage(), 0, $e);
            }

            try {
                $decoded = JWT::decode($token, $key);
            } catch (ExpiredException $e) {
                throw new TokenExpiredException($e->getMessage(), 0, $e);
            } catch (BeforeValidException $e) {
                throw new VerificationException('Token not yet valid: ' . $e->getMessage(), 0, $e);
            } catch (SignatureInvalidException $e) {
                throw new VerificationException('Invalid signature: ' . $e->getMessage(), 0, $e);
            } catch (\Throwable $e) {
                throw new VerificationException('JWT validation failed: ' . $e->getMessage(), 0, $e);
            }

            $payload = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), associative: true);
            if (!is_array($payload)) {
                throw new VerificationException('Decoded payload is not an object');
            }

            $this->validateClaims($payload);
            return AttestationClaims::fromPayload($payload);
        } finally {
            JWT::$leeway = $previousLeeway;
        }
    }

    /** @return object{kid?: string, alg?: string, typ?: string} */
    private function decodeHeader(string $token): object
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new VerificationException('Token is not a compact JWT');
        }
        $headerJson = JWT::urlsafeB64Decode($parts[0]);
        $header = json_decode($headerJson);
        if (!is_object($header)) {
            throw new VerificationException('Malformed JWT header');
        }
        return $header;
    }

    /** @param array<string, mixed> $payload */
    private function validateClaims(array $payload): void
    {
        $iss = (string) ($payload['iss'] ?? '');
        if ($iss !== $this->issuer) {
            throw new VerificationException("Issuer mismatch: got {$iss}, expected {$this->issuer}");
        }

        if ($this->audience !== null) {
            $aud = $payload['aud'] ?? null;
            $audMatch = is_string($aud) ? ($aud === $this->audience)
                : (is_array($aud) && in_array($this->audience, $aud, true));
            if (!$audMatch) {
                throw new VerificationException("Audience mismatch (expected {$this->audience})");
            }
        }

        foreach (['acr', 'amr', 'auth_time'] as $required) {
            if (!array_key_exists($required, $payload) || $payload[$required] === null) {
                throw new VerificationException("Missing OIDC claim: {$required}");
            }
        }

        $device = is_array($payload['rootherald_device'] ?? null) ? $payload['rootherald_device'] : [];
        $eatProfile = $device['eat_profile'] ?? $payload['eat_profile'] ?? null;
        if ($eatProfile !== null && $eatProfile !== self::EXPECTED_EAT_PROFILE) {
            throw new VerificationException("Unexpected eat_profile: {$eatProfile}");
        }
        $ueid = $device['ueid'] ?? $payload['ueid'] ?? null;
        if (!is_string($ueid) || $ueid === '') {
            throw new VerificationException('Missing required EAT claim: ueid');
        }
    }
}
