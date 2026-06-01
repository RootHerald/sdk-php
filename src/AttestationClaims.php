<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Verified composite attestation token claims.
 *
 * Constructed by {@see AttestationTokenVerifier::verify()}. The raw decoded
 * payload is preserved as {@see $raw} for advanced consumers; the public
 * properties expose the common-case fields with friendlier types.
 */
final class AttestationClaims
{
    /**
     * @param array<string, mixed> $amr
     * @param array<string, mixed> $requestedAcrValues
     * @param array<string, mixed> $device  Verified `rootherald_device` contents.
     * @param array<string, mixed> $raw     Full verified payload.
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $subject,
        public readonly string $audience,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly string $jwtId,
        public readonly string $acr,
        public readonly array $amr,
        public readonly int $authTime,
        public readonly array $requestedAcrValues,
        public readonly string $deviceId,
        public readonly string $attestationType,
        public readonly string $platform,
        public readonly string $tpmClass,
        public readonly string $earStatus,
        public readonly Verdict $verdict,
        public readonly array $device,
        public readonly array $raw,
    ) {
    }

    /**
     * Build an {@see AttestationClaims} from a verified JWT payload array.
     *
     * @param array<string, mixed> $payload
     */
    public static function fromPayload(array $payload): self
    {
        $device = is_array($payload['rootherald_device'] ?? null)
            ? $payload['rootherald_device']
            : [];

        $pick = static function (string $key, mixed $default = null) use ($device, $payload): mixed {
            if (array_key_exists($key, $device)) {
                return $device[$key];
            }
            return $payload[$key] ?? $default;
        };

        $earStatus = (string) $pick('ear_status', 'warning');

        return new self(
            issuer: (string) ($payload['iss'] ?? ''),
            subject: (string) ($payload['sub'] ?? ''),
            audience: (string) ($payload['aud'] ?? ''),
            issuedAt: (int) ($payload['iat'] ?? 0),
            expiresAt: (int) ($payload['exp'] ?? 0),
            jwtId: (string) ($payload['jti'] ?? ''),
            acr: (string) ($payload['acr'] ?? ''),
            amr: array_values((array) ($payload['amr'] ?? [])),
            authTime: (int) ($payload['auth_time'] ?? 0),
            requestedAcrValues: array_values((array) ($payload['requested_acr_values'] ?? [])),
            deviceId: (string) $pick('ueid', ''),
            attestationType: (string) $pick('attestation_type', 'unknown'),
            platform: (string) $pick('platform', ''),
            tpmClass: (string) $pick('tpm_class', ''),
            earStatus: $earStatus,
            verdict: Verdict::fromEarStatus($earStatus),
            device: $device,
            raw: $payload,
        );
    }
}
