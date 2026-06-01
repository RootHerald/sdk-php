<?php

declare(strict_types=1);

namespace Rootherald;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Rootherald\Exceptions\JwksException;

/**
 * Fetches and caches the JWKS document from the issuer.
 *
 * Uses PHP's bundled curl extension (no Guzzle dependency). Callers can
 * inject a custom HTTP fetcher (a callable that takes a URL and returns the
 * raw body) to integrate with their HTTP client stack or to mock in tests.
 */
final class JwksFetcher
{
    /**
     * @var array<string, Key>|null  kid -> Key
     */
    private ?array $cache = null;
    private float $fetchedAt = 0.0;
    private float $lastRefreshAttempt = 0.0;

    /** @var callable(string): string */
    private $httpFetcher;

    /**
     * @param callable(string): string|null $httpFetcher
     *        A callable accepting a URL and returning the raw response body.
     *        Throw any exception to signal fetch failure. Defaults to a
     *        curl-based fetcher.
     */
    public function __construct(
        public readonly string $jwksUri,
        public readonly float $cacheTtlSeconds = 3600.0,
        public readonly float $cooldownSeconds = 30.0,
        public readonly float $timeoutSeconds = 5.0,
        ?callable $httpFetcher = null,
    ) {
        $this->httpFetcher = $httpFetcher ?? function (string $url): string {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FAILONERROR => false,
                CURLOPT_TIMEOUT => (int) ceil($this->timeoutSeconds),
                CURLOPT_HTTPHEADER => ['Accept: application/json'],
            ]);
            $body = curl_exec($ch);
            $err = curl_error($ch);
            $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            if ($body === false) {
                throw new JwksException("curl error: {$err}");
            }
            if ($code >= 400) {
                throw new JwksException("JWKS fetch returned HTTP {$code}");
            }
            return (string) $body;
        };
    }

    public function getKey(string $kid): Key
    {
        $now = microtime(true);
        $cache = $this->cache;

        $stale = $cache === null || ($now - $this->fetchedAt) > $this->cacheTtlSeconds;
        $missingKid = $cache !== null && !isset($cache[$kid]);
        $inCooldown = ($now - $this->lastRefreshAttempt) < $this->cooldownSeconds;

        if ($stale || ($missingKid && !$inCooldown)) {
            $this->lastRefreshAttempt = $now;
            $this->refresh();
            $cache = $this->cache;
        }

        if ($cache === null || !isset($cache[$kid])) {
            throw new JwksException("No JWKS key found for kid={$kid}");
        }
        return $cache[$kid];
    }

    /**
     * @return array<string, Key>  kid -> Key (defensive copy)
     */
    public function getKeys(): array
    {
        if ($this->cache === null || (microtime(true) - $this->fetchedAt) > $this->cacheTtlSeconds) {
            $this->refresh();
        }
        return $this->cache ?? [];
    }

    private function refresh(): void
    {
        try {
            $body = ($this->httpFetcher)($this->jwksUri);
        } catch (JwksException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new JwksException("Failed to fetch JWKS: {$e->getMessage()}", 0, $e);
        }

        try {
            $doc = json_decode($body, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new JwksException("JWKS body is not JSON: {$e->getMessage()}", 0, $e);
        }
        if (!is_array($doc) || !isset($doc['keys']) || !is_array($doc['keys'])) {
            throw new JwksException("JWKS document missing 'keys' array");
        }

        try {
            $parsed = JWK::parseKeySet($doc, defaultAlg: 'RS256');
        } catch (\Throwable $e) {
            throw new JwksException("Failed to parse JWKS: {$e->getMessage()}", 0, $e);
        }
        if (empty($parsed)) {
            throw new JwksException("JWKS document contained no usable keys");
        }

        $this->cache = $parsed;
        $this->fetchedAt = microtime(true);
    }
}
