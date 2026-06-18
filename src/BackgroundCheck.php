<?php

declare(strict_types=1);

namespace Rootherald;

use Rootherald\Exceptions\ChallengeException;
use Rootherald\Exceptions\HttpException;
use Rootherald\Exceptions\InvalidEvidenceException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\Exceptions\QuotaExceededException;
use Rootherald\Exceptions\UnknownPolicyException;

/**
 * Server -> server Background-Check client.
 *
 * The customer's dumb client collects an opaque evidence blob (no keys, no
 * Root Herald contact) and hands it to the customer's own server. The server
 * uses this client, authenticated with its `rh_sk_` secret key, to:
 *   1. mint a relay-friendly nonce  ({@see createChallenge})
 *   2. submit the evidence for appraisal and get a verdict  ({@see attest})
 *
 * This is ADDITIVE. The offline/badge-tier path ({@see Client::verifyToken} /
 * {@see AttestationTokenVerifier}) is unchanged; the optional `token` returned
 * by {@see attest} with `returnToken: true` is itself verifiable with it.
 *
 * The REST call uses PHP's curl extension directly (no Guzzle dependency).
 * Inject a custom HTTP transport for testing.
 */
final class BackgroundCheck
{
    public const DEFAULT_BASE_URL = 'https://api.rootherald.io';

    private const SECRET_KEY_PREFIX = 'rh_sk_';

    private readonly string $baseUrl;

    /** @var callable(string, string, array<string, string>, ?string): array{status: int, body: string} */
    private $httpTransport;

    /**
     * @param string        $secretKey     your Root Herald secret key (rh_sk_…); required
     * @param string|null   $baseUrl       API base URL; defaults to production
     * @param float         $timeoutSeconds
     * @param callable|null $httpTransport callable(method, url, headers, body|null): {status, body}
     *
     * @throws \InvalidArgumentException if the key is empty or not an rh_sk_ key
     */
    public function __construct(
        private readonly string $secretKey,
        ?string $baseUrl = null,
        public readonly float $timeoutSeconds = 10.0,
        ?callable $httpTransport = null,
    ) {
        if ($secretKey === '') {
            throw new \InvalidArgumentException('a secret key (rh_sk_…) is required');
        }
        if (!str_starts_with($secretKey, self::SECRET_KEY_PREFIX)) {
            throw new \InvalidArgumentException(
                'secretKey must be a secret key (rh_sk_…); a publishable key (rh_pk_…) must never be used server-side'
            );
        }
        $this->baseUrl = rtrim($baseUrl ?? self::DEFAULT_BASE_URL, '/');
        $this->httpTransport = $httpTransport ?? $this->defaultTransport();
    }

    /**
     * POST /api/v1/attestations/challenge — mint a relay-friendly nonce. Relay
     * the nonce to the client; the client quotes over it, then submit the
     * resulting evidence with {@see attest} using the returned challengeId.
     *
     * @param string|null $deviceHint optional advisory hint identifying the device
     */
    public function createChallenge(?string $deviceHint = null): Challenge
    {
        $body = [];
        if ($deviceHint !== null) {
            $body['deviceHint'] = $deviceHint;
        }
        $data = $this->post('/api/v1/attestations/challenge', $body);
        if (!isset($data['challengeId'], $data['nonce'], $data['expiresAt'])) {
            throw new HttpException(200, json_encode($data) ?: '', 'challenge response missing challengeId/nonce/expiresAt');
        }
        return new Challenge(
            (string) $data['challengeId'],
            (string) $data['nonce'],
            (string) $data['expiresAt'],
        );
    }

    /**
     * POST /api/v1/attestations/verify — submit the opaque evidence blob for
     * server-side appraisal and return the verdict (plus an optional signed EAT
     * when $returnToken is true).
     *
     * An un-enrolled / failing device is NOT an error — it returns a normal
     * AttestResult carrying Verdict::DENY/WARN. Only protocol/auth/quota
     * problems raise an exception.
     *
     * @param array<string, mixed> $evidence    opaque blob from the client collector; passed through verbatim
     * @param string               $challengeId the single-use id from createChallenge
     * @param string|null          $policy      tenant policy id/name or a "rootherald:builtin:*" name; unknown names fail closed (422)
     * @param bool                 $returnToken opt-in signed EAT (JWT) output
     */
    public function attest(
        array $evidence,
        string $challengeId,
        ?string $policy = null,
        bool $returnToken = false,
    ): AttestResult {
        if ($challengeId === '') {
            throw new ChallengeException(409, '', 'attest() requires a challengeId (from createChallenge)');
        }
        $body = [
            'challengeId' => $challengeId,
            'evidence' => $evidence,
        ];
        if ($policy !== null) {
            $body['policy'] = $policy;
        }
        if ($returnToken) {
            $body['returnToken'] = true;
        }

        $data = $this->post('/api/v1/attestations/verify', $body);
        if (!isset($data['verdict']) || !is_array($data['verdict'])) {
            throw new HttpException(200, json_encode($data) ?: '', 'verify response missing verdict');
        }
        $verdictData = $data['verdict'];
        $raw = is_string($verdictData['verdict'] ?? null) ? $verdictData['verdict'] : null;
        $token = isset($data['token']) && is_string($data['token']) ? $data['token'] : null;

        return new AttestResult(Verdict::fromRaw($raw), $verdictData, $token);
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    private function post(string $path, array $body): array
    {
        $url = $this->baseUrl . $path;
        $headers = [
            'Authorization' => "Bearer {$this->secretKey}",
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];
        $rawBody = json_encode($body, JSON_THROW_ON_ERROR);

        $resp = ($this->httpTransport)('POST', $url, $headers, $rawBody);
        $status = $resp['status'];
        $respBody = $resp['body'];

        if ($status >= 400) {
            throw $this->mapError($status, $respBody);
        }
        if ($respBody === '' || $status === 204) {
            return [];
        }
        try {
            $decoded = json_decode($respBody, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new HttpException($status, $respBody, "non-JSON response: {$e->getMessage()}");
        }
        return is_array($decoded) ? $decoded : ['value' => $decoded];
    }

    /** Map a non-2xx status to the matching typed exception, mirroring @rootherald/node. */
    private function mapError(int $status, string $body): HttpException
    {
        $message = null;
        $parsed = json_decode($body, true);
        if (is_array($parsed)) {
            $message = (is_string($parsed['message'] ?? null) ? $parsed['message'] : null)
                ?? (is_string($parsed['error_description'] ?? null) ? $parsed['error_description'] : null);
        }
        return match ($status) {
            401 => new InvalidSecretKeyException($status, $body, $message),
            422 => new UnknownPolicyException($status, $body, $message),
            409 => new ChallengeException($status, $body, $message),
            400 => new InvalidEvidenceException($status, $body, $message),
            429 => new QuotaExceededException($status, $body, $message),
            default => new HttpException($status, $body, $message),
        };
    }

    /** @return callable(string, string, array<string, string>, ?string): array{status: int, body: string} */
    private function defaultTransport(): callable
    {
        return function (string $method, string $url, array $headers, ?string $body): array {
            $ch = curl_init($url);
            $headerLines = [];
            foreach ($headers as $k => $v) {
                $headerLines[] = "{$k}: {$v}";
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headerLines,
                CURLOPT_TIMEOUT => (int) ceil($this->timeoutSeconds),
            ]);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
            $respBody = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if ($respBody === false) {
                throw new HttpException(0, '', "curl error: {$err}");
            }
            return ['status' => (int) $status, 'body' => (string) $respBody];
        };
    }
}
