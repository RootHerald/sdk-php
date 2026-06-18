<?php

declare(strict_types=1);

namespace Rootherald;

use Rootherald\Exceptions\HttpException;

/**
 * Top-level Root Herald client: REST API wrapper + token/webhook
 * verification facade.
 *
 * The REST call surface uses PHP's curl extension directly so the SDK has
 * no Guzzle dependency. Inject a custom HTTP transport via
 * {@see $httpTransport} for testing.
 */
final class Client
{
    public readonly JwksFetcher $jwks;
    public readonly AttestationTokenVerifier $tokenVerifier;
    public readonly WebhookVerifier $webhookVerifier;

    /** @var callable(string, string, array<string, string>, ?string): array{status: int, body: string} */
    private $httpTransport;

    /**
     * @param callable|null $httpTransport
     *        callable(method, url, headers, body|null): {status, body}
     */
    public function __construct(
        public readonly string $issuer,
        public readonly ?string $apiKey = null,
        public readonly string $baseUrl = 'https://rootherald.io',
        string $jwksUri = 'https://rootherald.io/.well-known/jwks.json',
        public readonly ?string $audience = null,
        public readonly float $timeoutSeconds = 10.0,
        ?JwksFetcher $jwksFetcher = null,
        ?callable $httpTransport = null,
    ) {
        if ($issuer === '') {
            throw new \InvalidArgumentException('issuer is required');
        }
        $this->jwks = $jwksFetcher ?? new JwksFetcher($jwksUri, timeoutSeconds: $timeoutSeconds);
        $this->tokenVerifier = new AttestationTokenVerifier(
            issuer: $issuer,
            jwks: $this->jwks,
            audience: $audience,
        );
        $this->webhookVerifier = new WebhookVerifier(
            issuer: $issuer,
            jwks: $this->jwks,
        );

        $this->httpTransport = $httpTransport ?? function (
            string $method,
            string $url,
            array $headers,
            ?string $body,
        ): array {
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

    public function verifyToken(string $token): AttestationClaims
    {
        return $this->tokenVerifier->verify($token);
    }

    public function verifySet(string $signedJwt): WebhookEvent
    {
        return $this->webhookVerifier->verifySet($signedJwt);
    }

    /**
     * GET /api/v1/devices/{deviceId}
     *
     * @return array<string, mixed>
     */
    public function getDevice(string $deviceId): array
    {
        return $this->request('GET', "/api/v1/devices/{$deviceId}");
    }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     */
    private function request(string $method, string $path, ?array $body = null): array
    {
        $url = rtrim($this->baseUrl, '/') . $path;
        $headers = ['Accept' => 'application/json'];
        if ($this->apiKey !== null) {
            $headers['Authorization'] = "Bearer {$this->apiKey}";
        }
        $rawBody = null;
        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
            $rawBody = json_encode($body, JSON_THROW_ON_ERROR);
        }

        $resp = ($this->httpTransport)($method, $url, $headers, $rawBody);
        $status = $resp['status'];
        $respBody = $resp['body'];

        if ($status >= 400) {
            throw new HttpException($status, $respBody);
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
}
