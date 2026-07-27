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
 * Server -> server backend-relay client (Client ABI 2.0).
 *
 * The customer's keyless dumb client does only local TPM work and hands opaque
 * blobs to the customer's own backend — it holds no Root Herald key and opens no
 * socket to Root Herald. This client is the only thing that talks to Root Herald,
 * authenticated with the customer's `rh_sk_` secret key. It mirrors the four
 * server-SDK helpers of `@rootherald/node`:
 *
 *   1. {@see relayEnroll}    — relay the client's enroll blob; `POST /api/v1/devices/enroll`
 *   2. {@see relayActivate}  — relay the client's activation blob; `POST /api/v1/devices/activate`
 *   3. {@see issueChallenge} — mint a relay-friendly nonce; `POST /api/v1/attestations/challenge`
 *   4. {@see verify}         — submit the evidence, get the verdict; `POST /api/v1/attestations/verify`
 *
 * The verdict is computed by Root Herald and returned HERE, to the customer's
 * backend — it never travels through the client, which holds no key and gets no
 * verdict.
 *
 * The REST call uses PHP's curl extension directly (no Guzzle dependency).
 * Inject a custom HTTP transport for testing.
 */
final class BackgroundCheck
{
    public const DEFAULT_BASE_URL = 'https://rootherald.io';

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
                'RootHerald secret key must start with rh_sk_'
            );
        }
        $this->baseUrl = rtrim($baseUrl ?? self::DEFAULT_BASE_URL, '/');
        $this->httpTransport = $httpTransport ?? $this->defaultTransport();
    }

    /**
     * POST /api/v1/attestations/challenge — mint a relay-friendly nonce. Relay
     * the nonce to the client; the client quotes over it, then submit the
     * resulting evidence with {@see verify} using the returned challengeId.
     *
     * @param string|null $deviceHint optional advisory hint identifying the device
     */
    public function issueChallenge(?string $deviceHint = null): Challenge
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
     * server-side appraisal and return the verdict.
     *
     * An un-enrolled / failing device is NOT an error — it returns a normal
     * AttestResult carrying Verdict::DENY/WARN. Only protocol/auth/quota
     * problems raise an exception.
     *
     * @param array<string, mixed> $evidence    opaque blob from the client collector; passed through verbatim
     * @param string               $challengeId the single-use id from issueChallenge
     * @param string|null          $policy      tenant policy id/name or a "rootherald:builtin:*" name; unknown names fail closed (422)
     * @param string|null          $requestedDisclosureClass optional disclosure ceiling ("verdict"|"pseudonymous"|"derived"|"full"); omitted when null
     */
    public function verify(
        array $evidence,
        string $challengeId,
        ?string $policy = null,
        ?string $requestedDisclosureClass = null,
    ): AttestResult {
        if ($challengeId === '') {
            throw new ChallengeException(409, '', 'verify() requires a challengeId (from issueChallenge)');
        }
        $body = [
            'challengeId' => $challengeId,
            'evidence' => $evidence,
        ];
        if ($policy !== null) {
            $body['policy'] = $policy;
        }
        if ($requestedDisclosureClass !== null) {
            $body['requestedDisclosureClass'] = $requestedDisclosureClass;
        }

        $data = $this->post('/api/v1/attestations/verify', $body);
        if (!isset($data['verdict']) || !is_array($data['verdict'])) {
            throw new HttpException(200, json_encode($data) ?: '', 'verify response missing verdict');
        }
        $verdictData = $data['verdict'];
        // The pass/fail token lives at verdict.device.verdict on the wire — the
        // device sub-object also carries earStatus/attestationType/quoteVerified
        // etc., surfaced via AttestResult::device().
        $device = is_array($verdictData['device'] ?? null) ? $verdictData['device'] : [];
        $raw = is_string($device['verdict'] ?? null) ? $device['verdict'] : null;

        // Top-level siblings of "verdict", mirroring @rootherald/node.
        $assuranceClaimsMet = [];
        if (is_array($data['assuranceClaimsMet'] ?? null)) {
            foreach ($data['assuranceClaimsMet'] as $claim) {
                if (is_string($claim)) {
                    $assuranceClaimsMet[] = $claim;
                }
            }
        }
        $enrollmentRequired = ($data['enrollmentRequired'] ?? null) === true;

        return new AttestResult(
            Verdict::fromRaw($raw),
            $verdictData,
            $assuranceClaimsMet,
            $enrollmentRequired,
        );
    }

    /**
     * Enroll relay — leg 1. POST /api/v1/devices/enroll.
     *
     * Relays the client's `EnrollBegin()` blob to Root Herald with the `rh_sk_`
     * secret and resolves the enroll endpoint's asymmetric response:
     *
     *   - **201** — a fresh enroll: returns a {@see RelayEnrollResult} with
     *     `alreadyEnrolled === false` and a {@see EnrollChallenge}. Hand the
     *     challenge to the client's `EnrollComplete`, then relay the result to
     *     {@see relayActivate}.
     *   - **409** — the device is already bound: returns a {@see RelayEnrollResult}
     *     with `alreadyEnrolled === true` (no challenge). SKIP the activate leg;
     *     just use `deviceId`.
     *
     * The client never holds the `rh_sk_` key and never talks to Root Herald;
     * this backend helper is the only thing that does.
     *
     * @param array<string, mixed> $enrollRequestBlob opaque `EnrollBegin()` blob from the client
     *        (wire shape: ekPublicKey, akPublicArea, platform, ekCertPem?, ekCertificateChain?)
     *
     * @throws \InvalidArgumentException if the blob lacks ekPublicKey/akPublicArea
     */
    public function relayEnroll(array $enrollRequestBlob): RelayEnrollResult
    {
        if (
            !is_string($enrollRequestBlob['ekPublicKey'] ?? null)
            || !is_string($enrollRequestBlob['akPublicArea'] ?? null)
        ) {
            throw new \InvalidArgumentException(
                'relayEnroll() requires an enroll request blob with ekPublicKey and akPublicArea'
            );
        }

        [$status, $respBody] = $this->rawPost('/api/v1/devices/enroll', $enrollRequestBlob);

        // 409 = already enrolled: the body carries only deviceId. Resolve it and
        // signal "skip activate" instead of treating it as an error.
        if ($status === 409) {
            $body = $this->decodeObject($status, $respBody);
            $deviceId = is_string($body['deviceId'] ?? null) ? $body['deviceId'] : '';
            if ($deviceId === '') {
                throw new HttpException(409, $respBody, 'already-enrolled (409) response missing deviceId');
            }
            return RelayEnrollResult::alreadyEnrolled($deviceId);
        }

        if ($status >= 400) {
            throw $this->mapError($status, $respBody);
        }

        $data = $this->decodeObject($status, $respBody);
        if (
            !is_string($data['deviceId'] ?? null)
            || !is_string($data['credentialBlob'] ?? null)
            || !is_string($data['encryptedSecret'] ?? null)
        ) {
            throw new HttpException(
                $status,
                $respBody,
                'enroll response missing deviceId/credentialBlob/encryptedSecret'
            );
        }

        return RelayEnrollResult::fresh(new EnrollChallenge(
            (string) $data['deviceId'],
            (string) $data['credentialBlob'],
            (string) $data['encryptedSecret'],
        ));
    }

    /**
     * Enroll relay — leg 2. POST /api/v1/devices/activate.
     *
     * Relays the client's `EnrollComplete()` blob (the decrypted credential
     * secret) to Root Herald, completing the EK->AK credential-activation
     * handshake. Call this only when {@see relayEnroll} returned
     * `alreadyEnrolled === false`.
     *
     * @param array<string, mixed> $activationResponse opaque `EnrollComplete()` blob from the client
     *        (wire shape: deviceId, decryptedSecret, akPublicKey?)
     *
     * @throws \InvalidArgumentException if the blob lacks deviceId/decryptedSecret
     */
    public function relayActivate(array $activationResponse): RelayActivateResult
    {
        $deviceId = is_string($activationResponse['deviceId'] ?? null) ? $activationResponse['deviceId'] : '';
        if ($deviceId === '' || !is_string($activationResponse['decryptedSecret'] ?? null)) {
            throw new \InvalidArgumentException(
                'relayActivate() requires an activation response with deviceId and decryptedSecret'
            );
        }

        $data = $this->post('/api/v1/devices/activate', $activationResponse);
        $resolvedId = is_string($data['deviceId'] ?? null) ? $data['deviceId'] : '';
        if ($resolvedId === '') {
            throw new HttpException(200, json_encode($data) ?: '', 'activate response missing deviceId');
        }

        return new RelayActivateResult(
            $resolvedId,
            is_string($data['status'] ?? null) ? $data['status'] : null,
            is_string($data['enrolledAt'] ?? null) ? $data['enrolledAt'] : null,
        );
    }

    /**
     * @deprecated Renamed to {@see issueChallenge} for the Client ABI 2.0 backend
     * contract. Retained as a thin alias for backwards compatibility.
     */
    public function createChallenge(?string $deviceHint = null): Challenge
    {
        return $this->issueChallenge($deviceHint);
    }

    /**
     * @deprecated Renamed to {@see verify} for the Client ABI 2.0 backend
     * contract. Retained as a thin alias for backwards compatibility.
     *
     * @param array<string, mixed> $evidence
     */
    public function attest(
        array $evidence,
        string $challengeId,
        ?string $policy = null,
    ): AttestResult {
        return $this->verify($evidence, $challengeId, $policy);
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    private function post(string $path, array $body): array
    {
        [$status, $respBody] = $this->rawPost($path, $body);
        if ($status >= 400) {
            throw $this->mapError($status, $respBody);
        }
        if ($respBody === '' || $status === 204) {
            return [];
        }
        return $this->decodeObject($status, $respBody);
    }

    /**
     * Issue an authenticated JSON POST and return the raw status + body, leaving
     * status interpretation to the caller (used by {@see relayEnroll}, which must
     * branch on the enroll 409 instead of treating it as an error).
     *
     * @param array<string, mixed> $body
     * @return array{0: int, 1: string} [status, body]
     */
    private function rawPost(string $path, array $body): array
    {
        $url = $this->baseUrl . $path;
        $headers = [
            'Authorization' => "Bearer {$this->secretKey}",
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];
        $rawBody = json_encode($body, JSON_THROW_ON_ERROR);

        $resp = ($this->httpTransport)('POST', $url, $headers, $rawBody);

        return [(int) $resp['status'], (string) $resp['body']];
    }

    /**
     * Decode a JSON response body into an associative array, mapping a parse
     * failure to a typed {@see HttpException}.
     *
     * @return array<string, mixed>
     */
    private function decodeObject(int $status, string $respBody): array
    {
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
