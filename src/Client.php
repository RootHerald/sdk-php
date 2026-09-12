<?php

declare(strict_types=1);

namespace Rootherald;

use Rootherald\Exceptions\AdmissionRefusedException;
use Rootherald\Exceptions\ChallengeException;
use Rootherald\Exceptions\HttpException;
use Rootherald\Exceptions\InvalidEvidenceException;
use Rootherald\Exceptions\InvalidSecretKeyException;
use Rootherald\Exceptions\QuotaExceededException;
use Rootherald\Exceptions\UnknownPolicyException;

/**
 * Server -> server backend-relay client (client ABI 7.0).
 *
 * The customer's keyless dumb client does only local TPM work and hands opaque
 * blobs to the customer's own backend — it holds no Root Herald key and opens no
 * socket to Root Herald. This client is the only thing that talks to Root Herald,
 * authenticated with the customer's `rh_sk_` secret key. Nothing it sends
 * locates a row: the server resolves the tenant from the key, the challenge
 * from the nonce the proof was made over, the enrollment from the id it
 * minted, and the device from the proof itself. It mirrors the four
 * server-SDK helpers of `@rootherald/node`:
 *
 *   1. {@see relayEnroll}    — relay the client's enroll blob; `POST /api/v1/attest/enroll`
 *   2. {@see relayActivate}  — relay the client's activation blob; `POST /api/v1/attest/activate`
 *   3. {@see issueChallenge} — mint a challenge carrying the ask; `POST /api/v1/attest/challenge`
 *   4. {@see verify}         — submit the evidence, get the verdict; `POST /api/v1/attest/verify`
 *
 * The verdict is computed by Root Herald and returned HERE, to the customer's
 * backend — it never travels through the client, which holds no key and gets no
 * verdict.
 *
 * The REST call uses PHP's curl extension directly (no Guzzle dependency).
 * Inject a custom HTTP transport for testing.
 */
final class Client
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
     * @throws \InvalidArgumentException if the key is empty, is not an rh_sk_ key,
     *         or the base URL is not https (loopback excepted)
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
        $this->baseUrl = self::requireSecureBaseUrl($baseUrl ?? self::DEFAULT_BASE_URL);
        $this->httpTransport = $httpTransport ?? $this->defaultTransport();
    }

    /**
     * Reject a base URL that would put the rh_sk_ secret on the wire in the clear.
     *
     * The secret rides in an Authorization header on every request and is
     * full-privilege, so an http:// or scheme-less base URL hands it to anyone on
     * the path. A typo is enough, and nothing downstream notices, because the
     * request itself still succeeds.
     *
     * Loopback is excepted so the local docker stack keeps working over http.
     *
     * @throws \InvalidArgumentException when the URL is not absolute https or loopback
     */
    private static function requireSecureBaseUrl(string $baseUrl): string
    {
        $trimmed = rtrim($baseUrl, '/');
        $parts = parse_url($trimmed);

        if ($parts === false || !isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            throw new \InvalidArgumentException(
                sprintf('baseUrl must be an absolute https URL (got %s)', var_export($trimmed, true))
            );
        }
        if ($parts['scheme'] === 'https') {
            return $trimmed;
        }
        if (self::isLoopbackHost($parts['host'])) {
            return $trimmed;
        }

        throw new \InvalidArgumentException(
            sprintf('baseUrl must use https (got %s)', var_export($trimmed, true))
        );
    }

    private static function isLoopbackHost(string $host): bool
    {
        $stripped = trim($host, '[]');
        if ($stripped === 'localhost') {
            return true;
        }
        if (filter_var($stripped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return str_starts_with($stripped, '127.');
        }
        if (filter_var($stripped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return inet_pton($stripped) === inet_pton('::1');
        }

        return false;
    }

    /** Ask: prove which enrolled device this is. */
    public const ASK_IDENTITY = 'identity';
    /** Ask: prove the boot / configuration state (quote + event log). */
    public const ASK_POSTURE = 'posture';
    /** Ask: certify a fresh TPM-resident signing key under the AK. */
    public const ASK_KEY = 'key';
    /** The only key purpose today. */
    public const KEY_PURPOSE_SIGN = 'sign';

    /**
     * POST /api/v1/attest/challenge — mint a challenge that carries the ask.
     * Relay {@see Challenge::$challenge} to the client verbatim; it quotes
     * over it, then submit the resulting evidence with {@see verify} using the
     * returned {@see Challenge::$nonce}.
     *
     * What the device must prove is fixed here, not at verify time. Policies
     * bind to the API key: the server resolves the policy from the key that
     * mints the challenge and pins it on the challenge, so nothing between
     * the two calls can change it. A `policy` field in a hand-built body is
     * refused with 400 policy_bound_to_key; bind one from the dashboard or
     * `PUT /api/v1/admin/api-keys/{id}/policies`.
     *
     * @param string|null       $deviceHint optional advisory hint identifying the device
     * @param list<string>|null $ask        any of ASK_IDENTITY / ASK_POSTURE / ASK_KEY;
     *        null or empty means the server default, identity + posture
     * @param string|null       $keyPurpose purpose of the certified key when asking for ASK_KEY
     *        (KEY_PURPOSE_SIGN)
     */
    public function issueChallenge(
        ?string $deviceHint = null,
        ?array $ask = null,
        ?string $keyPurpose = null,
    ): Challenge {
        $body = [];
        if ($deviceHint !== null) {
            $body['deviceHint'] = $deviceHint;
        }
        if ($ask !== null && $ask !== []) {
            $body['ask'] = array_values($ask);
        }
        if ($keyPurpose !== null) {
            $body['keyPurpose'] = $keyPurpose;
        }
        $data = $this->post('/api/v1/attest/challenge', $body);
        if (
            !is_string($data['nonce'] ?? null)
            || !is_string($data['challenge'] ?? null)
            || !is_string($data['expiresAt'] ?? null)
        ) {
            throw new HttpException(200, json_encode($data) ?: '', 'challenge response missing nonce/challenge/expiresAt');
        }
        return new Challenge($data['nonce'], $data['challenge'], $data['expiresAt']);
    }

    /**
     * POST /api/v1/attest/verify — submit the opaque evidence blob for
     * server-side appraisal and return the verdict.
     *
     * An un-enrolled / failing device is NOT an error — it returns a normal
     * AttestResult carrying Verdict::DENY/WARN. Only protocol/auth/quota
     * problems raise an exception.
     *
     * The appraisal runs under the policy pinned on the challenge at mint,
     * resolved from the API key; a `policy` field in a hand-built body is
     * refused with 400 policy_bound_to_key. A bound policy that no longer
     * exists raises {@see UnknownPolicyException} (422 unknown_policy);
     * nothing is substituted.
     *
     * @param array<string, mixed> $evidence opaque blob from the client collector; passed through verbatim
     * @param string               $nonce    the challenge handle from issueChallenge; the server finds the
     *        single-use challenge by it and checks the proof was made over it
     * @param string|null          $requestedDisclosureClass optional disclosure ceiling ("verdict"|"pseudonymous"|"derived"|"full"); omitted when null
     */
    public function verify(
        array $evidence,
        string $nonce,
        ?string $requestedDisclosureClass = null,
    ): AttestResult {
        if ($nonce === '') {
            throw new ChallengeException(409, '', 'verify() requires a nonce (from issueChallenge)');
        }
        $body = [
            'nonce' => $nonce,
            'evidence' => $evidence,
        ];
        if ($requestedDisclosureClass !== null) {
            $body['requestedDisclosureClass'] = $requestedDisclosureClass;
        }

        $data = $this->post('/api/v1/attest/verify', $body);
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

        // `key` is a top-level sibling too, present only on a passing verdict
        // for a challenge that asked for a key.
        $key = null;
        if (($data['key'] ?? null) !== null) {
            $key = CertifiedKey::fromWire($data['key']);
            if ($key === null) {
                throw new HttpException(200, json_encode($data) ?: '', 'verify response key missing keyId/jwk/certifiedAt');
            }
        }

        return new AttestResult(
            Verdict::fromRaw($raw),
            $verdictData,
            $assuranceClaimsMet,
            $enrollmentRequired,
            $key,
        );
    }

    /**
     * Enroll relay — leg 1. POST /api/v1/attest/enroll.
     *
     * Relays the client's `EnrollBegin()` blob to Root Herald with the `rh_sk_`
     * secret and returns the {@see EnrollChallenge} to hand back to the client's
     * `EnrollComplete`, whose result goes to {@see relayActivate}. An iOS blob
     * (`platform: "ios"`) has no activation leg: the server answers `{}` and
     * {@see RelayEnrollResult::$challenge} is null.
     *
     * Nothing in the response names the device. The backend learns its alias
     * for the device from {@see relayActivate}, or from the first verdict on
     * iOS, and never relays it to the device.
     *
     * The client never holds the `rh_sk_` key and never talks to Root Herald;
     * this backend helper is the only thing that does.
     *
     * Admission runs under the identity policy bound to the API key; a device
     * that could never satisfy it is refused before it gets an AK
     * ({@see AdmissionRefusedException}, 422 admission_refused).
     *
     * @param array<string, mixed> $enrollRequestBlob opaque `EnrollBegin()` blob from the client, passed through verbatim
     *        (wire shape: ekPublicKey, akPublicArea, platform, ekCertPem?, ekCertificateChain?, tpmSelfReport?;
     *        on iOS: platform, iosKeyId, iosAttestationObject, nonce)
     *
     * @throws \InvalidArgumentException if the blob lacks the fields its platform requires
     */
    public function relayEnroll(array $enrollRequestBlob): RelayEnrollResult
    {
        $ios = ($enrollRequestBlob['platform'] ?? null) === 'ios';
        $required = $ios ? ['iosKeyId', 'iosAttestationObject', 'nonce'] : ['ekPublicKey', 'akPublicArea'];
        foreach ($required as $field) {
            if (!is_string($enrollRequestBlob[$field] ?? null)) {
                throw new \InvalidArgumentException(
                    'relayEnroll() requires an enroll request blob with ' . implode(', ', $required)
                );
            }
        }

        [$status, $respBody] = $this->rawPost('/api/v1/attest/enroll', $enrollRequestBlob);
        if ($status >= 400) {
            throw $this->mapError($status, $respBody);
        }

        $data = $this->decodeObject($status, $respBody);
        if ($ios && $data === []) {
            return new RelayEnrollResult(null);
        }
        $challenge = EnrollChallenge::fromWire($data);
        if ($challenge === null) {
            throw new HttpException(
                $status,
                $respBody,
                'enroll response missing enrollmentId with credentialBlob/encryptedSecret or challengeNonce'
            );
        }

        return new RelayEnrollResult($challenge);
    }

    /**
     * Enroll relay — leg 2. POST /api/v1/attest/activate.
     *
     * Relays the client's `EnrollComplete()` blob to Root Herald: the decrypted
     * credential secret (TPM) or the signature over the challenge nonce
     * (macOS), answering the enrollment {@see relayEnroll} opened. The server
     * refuses an unknown, spent or foreign enrollmentId and a wrong proof
     * alike, with one 401 answer.
     *
     * {@see RelayActivateResult::$deviceId} is this tenant's alias for the
     * device, for the backend to map to its user/account. It must not be
     * relayed to the device.
     *
     * @param array<string, mixed> $activationResponse opaque `EnrollComplete()` blob from the client, passed through verbatim
     *        (wire shape: enrollmentId, decryptedSecret | signature)
     *
     * @throws \InvalidArgumentException if the blob lacks enrollmentId, or carries neither decryptedSecret nor signature
     */
    public function relayActivate(array $activationResponse): RelayActivateResult
    {
        $enrollmentId = $activationResponse['enrollmentId'] ?? null;
        $proof = is_string($activationResponse['decryptedSecret'] ?? null)
            || is_string($activationResponse['signature'] ?? null);
        if (!is_string($enrollmentId) || $enrollmentId === '' || !$proof) {
            throw new \InvalidArgumentException(
                'relayActivate() requires an activation response with enrollmentId and decryptedSecret or signature'
            );
        }

        $data = $this->post('/api/v1/attest/activate', $activationResponse);
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
     * status interpretation to the caller. $path may carry a query string.
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

    /**
     * Map a non-2xx status to the matching typed exception, mirroring
     * @rootherald/node. A 422 is split on the server's "error" code:
     * admission_refused gets its own class; anything else is the
     * policy-resolution failure.
     */
    private function mapError(int $status, string $body): HttpException
    {
        $message = null;
        $code = null;
        $parsed = json_decode($body, true);
        if (is_array($parsed)) {
            foreach (['message', 'detail', 'error_description'] as $field) {
                if (is_string($parsed[$field] ?? null)) {
                    $message = $parsed[$field];
                    break;
                }
            }
            $code = (is_string($parsed['error'] ?? null) ? $parsed['error'] : null)
                ?? (is_string($parsed['code'] ?? null) ? $parsed['code'] : null);
        }
        return match (true) {
            $status === 401 => new InvalidSecretKeyException($status, $body, $message, $code),
            $status === 422 && $code === 'admission_refused' => new AdmissionRefusedException($status, $body, $message, $code),
            $status === 422 => new UnknownPolicyException($status, $body, $message, $code),
            $status === 409 => new ChallengeException($status, $body, $message, $code),
            $status === 400 => new InvalidEvidenceException($status, $body, $message, $code),
            $status === 429 => new QuotaExceededException($status, $body, $message, $code),
            default => new HttpException($status, $body, $message, $code),
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
