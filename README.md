# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+.

**Backend relay (server → server, client ABI 7.0)** via `Client`: your
keyless dumb client does only local TPM work and hands opaque blobs to *your*
server, which relays them to Root Herald using your `rh_sk_` secret key. The
client never holds a key or talks to Root Herald, and never gets a verdict.
Nothing your server sends locates a row: Root Herald resolves the tenant from
the key, the challenge from the nonce the proof was made over, the enrollment
from the id it minted, and the device from the proof itself. Four helpers
mirror `@rootherald/node`: `relayEnroll`, `relayActivate`, `issueChallenge`,
`verify`.

```bash
composer require rootherald/rootherald
```

## Backend relay (server → server)

```php
use Rootherald\Client;
use Rootherald\Verdict;

// Construct with your SECRET key (rh_sk_…). Any key without the rh_sk_ prefix
// is rejected.
$rh = new Client(secretKey: getenv('ROOTHERALD_SECRET_KEY'));

// 1) Mint a challenge; relay $challenge->challenge to the client verbatim and
//    keep $challenge->nonce, your handle for it. The challenge carries the
//    ask: what the device must prove is fixed here.
$challenge = $rh->issueChallenge(
    ask: [Client::ASK_IDENTITY, Client::ASK_POSTURE], // the default when omitted
);

// 2) The client quotes over the challenge and returns an opaque $evidence
//    array; relay it for appraisal with the nonce the proof was made over.
$result = $rh->verify(
    evidence: $evidence,
    nonce: $challenge->nonce,
);

if ($result->verdict === Verdict::PASS) {
    // proceed
}
```

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; a posture ask runs under the posture
policy and everything else under the identity policy. The resolved policy is
pinned on the challenge when it is minted. Change what a key enforces from the
dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a
hand-built request body is refused with `400 policy_bound_to_key`.

`$result->verdict` is the server's own token, `Verdict::PASS` / `Verdict::WARN`
/ `Verdict::FAIL` (`"pass"` / `"warn"` / `"fail"`, the same vocabulary in every
Root Herald SDK). A response carrying any other token is refused with
`HttpException`, never a guessed verdict.

### Errors

An un-enrolled / failing device is a verdict (`Verdict::FAIL`/`WARN`), **not**
an exception. Only protocol, auth and quota problems throw, each exposing
`$status` and the server's `$serverError`:

| Status | Server `error` code                                 | Exception                    |
| ------ | --------------------------------------------------- | ---------------------------- |
| 401    | `activation_refused`                                | `ActivationRefusedException` |
| 401    | anything else                                       | `InvalidSecretKeyException`  |
| 400    |                                                     | `InvalidEvidenceException`   |
| 409    |                                                     | `ChallengeException`         |
| 422    | `unknown_policy`, or none                           | `UnknownPolicyException`     |
| 422    | `admission_refused`                                 | `AdmissionRefusedException`  |
| 429    | `quota_exceeded`, or an `X-RootHerald-Quota` header | `QuotaExceededException`     |
| 429    | anything else                                       | `RateLimitedException`       |

`ActivationRefusedException` is `relayActivate` being refused for an unknown,
spent or foreign `enrollmentId` or a wrong proof; the secret key was accepted.
`RateLimitedException::$retryAfterSeconds` is the server's `Retry-After` (else
the body's `retryAfterSeconds`, else null); `QuotaExceededException` is the
metered billing ceiling. Any other status, and a 422 or 402 carrying a code no
class covers (`posture_not_bound`, `plan_lapsed`), is a plain `HttpException`
with `$serverError` preserved. Input the SDK refuses locally, such as an empty
nonce, is `\InvalidArgumentException` and makes no request.

Every request times out after 30 s (`Client::DEFAULT_TIMEOUT_SECONDS`, the
`timeoutSeconds` constructor argument). The default is the same in every Root
Herald server SDK. A custom `httpTransport` may return a `headers` array
(response header names lowercased) so the 429 split can read `Retry-After` and
`X-RootHerald-Quota`; the built-in curl transport does.

### Certified device key

Ask for `key` and a passing verdict also certifies a fresh TPM-resident P-256
signing key. Store the `CertifiedKey` against the user; later signatures from
the device verify locally, with no Root Herald call.

```php
use Rootherald\KeySignatures;

$challenge = $rh->issueChallenge(
    ask: [Client::ASK_IDENTITY, Client::ASK_KEY],
    keyPurpose: Client::KEY_PURPOSE_SIGN,
);

$result = $rh->verify(evidence: $evidence, nonce: $challenge->nonce);
$key = $result->key();               // present only on a pass with a key ask
store($userId, $key->keyId, $key->jwk);

// Later: the device signed $message with that key (raw r||s or DER).
$ok = KeySignatures::verify($key->jwk, $message, $signature);
```

### Enroll relay (one-time device bootstrap)

The client's keyless enroll handshake is relayed in two legs. Every enrollment
returns an activation challenge, a device already known included —
re-enrollment is how a device rotates its attestation key. The challenge
names the enrollment, never the device: no identifier Root Herald assigns is
relayed to the client.

```php
// Leg 1 — relay the client's EnrollBegin() blob. Admission runs under the
// key's identity policy; a device that could never satisfy it is refused
// with AdmissionRefusedException (422 admission_refused).
$enroll = $rh->relayEnroll($enrollRequestBlob);

// Hand $enroll->challenge to the client's EnrollComplete(), then…
$client->sendToClient($enroll->challenge->toArray()); // enrollmentId + credentialBlob/encryptedSecret (TPM) or challengeNonce (macOS)

// Leg 2 — relay the client's EnrollComplete() blob.
$activated = $rh->relayActivate($activationResponse); // enrollmentId + decryptedSecret (TPM) or signature (macOS)
// $activated->deviceId is your tenant's alias for the device: map it to your
// user/account, and never send it to the client.
```

An iOS enrollment has one leg: `relayEnroll` returns a null `challenge`, and
your backend learns the device's alias from its first verdict
(`$result->device()['ueid']`).

The verdict is computed by Root Herald and returned to your backend; it never
travels through the client.

## Samples

- [`samples/laravel-demo`](samples/laravel-demo): Laravel `POST /challenge`, `POST /attest` and `POST /verify-signature` routes
