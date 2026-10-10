# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+.

Wire 8.0. A 7.0 client cannot enroll against an 8.0 server; see the
[CHANGELOG](./CHANGELOG.md) for the migration.

**Backend relay (server → server, client ABI 8.0)** via `Client`: your
keyless client does only local TPM work and hands opaque blobs to *your*
server, which relays them to Root Herald using your `rh_sk_` secret key. The
client never holds a key or talks to Root Herald, and never gets a verdict.
Nothing your server sends locates a row: Root Herald resolves the tenant from
the key, the challenge from the nonce the proof was made over, the enrollment
from the id it minted, and the installation from the proof itself.

**Three ceremonies, two calls each**, mirroring `@rootherald/node`:

- `relayEnroll($enrollRequestBlob)` / `relayActivate($activationResponse)`:
  enroll an installation (`POST /api/v1/attest/enroll`, `/activate`).
- `issueKeyChallenge($purpose, expectedDevices: ...)` /
  `certifyKey($certification, $nonce)`: mint a device-bound key
  (`POST /api/v1/keys/challenge`, `/certify`).
- `issueChallenge(ask: ..., expectedKey: ..., expectedDevices: ...)` /
  `verify($evidence, $nonce, ...)`: attest
  (`POST /api/v1/attest/challenge`, `/verify`).
- `KeySignatures::verify($jwk, $message, $signature)`: check a signature from
  a certified key locally, with ext-openssl only.

```bash
composer require rootherald/rootherald
```

## Enroll an installation

Each installation of your client enrolls once. The client's `EnrollBegin`
creates an attestation key (AK) inside the TPM and returns an opaque AK blob
alongside the enroll body; the client keeps the blob and passes it to every
later attest and mint. Windows needs one elevation per enrollment.

```php
use Rootherald\Client;

// Construct with your SECRET key (rh_sk_…). Any key without the rh_sk_ prefix
// is rejected.
$rh = new Client(secretKey: getenv('ROOTHERALD_SECRET_KEY'));

// Leg 1 — relay the client's EnrollBegin() blob verbatim. Admission runs
// under the key's identity policy; a device that could never satisfy it is
// refused with AdmissionRefusedException (422 admission_refused).
$enroll = $rh->relayEnroll($enrollRequestBlob);

// Hand $enroll->challenge to the client's EnrollComplete(), then…
$client->sendToClient($enroll->challenge->toArray()); // enrollmentId + credentialBlob/encryptedSecret (TPM) or challengeNonce (macOS)

// Leg 2 — relay the client's EnrollComplete() blob.
$activated = $rh->relayActivate($activationResponse); // enrollmentId + decryptedSecret (TPM) or signature (macOS)
// $activated->deviceId is your tenant's alias for the device: map it to your
// user/account, and never send it to the client.
```

The alias is the device's only identity: a new AK, a new key, a re-enrollment
or a TPM clear never changes it. Bind accounts to it. An iOS enrollment has
one leg: `relayEnroll` returns a null `challenge`, and your backend learns the
device's alias from its first verdict (`$result->deviceId()`).

`relayEnroll` relays the body verbatim, whichever shape it is: the TPM body
with its nested `attestationKey { publicArea, parentPublicArea, qualifiedName }`
(windows / linux), the flat macOS body, or the iOS body. A flat TPM body with
a top-level `akPublicArea` is the 7.0 shape and is refused locally with
`\InvalidArgumentException` before any request.

When to enroll:

- The client has no AK blob: enroll first.
- The client's attest or mint reports the AK blob unloadable (TPM cleared,
  parent changed): discard the blob, enroll, retry once.
- `verify` answers `enrollmentRequired: true`: enroll.

## Attest

```php
use Rootherald\Client;
use Rootherald\Verdict;

// 1) Mint a challenge; relay $challenge->challenge to the client verbatim and
//    keep $challenge->nonce, your handle for it. The challenge carries the
//    ask: what the device must prove is fixed here.
$challenge = $rh->issueChallenge(ask: [Client::ASK_IDENTITY]);

// 2) The client quotes over the challenge and returns an opaque $evidence
//    array; relay it for appraisal with the nonce the proof was made over.
$result = $rh->verify(evidence: $evidence, nonce: $challenge->nonce);

if ($result->verdict === Verdict::PASS) {
    // $result->deviceId() is the alias: bind the session to it.
}
```

Omitting `ask` asks for identity and posture. A posture ask runs under the
key's posture policy and checks the boot configuration; use it for step-up,
with `$result->assuranceClaimsMet` listing the policy claims the device
satisfied.

**Name the device that must answer.** `expectedDevices` takes aliases you
enrolled, `expectedKey` a `keyId` you certified; any other device answers a
failing verdict with reason `expected_device_mismatch`, and an unknown value
is `422 expected_unknown`. Pass the same values to `verify`: the verdict
echoes what the server enforced under `expected`, and `verify` refuses a
verdict that does not echo it (`ExpectedNotEnforcedException`).

```php
$challenge = $rh->issueChallenge(
    ask: [Client::ASK_IDENTITY],
    expectedDevices: [$session->deviceId],
);
$result = $rh->verify(
    evidence: $evidence,
    nonce: $challenge->nonce,
    expectedDevices: [$session->deviceId],
);
```

`issueChallenge` takes named arguments only: `ask`, `expectedKey`,
`expectedDevices`. There is no `deviceHint` and no `keyPurpose`; a `"key"`
ask is refused with `InvalidAskException` (400 `invalid_ask`).

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; the resolved policy is pinned on the
challenge when it is minted. Change what a key enforces from the dashboard or
`PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a hand-built
request body is refused with `400 policy_bound_to_key`.

`$result->verdict` is the server's own token, `Verdict::PASS` / `Verdict::WARN`
/ `Verdict::FAIL` (`"pass"` / `"warn"` / `"fail"`, the same vocabulary in every
Root Herald SDK). A response carrying any other token is refused with
`HttpException`, never a guessed verdict. `$result->device()` is the verdict's
`device` object verbatim (`ueid`, `earStatus`, `attestationType`, `tpmKind`,
`hardwareGenuine`, `bootChanged`, …); `$result->expected()` is the binding the
server enforced; `$result->verdictData` is the whole verdict.

## Device-bound signing keys

A key is created inside the chip and certified by the installation's AK; you
get its public half, the device keeps the blob. A signature on a request then
proves the request came from that device, and you check it with no Root
Herald call.

```php
use Rootherald\Client;
use Rootherald\KeySignatures;

// 1) Mint a key challenge for the device that just passed an attest
//    challenge. Relay $keyChallenge->keyChallenge to the client; keep the nonce.
$keyChallenge = $rh->issueKeyChallenge(
    Client::PURPOSE_SIGN,
    expectedDevices: [$result->deviceId()],
);

// 2) The client's MintKey answers with a $certification and keeps its key blob.
$key = $rh->certifyKey($certification, $keyChallenge->nonce);
store($key->deviceId, $key->keyId, $key->jwk);

// Later, without any Root Herald call: the device signed $message with that
// key and sent { message, signature }.
$ok = KeySignatures::verify($jwk, $message, $signature);
```

`certifyKey` returns a `CertifiedKey`:

```php
$key->deviceId      // string — the alias of the device that holds the key
$key->keyId         // string — Root Herald's id for the key
$key->purpose       // 'sign' | 'decrypt'
$key->alg           // 'ES256' | 'RS256' | 'ECDH-ES' | 'RSA-OAEP-256'
$key->format        // 'jwe' | 'apple-ecies' | null — decrypt keys only
$key->jwk           // ['kty' => 'EC', 'crv' => 'P-256', 'x', 'y'] or ['kty' => 'RSA', 'n', 'e']
$key->hardwareBound // bool — false on macOS, where only possession is proved
$key->certifiedAt   // string — ISO 8601
```

The key is P-256 or RSA-2048, chosen by the device. A signature proves which
chip signed, not how the machine booted; run an attest challenge for that.

Minting again for the same purpose rotates the key under the same `keyId`; a
re-enrolled installation gets new key IDs. The key ID identifies an
installation's credential, never a device: bind accounts to the alias.

`KeySignatures::verify($jwk, $message, $signature)` takes the message and the
signature as raw bytes. ES256: a 64-byte signature is read as raw `r || s`,
any other length as DER. RS256: PKCS#1 v1.5 over SHA-256, exactly the modulus
length (256 bytes). It returns `false` for a malformed or non-matching
signature; a JWK that is not a P-256 EC key or an RSA key of at least 2048
bits is `\InvalidArgumentException`.

## Errors

An un-enrolled / failing device is a verdict (`Verdict::FAIL`/`WARN`), **not**
an exception. Only protocol, auth and budget problems throw, each exposing
`$status` and the server's `$serverError`:

| Status | Server `error` code                                   | Exception                    |
| ------ | ----------------------------------------------------- | ---------------------------- |
| 401    | `activation_refused`                                  | `ActivationRefusedException` |
| 401    | anything else                                         | `InvalidSecretKeyException`  |
| 400    | `invalid_ask`, `invalid_purpose`                      | `InvalidAskException`        |
| 400    | anything else, including `wire_version_unsupported`, `invalid_enroll_shape`, `invalid_certification` | `InvalidEvidenceException` |
| 409    | `key_rotation_conflict`                               | `HttpException`              |
| 409    | anything else, including `challenge_expired_or_used`  | `ChallengeException`         |
| 422    | `unknown_policy`, or none                             | `UnknownPolicyException`     |
| 422    | `admission_refused`                                   | `AdmissionRefusedException`  |
| 422    | `expected_unknown`, `key_disclosure_too_low`, `purpose_unsupported`, `certification_rejected` | `HttpException` |
| 429    | `budget_exhausted`, or an `X-RootHerald-Quota` header | `QuotaExceededException`     |
| 429    | anything else                                         | `RateLimitedException`       |

`ActivationRefusedException` is `relayActivate` being refused for an unknown,
spent or foreign `enrollmentId` or a wrong proof; the secret key was accepted.
`InvalidAskException` is a programming error in your backend, not a device
failure. `RateLimitedException::$retryAfterSeconds` is the server's
`Retry-After` (else the body's `retryAfterSeconds`, else null);
`QuotaExceededException::$budget` names the budget that refused
(`['id' => …, 'name' => …]`). Any other status, and a code no class covers
(`posture_not_bound`, `plan_lapsed`), is a plain `HttpException` with
`$serverError` preserved. Input the SDK refuses locally, such as an empty
nonce or a 7.0 enroll body, is `\InvalidArgumentException` and makes no
request.

A response whose `verdict.device.verdict` is not `pass`/`warn`/`fail`, or
whose certified key is malformed, is refused with `HttpException` rather
than returned half-parsed. A verdict that does not echo the `expectedKey` /
`expectedDevices` you passed to `verify` is `ExpectedNotEnforcedException`.

Every request times out after 30 s (`Client::DEFAULT_TIMEOUT_SECONDS`, the
`timeoutSeconds` constructor argument). The default is the same in every Root
Herald server SDK. A custom `httpTransport` may return a `headers` array
(response header names lowercased) so the 429 split can read `Retry-After` and
`X-RootHerald-Quota`; the built-in curl transport does.

## Samples

- [`samples/laravel-demo`](samples/laravel-demo): Laravel `POST /challenge`, `POST /attest`, `POST /certify` and `POST /verify-signature` routes
