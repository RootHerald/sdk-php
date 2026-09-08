# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+.

**Backend relay (server → server, Client ABI 2.0)** via `Client`: your
keyless dumb client does only local TPM work and hands opaque blobs to *your*
server, which relays them to Root Herald using your `rh_sk_` secret key. The
client never holds a key or talks to Root Herald, and never gets a verdict.
Four helpers mirror `@rootherald/node`: `relayEnroll`, `relayActivate`,
`issueChallenge`, `verify`.

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

// 1) Mint a challenge; relay $challenge->challenge to the client verbatim.
//    The challenge carries the ask: what the device must prove is fixed here.
$challenge = $rh->issueChallenge(
    ask: [Client::ASK_IDENTITY, Client::ASK_POSTURE], // the default when omitted
    policy: 'rootherald:builtin:strict-hardware',      // optional, bound to the challenge
);

// 2) The client quotes over the challenge and returns an opaque $evidence
//    array; relay it for appraisal.
$result = $rh->verify(
    evidence: $evidence,
    challengeId: $challenge->challengeId,
);

if ($result->verdict === Verdict::ALLOW) {
    // proceed
}
```

A policy named at verify time may only tighten the challenge's; a looser one
is refused with `PolicyDowngradeException` (422 `policy_downgrade`).

An un-enrolled / failing device is a verdict (`Verdict::DENY`/`WARN`), **not**
an exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException`
(401), `UnknownPolicyException` / `PolicyDowngradeException` /
`AdmissionRefusedException` (422, told apart by `$serverError`),
`ChallengeException` (409), `InvalidEvidenceException` (400),
`QuotaExceededException` (429).

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

$result = $rh->verify(evidence: $evidence, challengeId: $challenge->challengeId);
$key = $result->key();               // present only on a pass with a key ask
store($userId, $key->keyId, $key->jwk);

// Later: the device signed $message with that key (raw r||s or DER).
$ok = KeySignatures::verify($key->jwk, $message, $signature);
```

### Enroll relay (one-time device bootstrap)

The client's keyless enroll handshake is relayed in two legs. Every enrollment
returns a MakeCredential challenge, a device already known included —
re-enrollment is how a device rotates its attestation key. `deviceId` is your
tenant's alias for the device, not a global identifier.

```php
// Leg 1 — relay the client's EnrollBegin() blob. Pass a live challenge id to
// run admission against that challenge's policy; a device that could never
// satisfy it is refused with AdmissionRefusedException (422 admission_refused).
$enroll = $rh->relayEnroll($enrollRequestBlob, $challenge->challengeId); // challengeId optional

// Hand $enroll->challenge to the client's EnrollComplete(), then…
$client->sendToClient($enroll->challenge->toArray());

// Leg 2 — relay the client's EnrollComplete() blob.
$activated = $rh->relayActivate($activationResponse); // deviceId, decryptedSecret
// $activated->deviceId is what you map to your user/account.
```

The verdict is computed by Root Herald and returned to your backend; it never
travels through the client.

## Samples

- [`samples/laravel-demo`](samples/laravel-demo): Laravel `POST /challenge`, `POST /attest` and `POST /verify-signature` routes
