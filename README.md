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

// 1) Mint a relay-friendly nonce; send $challenge->nonce down to the client.
$challenge = $rh->issueChallenge();

// 2) The client quotes over the nonce and returns an opaque $evidence array;
//    relay it for appraisal.
$result = $rh->verify(
    evidence: $evidence,
    challengeId: $challenge->challengeId,
    policy: 'rootherald:builtin:strict-hardware', // optional
);

if ($result->verdict === Verdict::ALLOW) {
    // proceed
}
```

> `createChallenge()` / `attest()` are retained as deprecated aliases of
> `issueChallenge()` / `verify()`.

An un-enrolled / failing device is a verdict (`Verdict::DENY`/`WARN`), **not**
an exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException`
(401), `UnknownPolicyException` (422), `ChallengeException` (409),
`InvalidEvidenceException` (400), `QuotaExceededException` (429).

### Enroll relay (one-time device bootstrap)

The client's keyless enroll handshake is relayed in two legs. Every enrolment
returns a MakeCredential challenge, a device already known included —
re-enrolment is how a device rotates its attestation key. `deviceId` is your
tenant's alias for the device, not a global identifier.

```php
// Leg 1 — relay the client's EnrollBegin() blob.
$enroll = $rh->relayEnroll($enrollRequestBlob); // ekPublicKey, akPublicArea, platform, …

// Hand $enroll->challenge to the client's EnrollComplete(), then…
$client->sendToClient($enroll->challenge->toArray());

// Leg 2 — relay the client's EnrollComplete() blob.
$activated = $rh->relayActivate($activationResponse); // deviceId, decryptedSecret
// $activated->deviceId is what you map to your user/account.
```

The verdict is computed by Root Herald and returned to your backend; it never
travels through the client.

## Samples

- [`samples/laravel-demo`](samples/laravel-demo): Laravel `POST /attest` Background-Check route
