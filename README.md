# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+. Two paths:

- **Backend relay (server → server, Client ABI 2.0)** — `BackgroundCheck`: your
  keyless dumb client does only local TPM work and hands opaque blobs to *your*
  server, which relays them to Root Herald using your `rh_sk_` secret key. The
  client never holds a key or talks to Root Herald, and never gets a verdict.
  Four helpers mirror `@rootherald/node`: `relayEnroll`, `relayActivate`,
  `issueChallenge`, `verify`.
- **Badge tier (offline verify)** — `Client::verifyToken` + Laravel/Symfony
  middleware: verify a Root Herald-issued EAT (JWT) and CAEP webhook events
  against the Root Herald JWKS, no per-request network call.

```bash
composer require rootherald/rootherald
```

## Backend relay (server → server)

```php
use Rootherald\BackgroundCheck;
use Rootherald\Verdict;

// Construct with your SECRET key (rh_sk_…). A publishable key (rh_pk_…) is
// rejected — it must never be used server-side.
$rh = new BackgroundCheck(secretKey: getenv('ROOTHERALD_SECRET_KEY'));

// 1) Mint a relay-friendly nonce; send $challenge->nonce down to the client.
$challenge = $rh->issueChallenge();

// 2) The client quotes over the nonce and returns an opaque $evidence array;
//    relay it for appraisal.
$result = $rh->verify(
    evidence: $evidence,
    challengeId: $challenge->challengeId,
    policy: 'rootherald:builtin:strict-hardware', // optional
    returnToken: true,                            // optional signed EAT
);

if ($result->verdict === Verdict::ALLOW) {
    // proceed; $result->token (when returnToken) is verifiable offline.
}
```

> `createChallenge()` / `attest()` are retained as deprecated aliases of
> `issueChallenge()` / `verify()`.

An un-enrolled / failing device is a verdict (`Verdict::DENY`/`WARN`), **not**
an exception. Only protocol/auth/quota problems throw — `InvalidSecretKeyException`
(401), `UnknownPolicyException` (422), `ChallengeException` (409),
`InvalidEvidenceException` (400), `QuotaExceededException` (429).

### Enroll relay (one-time device bootstrap)

The client's keyless enroll handshake is relayed in two legs. The enroll leg is
asymmetric — a fresh device returns a MakeCredential challenge (`201`); an
already-bound device short-circuits (`409`) and you skip activation.

```php
// Leg 1 — relay the client's EnrollBegin() blob.
$enroll = $rh->relayEnroll($enrollRequestBlob); // ekPublicKey, akPublicArea, platform, …

if ($enroll->alreadyEnrolled) {
    // 409: device already bound — use $enroll->deviceId, skip activation.
} else {
    // 201: hand $enroll->challenge to the client's EnrollComplete(), then…
    $client->sendToClient($enroll->challenge->toArray());

    // Leg 2 — relay the client's EnrollComplete() blob.
    $activated = $rh->relayActivate($activationResponse); // deviceId, decryptedSecret
    // $activated->deviceId is what you map to your user/account.
}
```

## Verify a token (badge tier)

```php
use Rootherald\Client;
use Rootherald\Verdict;

$client = new Client(
    issuer: 'https://rootherald.io/myorg',
    jwksUri: 'https://rootherald.io/.well-known/jwks.json',
);
$claims = $client->verifyToken($token);

if ($claims->verdict === Verdict::ALLOW) {
    // proceed with signup
}
```

`$claims` exposes the subject, OIDC claims (`acr`/`amr`/`authTime`), device
fields (`deviceId`/`tpmClass`/`platform`/`attestationType`), the `verdict`
(`Verdict::ALLOW`/`WARN`/`DENY`), and the full verified payload as
`$claims->raw`.

## Laravel

```php
Route::post('/signup', SignupController::class)
    ->middleware(['rootherald.guard:signup']);

// In the controller:
$claims = request()->attributes->get('rootherald_claims');
```

The service provider auto-discovers; configure via `config/rootherald.php` or
the `ROOTHERALD_*` environment variables.

## Samples

- [`samples/laravel-demo`](samples/laravel-demo) — Laravel signup guard
- [`samples/wordpress-plugin`](samples/wordpress-plugin) — single-file plugin
  that blocks registration without a valid attestation token

Symfony, webhook (SET) verification, and the REST surface are documented at
<https://rootherald.io/developers/sdks/php>.
