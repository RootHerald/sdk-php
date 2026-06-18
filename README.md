# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+. Two paths:

- **Background-Check (server → server)** — `BackgroundCheck`: your dumb client
  collects an opaque evidence blob and hands it to *your* server, which appraises
  it with Root Herald using your `rh_sk_` secret key. The client never holds a
  key or talks to Root Herald.
- **Badge tier (offline verify)** — `Client::verifyToken` + Laravel/Symfony
  middleware: verify a Root Herald-issued EAT (JWT) and CAEP webhook events
  against the Root Herald JWKS, no per-request network call.

```bash
composer require rootherald/rootherald
```

## Background-Check (server → server)

```php
use Rootherald\BackgroundCheck;
use Rootherald\Verdict;

// Construct with your SECRET key (rh_sk_…). A publishable key (rh_pk_…) is
// rejected — it must never be used server-side.
$rh = new BackgroundCheck(secretKey: getenv('ROOTHERALD_SECRET_KEY'));

// 1) Mint a relay-friendly nonce; send $challenge->nonce down to the client.
$challenge = $rh->createChallenge();

// 2) The client quotes over the nonce and returns an opaque $evidence array;
//    submit it for appraisal.
$result = $rh->attest(
    evidence: $evidence,
    challengeId: $challenge->challengeId,
    policy: 'rootherald:builtin:strict-hardware', // optional
    returnToken: true,                            // optional signed EAT
);

if ($result->verdict === Verdict::ALLOW) {
    // proceed; $result->token (when returnToken) is verifiable offline.
}
```

An un-enrolled / failing device is a verdict (`Verdict::DENY`/`WARN`), **not**
an exception. Only protocol/auth/quota problems throw — `InvalidSecretKeyException`
(401), `UnknownPolicyException` (422), `ChallengeException` (409),
`InvalidEvidenceException` (400), `QuotaExceededException` (429).

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
