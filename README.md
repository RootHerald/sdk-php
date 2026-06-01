# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+. Verifies attestation token JWTs and
CAEP webhook events (SET JWTs) against the Root Herald JWKS. Pure PHP —
only requires `ext-openssl` and `firebase/php-jwt`.

```bash
composer require rootherald/rootherald
```

## Usage

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

`$claims` exposes:

- `$claims->subject` — stable user UUID
- `$claims->acr`, `$claims->amr`, `$claims->authTime` — OIDC claims
- `$claims->deviceId` (`rootherald_device.ueid`)
- `$claims->tpmClass`, `$claims->platform`, `$claims->attestationType`
- `$claims->earStatus` and `$claims->verdict` (`Verdict::ALLOW`/`WARN`/`DENY`)
- `$claims->raw` — full verified payload

## Webhook verification

```php
$event = $client->verifySet($request->getContent());

if ($event->eventType === 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change') {
    updateDevice($event->deviceId, $event->eventPayload);
}
return new Response('', 202);
```

## Laravel integration

```php
// config/app.php (or via auto-discovery)
'providers' => [
    Rootherald\Laravel\RootheraldServiceProvider::class,
],

// routes/api.php
Route::post('/signup', SignupController::class)
    ->middleware(['rootherald.guard:signup']);

// Inside the controller:
$claims = request()->attributes->get('rootherald_claims');
```

## Symfony integration

Register `\Rootherald\Symfony\EventSubscriber\RootheraldSubscriber` in your
services configuration; opt routes in by setting the `_rootherald_action`
attribute (via a controller attribute or route default).

## WordPress

See [`samples/wordpress-plugin`](samples/wordpress-plugin) for a single-file
plugin that blocks user registration without a valid attestation token.

## Errors

All exceptions extend `\Rootherald\Exceptions\RootheraldException`:

- `TokenExpiredException` — `exp` is in the past
- `VerificationException` — signature / issuer / audience / schema fail
- `WebhookSignatureException` — SET JWT verification failed
- `JwksException` — JWKS could not be fetched / parsed
- `HttpException` — Root Herald REST API returned non-2xx

## Tests

```bash
composer install
vendor/bin/phpunit
```

Tests cover the same edge-case matrix as the other Root Herald SDKs:
happy path, expired token, wrong issuer/audience, missing required
claim, bad EAT profile, unknown kid, tampered signature, `alg: none`,
WARN/DENY mapping, webhook envelope checks, REST surface, and the
Laravel middleware.
