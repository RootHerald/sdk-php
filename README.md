# rootherald/rootherald (PHP)

Root Herald server SDK for PHP 8.1+ — verifies attestation token JWTs and
CAEP webhook events against the Root Herald JWKS.

```bash
composer require rootherald/rootherald
```

## Verify a token

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
