# Root Herald — PHP SDK

Backend SDK for verifying [Root Herald](https://rootherald.io) device attestation JWTs from PHP applications. Includes Laravel integration.

## Install

```bash
composer require rootherald/rootherald
```

Requires PHP 8.1 or later.

## 30-second integration (plain PHP)

```php
<?php
use RootHerald\Client;

$client = new Client([
    'issuer' => 'https://api.rootherald.io',
    'audience' => 'plat_your_client_id',
]);

$verdict = $client->verifyToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');

if ($verdict->device->verdict !== 'pass') {
    http_response_code(403);
    exit('device check failed');
}

echo "device: " . $verdict->device->deviceId;
```

## Laravel integration

```php
// config/rootherald.php
return [
    'issuer' => env('ROOTHERALD_ISSUER', 'https://api.rootherald.io'),
    'audience' => env('ROOTHERALD_AUDIENCE'),
];
```

```php
// routes/web.php
Route::middleware('rootherald.attest')->get('/me', function () {
    return ['device' => rh_verdict()->device->deviceId];
});
```

See [`samples/laravel-demo`](./samples/laravel-demo) for a full working example.

## What you get

- `RootHerald\Client` — JWKS-cached token verifier
- `rh_verdict()` helper inside Laravel routes/controllers
- `rootherald.attest` middleware for gating routes
- Strongly-typed `AttestationVerdict` and `DeviceVerdict` value objects
- `WebhookVerifier` for CAEP webhook signature checks

## Trust chain

The SDK fetches Root Herald's signing keys from `{issuer}/.well-known/jwks.json` and caches them (default 1 hour). Verification is offline after the first key fetch.

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
