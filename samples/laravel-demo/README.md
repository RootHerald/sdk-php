# Laravel demo

Minimal integration of `rootherald/rootherald` into a Laravel app.

## Setup

```bash
composer require rootherald/rootherald
```

Set environment variables in `.env`:

```ini
ROOTHERALD_ISSUER=https://rootherald.io/myorg
ROOTHERALD_API_KEY=rh_sk_live_xxxxxxxx
```

Copy `config-rootherald.php` to `config/rootherald.php`. The service
provider is auto-discovered via Composer, so the `rootherald.guard`
middleware alias is registered automatically.

## Usage

Drop the snippet in `routes.php` into your `routes/api.php`.

```php
Route::post('/signup', SignupController::class)
    ->middleware(['rootherald.guard:signup']);
```

`rootherald.guard:signup,strict` rejects WARN verdicts in addition to DENY.
