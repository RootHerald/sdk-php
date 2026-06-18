# Laravel demo

Minimal integration of `rootherald/rootherald` into a Laravel app.

## Setup

```bash
composer require rootherald/rootherald
```

Set environment variables in `.env`:

```ini
# Badge-tier offline verification (the guard middleware):
ROOTHERALD_ISSUER=https://rootherald.io/myorg
# Background-Check (server -> server) secret key — stays on YOUR server only:
ROOTHERALD_SECRET_KEY=rh_sk_live_xxxxxxxx
```

Copy `config-rootherald.php` to `config/rootherald.php`. The service
provider is auto-discovered via Composer, so the `rootherald.guard`
middleware alias is registered automatically.

## Usage

Drop the snippets in `routes.php` into your `routes/api.php`. It shows both
paths:

- `POST /attest` — the **Background-Check (server → server)** flow: the dumb
  client posts its opaque evidence blob and this server appraises it with the
  `rh_sk_` secret key via `Rootherald\BackgroundCheck`.
- `POST /signup`, `POST /wire-transfer` — the **badge-tier** offline-verify flow
  gated by the guard middleware:

```php
Route::post('/signup', SignupController::class)
    ->middleware(['rootherald.guard:signup']);
```

`rootherald.guard:signup,strict` rejects WARN verdicts in addition to DENY.
