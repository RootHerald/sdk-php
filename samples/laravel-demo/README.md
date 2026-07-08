# Laravel demo

Minimal integration of `rootherald/rootherald` into a Laravel app.

## Setup

```bash
composer require rootherald/rootherald
```

Set environment variables in `.env`:

```ini
# Background-Check (server -> server) secret key — stays on YOUR server only:
ROOTHERALD_SECRET_KEY=rh_sk_live_xxxxxxxx
```

## Usage

Drop the snippet in `routes.php` into your `routes/api.php`:

- `POST /attest` — the **Background-Check (server → server)** flow: the dumb
  client posts its opaque evidence blob and this server appraises it with the
  `rh_sk_` secret key via `Rootherald\BackgroundCheck`.
