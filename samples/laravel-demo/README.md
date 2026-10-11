# Laravel demo

Minimal integration of `rootherald/rootherald` into a Laravel app.

## Setup

```bash
composer require rootherald/rootherald
```

Set environment variables in `.env`:

```ini
# Server -> server secret key — stays on YOUR server only:
ROOTHERALD_SECRET_KEY=rh_sk_live_xxxxxxxx
```

## Usage

Drop the snippet in `routes.php` into your `routes/api.php`. Four routes
show the flow with a device-bound signing key, all via `Rootherald\Client`:

- `POST /challenge` — mint a challenge asking for identity; relay its
  `challenge` string to the client verbatim.
- `POST /attest` — the client posts its opaque evidence blob and the
  nonce; this server appraises it with the `rh_sk_` secret key and, on a
  pass, mints a key challenge bound to that device.
- `POST /certify` — the client posts its `MintKey` certification; this
  server relays it and stores the key's public half.
- `POST /verify-signature` — check a later signature from the device against
  the stored key with `Rootherald\KeySignatures`, locally.
