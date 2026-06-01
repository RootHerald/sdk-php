# Root Herald Signup Guard (WordPress)

Single-file WordPress plugin demonstrating Root Herald integration on the
`register_post` hook. Blocks new user registrations that don't carry a
valid, ALLOW-verdict attestation token.

## Install

```bash
cd path/to/wordpress
composer require rootherald/rootherald
mkdir wp-content/plugins/rootherald-signup-guard
cp /path/to/rootherald-signup-guard.php wp-content/plugins/rootherald-signup-guard/
```

Add the following to `wp-config.php`:

```php
define('ROOTHERALD_ISSUER', 'https://rootherald.io/myorg');
define('ROOTHERALD_API_KEY', 'rh_sk_live_xxxxxxxx');
```

Activate the plugin in the WP admin. The frontend signup form must POST a
`rootherald_token` parameter — that's typically rendered by your client
SDK or browser extension.
