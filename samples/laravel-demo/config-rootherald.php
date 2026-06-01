<?php

/**
 * Place this file at `config/rootherald.php` in your Laravel app.
 */

return [
    'issuer' => env('ROOTHERALD_ISSUER'),
    'api_key' => env('ROOTHERALD_API_KEY'),
    'base_url' => env('ROOTHERALD_BASE_URL', 'https://rootherald.io'),
    'jwks_uri' => env('ROOTHERALD_JWKS_URI', 'https://rootherald.io/.well-known/jwks.json'),
    'audience' => env('ROOTHERALD_AUDIENCE'),
];
