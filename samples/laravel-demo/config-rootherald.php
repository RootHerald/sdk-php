<?php

/**
 * Place this file at `config/rootherald.php` in your Laravel app.
 */

return [
    // Background-Check (server -> server) secret key (rh_sk_…). Stays on YOUR
    // server only; never shipped to the client.
    'secret_key' => env('ROOTHERALD_SECRET_KEY'),
    'base_url' => env('ROOTHERALD_BASE_URL', 'https://rootherald.io'),
];
