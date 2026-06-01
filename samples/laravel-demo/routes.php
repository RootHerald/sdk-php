<?php

/**
 * Sample Laravel route registration for the Root Herald guard middleware.
 *
 * Add `Rootherald\Laravel\RootheraldServiceProvider::class` to
 * `config/app.php` providers (or rely on auto-discovery), then drop this
 * snippet into your `routes/web.php` or `routes/api.php`.
 *
 *   ROOTHERALD_ISSUER=https://rootherald.io/myorg in .env
 */

use Illuminate\Support\Facades\Route;

Route::post('/signup', function () {
    $claims = request()->attributes->get('rootherald_claims');
    return ['ok' => true, 'device_id' => $claims?->deviceId];
})->middleware('rootherald.guard:signup');

Route::post('/wire-transfer', function () {
    return ['ok' => true];
})->middleware('rootherald.guard:wire-transfer,strict');
