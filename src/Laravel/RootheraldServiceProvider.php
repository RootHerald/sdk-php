<?php

declare(strict_types=1);

namespace Rootherald\Laravel;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Rootherald\Client;
use Rootherald\Laravel\Middleware\GuardDevice;

/**
 * Laravel service provider: bind a {@see Client} singleton and register the
 * `rootherald.guard` route middleware alias.
 *
 * Config values (in `config/rootherald.php` or environment):
 *
 *   - rootherald.issuer    (string, required)
 *   - rootherald.api_key   (string, optional)
 *   - rootherald.base_url  (default https://rootherald.io)
 *   - rootherald.jwks_uri  (default https://rootherald.io/.well-known/jwks.json)
 *   - rootherald.audience  (string, optional)
 */
class RootheraldServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Client::class, function (Application $app): Client {
            $config = $app['config']->get('rootherald', []);
            return new Client(
                issuer: (string) ($config['issuer'] ?? env('ROOTHERALD_ISSUER')),
                apiKey: $config['api_key'] ?? env('ROOTHERALD_API_KEY'),
                baseUrl: $config['base_url'] ?? env('ROOTHERALD_BASE_URL', 'https://rootherald.io'),
                jwksUri: $config['jwks_uri']
                    ?? env('ROOTHERALD_JWKS_URI', 'https://rootherald.io/.well-known/jwks.json'),
                audience: $config['audience'] ?? env('ROOTHERALD_AUDIENCE'),
            );
        });
    }

    public function boot(Router $router): void
    {
        $router->aliasMiddleware('rootherald.guard', GuardDevice::class);
    }
}
