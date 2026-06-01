<?php

declare(strict_types=1);

namespace Rootherald\Tests\Laravel;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\TestCase;
use Rootherald\Client;
use Rootherald\Laravel\Middleware\GuardDevice;
use Rootherald\Tests\Fixtures;

/**
 * Exercises {@see GuardDevice} directly without booting a full Laravel
 * application. We use the underlying HttpFoundation Request/Response
 * objects, which is all the middleware actually depends on.
 */
final class GuardDeviceTest extends TestCase
{
    protected function setUp(): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        // The middleware calls Laravel's `response()` helper; bind a tiny
        // factory if not already bound.
        if (!function_exists('response')) {
            require __DIR__ . '/responseShim.php';
        }
    }

    private function client(): Client
    {
        return new Client(
            issuer: Fixtures::ISSUER,
            audience: Fixtures::AUDIENCE,
            jwksFetcher: Fixtures::jwksFetcher(),
            httpTransport: fn () => ['status' => 404, 'body' => ''],
        );
    }

    public function testMissingTokenReturns401(): void
    {
        $mw = new GuardDevice($this->client());
        $req = Request::create('/signup', 'POST');
        /** @var JsonResponse $resp */
        $resp = $mw->handle($req, fn () => new Response('next'), 'signup');
        $this->assertSame(401, $resp->getStatusCode());
    }

    public function testValidTokenPassesThrough(): void
    {
        $mw = new GuardDevice($this->client());
        $token = Fixtures::makeToken();
        $req = Request::create('/signup', 'POST', [], [], [], [
            'HTTP_AUTHORIZATION' => "Bearer {$token}",
        ]);
        $resp = $mw->handle($req, fn ($r) => new Response('ok'), 'signup');
        $this->assertSame(200, $resp->getStatusCode());
        $this->assertNotNull($req->attributes->get('rootherald_claims'));
    }

    public function testWarnAllowedByDefault(): void
    {
        $mw = new GuardDevice($this->client());
        $token = Fixtures::makeToken(earStatus: 'warning');
        $req = Request::create('/signup', 'POST', [], [], [], [
            'HTTP_AUTHORIZATION' => "Bearer {$token}",
        ]);
        $resp = $mw->handle($req, fn () => new Response('ok'), 'signup');
        $this->assertSame(200, $resp->getStatusCode());
    }

    public function testWarnBlockedInStrictMode(): void
    {
        $mw = new GuardDevice($this->client());
        $token = Fixtures::makeToken(earStatus: 'warning');
        $req = Request::create('/signup', 'POST', [], [], [], [
            'HTTP_AUTHORIZATION' => "Bearer {$token}",
        ]);
        $resp = $mw->handle($req, fn () => new Response('ok'), 'signup', 'strict');
        $this->assertSame(403, $resp->getStatusCode());
    }
}
