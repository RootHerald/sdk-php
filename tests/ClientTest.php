<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\Client;
use Rootherald\Exceptions\HttpException;

final class ClientTest extends TestCase
{
    private function client(callable $transport): Client
    {
        return new Client(
            issuer: Fixtures::ISSUER,
            apiKey: 'rh_sk_test_xxx',
            baseUrl: 'https://rootherald.io',
            audience: Fixtures::AUDIENCE,
            jwksFetcher: Fixtures::jwksFetcher(),
            httpTransport: $transport,
        );
    }

    public function testGetDeviceRoundTrips(): void
    {
        $seen = [];
        $client = $this->client(function (string $method, string $url, array $headers, ?string $body) use (&$seen): array {
            $seen['method'] = $method;
            $seen['url'] = $url;
            $seen['auth'] = $headers['Authorization'] ?? null;
            return ['status' => 200, 'body' => json_encode(['id' => 'dev-123', 'tpm_class' => 'hardware'])];
        });

        $out = $client->getDevice('dev-123');
        $this->assertSame('dev-123', $out['id']);
        $this->assertSame('GET', $seen['method']);
        $this->assertStringEndsWith('/api/v1/devices/dev-123', $seen['url']);
        $this->assertSame('Bearer rh_sk_test_xxx', $seen['auth']);
    }

    public function testHttpErrorRaised(): void
    {
        $client = $this->client(fn () => ['status' => 403, 'body' => '{"error":"forbidden"}']);
        $this->expectException(HttpException::class);
        $client->getDevice('d-403');
    }

    public function testVerifyTokenFacadeUsesSharedJwks(): void
    {
        $client = $this->client(fn () => ['status' => 404, 'body' => '']);
        $claims = $client->verifyToken(Fixtures::makeToken());
        $this->assertSame('device-uuid-1234', $claims->deviceId);
    }

    public function testVerifySetFacade(): void
    {
        $client = $this->client(fn () => ['status' => 404, 'body' => '']);
        $event = $client->verifySet(Fixtures::makeSet());
        $this->assertSame('device-uuid-1234', $event->deviceId);
    }
}
