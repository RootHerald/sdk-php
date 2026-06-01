<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\Exceptions\JwksException;
use Rootherald\JwksFetcher;

final class JwksFetcherTest extends TestCase
{
    public function testCacheHitsAvoidRefetch(): void
    {
        $calls = 0;
        $jwks = Fixtures::keys()['jwks'];
        $fetcher = new JwksFetcher(
            jwksUri: Fixtures::JWKS_URI,
            cacheTtlSeconds: 3600,
            httpFetcher: function () use (&$calls, $jwks): string {
                $calls++;
                return json_encode($jwks, JSON_THROW_ON_ERROR);
            },
        );
        for ($i = 0; $i < 5; $i++) {
            $fetcher->getKey(Fixtures::KID);
        }
        $this->assertSame(1, $calls);
    }

    public function testUnknownKidRaises(): void
    {
        $fetcher = new JwksFetcher(
            jwksUri: Fixtures::JWKS_URI,
            cooldownSeconds: 0,
            httpFetcher: fn () => json_encode(Fixtures::keys()['jwks'], JSON_THROW_ON_ERROR),
        );
        $this->expectException(JwksException::class);
        $fetcher->getKey('definitely-not-real');
    }

    public function testHttpErrorWrapsAsJwksException(): void
    {
        $fetcher = new JwksFetcher(
            jwksUri: Fixtures::JWKS_URI,
            httpFetcher: fn () => throw new \RuntimeException('curl boom'),
        );
        $this->expectException(JwksException::class);
        $fetcher->getKey(Fixtures::KID);
    }

    public function testMalformedJwksBody(): void
    {
        $fetcher = new JwksFetcher(
            jwksUri: Fixtures::JWKS_URI,
            httpFetcher: fn () => json_encode(['not_keys' => []]),
        );
        $this->expectException(JwksException::class);
        $fetcher->getKey(Fixtures::KID);
    }
}
