<?php

declare(strict_types=1);

namespace Rootherald\Tests;

use PHPUnit\Framework\TestCase;
use Rootherald\Client;

/**
 * The secret rides in an Authorization header on every request and is
 * full-privilege, so a base URL that is not https hands it to anyone on the
 * path. A typo is enough, and nothing downstream notices because the request
 * itself still succeeds.
 */
final class BaseUrlTest extends TestCase
{
    /** @return array<string, array{string}> */
    public static function insecureUrls(): array
    {
        return [
            'plain http'      => ['http://api.example.test'],
            'production http' => ['http://rootherald.io'],
            'no scheme'       => ['api.example.test'],
            'scheme relative' => ['//api.example.test'],
            'empty'           => [''],
        ];
    }

    /** @dataProvider insecureUrls */
    public function testRejectsInsecureBaseUrl(string $baseUrl): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Client('rh_sk_test_xxx', $baseUrl);
    }

    /** @return array<string, array{string}> */
    public static function acceptableUrls(): array
    {
        return [
            'https'          => ['https://api.example.test'],
            'localhost'      => ['http://localhost:8080'],
            'ipv4 loopback'  => ['http://127.0.0.1:5000'],
            'ipv6 loopback'  => ['http://[::1]:5000'],
        ];
    }

    /**
     * Loopback stays usable so the local docker stack works over http.
     *
     * @dataProvider acceptableUrls
     */
    public function testAcceptsHttpsAndLoopback(string $baseUrl): void
    {
        $client = new Client('rh_sk_test_xxx', $baseUrl);
        $this->assertInstanceOf(Client::class, $client);
    }
}
