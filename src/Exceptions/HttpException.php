<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The Root Herald REST API returned a non-2xx response.
 */
class HttpException extends RootheraldException
{
    public string $errorCode = 'http_error';

    public function __construct(
        public readonly int $status,
        public readonly string $body,
        ?string $message = null,
    ) {
        parent::__construct($message ?? "HTTP {$status}: " . substr($body, 0, 200));
    }
}
