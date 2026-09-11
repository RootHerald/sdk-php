<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The Root Herald REST API returned a non-2xx response.
 */
class HttpException extends RootheraldException
{
    public string $errorCode = 'http_error';

    /**
     * @param string|null $serverError the server's "error" discriminator from
     *        the response body (e.g. "unknown_policy", "admission_refused"),
     *        or null when the body carried none
     */
    public function __construct(
        public readonly int $status,
        public readonly string $body,
        ?string $message = null,
        public readonly ?string $serverError = null,
    ) {
        parent::__construct($message ?? "HTTP {$status}: " . substr($body, 0, 200));
    }
}
