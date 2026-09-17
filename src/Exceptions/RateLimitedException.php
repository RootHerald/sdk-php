<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The request-rate limiter refused the call (HTTP 429 without a quota
 * signal). Retry after $retryAfterSeconds. Distinct from
 * {@see QuotaExceededException}, the metered billing ceiling.
 */
class RateLimitedException extends HttpException
{
    public string $errorCode = 'rate_limited';

    /**
     * @param int|null $retryAfterSeconds seconds to wait before retrying: the
     *        Retry-After header, else the body's retryAfterSeconds, else null
     */
    public function __construct(
        int $status,
        string $body,
        ?string $message = null,
        ?string $serverError = null,
        public readonly ?int $retryAfterSeconds = null,
    ) {
        parent::__construct($status, $body, $message, $serverError);
    }
}
