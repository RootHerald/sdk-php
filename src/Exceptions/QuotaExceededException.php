<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The tenant has exceeded its metered verify quota (HTTP 429 with server code
 * "quota_exceeded" or an X-RootHerald-Quota header). A 429 without that
 * signal is {@see RateLimitedException}.
 */
class QuotaExceededException extends HttpException
{
    public string $errorCode = 'quota_exceeded';
}
