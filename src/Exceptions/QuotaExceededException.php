<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The account's attestation quota or rate limit was exceeded (HTTP 429).
 */
class QuotaExceededException extends HttpException
{
    public string $errorCode = 'quota_exceeded';
}
