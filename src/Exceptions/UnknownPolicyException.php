<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The named policy is unknown or not owned by this tenant (HTTP 422). Foreign
 * or unrecognised policy names fail closed.
 */
class UnknownPolicyException extends HttpException
{
    public string $errorCode = 'unknown_policy';
}
