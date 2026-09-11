<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * A policy bound to the API key no longer exists (HTTP 422, server code
 * "unknown_policy"). Nothing is substituted; the call fails closed until the
 * key is bound to a policy that exists.
 */
class UnknownPolicyException extends HttpException
{
    public string $errorCode = 'unknown_policy';
}
