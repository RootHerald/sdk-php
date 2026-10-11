<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * Client::verify was given an expectedKey or expectedDevices and the verdict
 * did not echo it under `expected`, or named a device outside it. The API
 * ignores unknown fields, so a server that does not enforce the binding
 * would otherwise accept any device silently; the verdict is refused instead.
 */
class ExpectedNotEnforcedException extends HttpException
{
    public string $errorCode = 'expected_not_enforced';
}
