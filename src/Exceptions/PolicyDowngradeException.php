<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The verify leg named a policy looser than the one the challenge was issued
 * with (HTTP 422, server code "policy_downgrade"). A challenge fixes the ask
 * when it is minted; verify may only tighten it.
 */
class PolicyDowngradeException extends HttpException
{
    public string $errorCode = 'policy_downgrade';
}
