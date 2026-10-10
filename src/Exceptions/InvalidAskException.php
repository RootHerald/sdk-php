<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The challenge named an ask the server does not know, such as the retired
 * "key" (HTTP 400, server code "invalid_ask"). The backend's code is wrong,
 * not the device; keys are minted with Client::issueKeyChallenge.
 */
class InvalidAskException extends HttpException
{
    public string $errorCode = 'invalid_ask';
}
