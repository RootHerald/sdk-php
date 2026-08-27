<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The challenge is unknown, expired, or already consumed (HTTP 409). Mint a
 * fresh one with Client::issueChallenge.
 */
class ChallengeException extends HttpException
{
    public string $errorCode = 'challenge_error';
}
