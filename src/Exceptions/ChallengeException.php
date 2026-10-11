<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The challenge is unknown, expired, or already consumed (HTTP 409). Mint a
 * fresh one with Client::issueChallenge or Client::issueKeyChallenge. A 409
 * carrying "key_rotation_conflict" is a plain HttpException instead: the key
 * challenge was fine, the rotation it asked for collided.
 */
class ChallengeException extends HttpException
{
    public string $errorCode = 'challenge_error';
}
