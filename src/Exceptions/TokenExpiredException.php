<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The attestation token's `exp` claim is in the past.
 */
class TokenExpiredException extends VerificationException
{
    public string $errorCode = 'token_expired';
}
