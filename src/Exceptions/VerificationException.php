<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * Thrown when an attestation token fails signature, claim, or schema
 * verification.
 */
class VerificationException extends RootheraldException
{
    public string $errorCode = 'verification_failed';
}
