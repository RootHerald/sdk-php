<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * JWKS document could not be fetched or parsed.
 */
class JwksException extends RootheraldException
{
    public string $errorCode = 'jwks_error';
}
