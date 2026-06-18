<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The secret key was rejected by the Root Herald API (HTTP 401).
 *
 * A locally-detected bad key (empty, malformed, or a publishable rh_pk_ key
 * passed where a secret key is required) is reported as \InvalidArgumentException
 * at construction time and never reaches the network.
 */
class InvalidSecretKeyException extends HttpException
{
    public string $errorCode = 'invalid_secret_key';
}
