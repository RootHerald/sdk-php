<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The secret key was rejected by the Root Herald API (HTTP 401). A 401
 * carrying "activation_refused" is {@see ActivationRefusedException} instead.
 *
 * A locally-detected bad key (empty or malformed — anything not starting with
 * rh_sk_) is reported as \InvalidArgumentException at construction time and
 * never reaches the network.
 */
class InvalidSecretKeyException extends HttpException
{
    public string $errorCode = 'invalid_secret_key';
}
