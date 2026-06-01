<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * Base class for all Root Herald SDK exceptions.
 */
class RootheraldException extends \RuntimeException
{
    public string $errorCode = 'rootherald_error';
}
