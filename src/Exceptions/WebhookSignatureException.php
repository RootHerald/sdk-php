<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * Thrown when a CAEP webhook (SET JWT) fails signature or envelope
 * verification.
 */
class WebhookSignatureException extends RootheraldException
{
    public string $errorCode = 'webhook_signature_invalid';
}
