<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The submitted evidence blob was malformed or unparseable (HTTP 400).
 *
 * Note: an un-enrolled or failing device is NOT an error — that returns a
 * normal verdict (Verdict::DENY/WARN). This exception is only for evidence the
 * server could not parse at all.
 */
class InvalidEvidenceException extends HttpException
{
    public string $errorCode = 'invalid_evidence';
}
