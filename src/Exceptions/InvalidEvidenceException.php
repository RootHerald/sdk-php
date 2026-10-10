<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The relayed blob was malformed or could not be appraised (HTTP 400). This
 * includes "wire_version_unsupported" (a 7.0-shaped enroll body) and
 * "invalid_enroll_shape" (an attestation key whose qualified name does not
 * follow from its parent). A 400 carrying "invalid_ask" is
 * {@see InvalidAskException} instead.
 *
 * An un-enrolled or failing device is NOT an error — that returns a normal
 * verdict (Verdict::FAIL/WARN). This exception is only for a request the
 * server could not parse at all.
 */
class InvalidEvidenceException extends HttpException
{
    public string $errorCode = 'invalid_evidence';
}
