<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * POST /api/v1/attest/activate refused the enrollment (HTTP 401, server code
 * "activation_refused"): the enrollmentId is unknown, spent or foreign, or
 * the proof did not match. The secret key was accepted; this is not a
 * credential problem. Every activation refusal reason produces this one
 * answer.
 */
class ActivationRefusedException extends HttpException
{
    public string $errorCode = 'activation_refused';
}
