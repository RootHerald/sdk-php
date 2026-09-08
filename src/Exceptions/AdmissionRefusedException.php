<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * Enrollment was refused because the device can never satisfy the policy bound
 * to the supplied challengeId — for example a firmware TPM under a
 * discrete-TPM-only policy (HTTP 422, server code "admission_refused"). The
 * server names the TPM class in the message.
 */
class AdmissionRefusedException extends HttpException
{
    public string $errorCode = 'admission_refused';
}
