<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The key's format is one DeviceEncryption::encryptToDevice cannot produce:
 * "apple-ecies", the Security.framework ECIES envelope a macOS enclave key
 * opens, needs an Apple-side encryptor.
 */
class EnvelopeFormatNotSupportedException extends \InvalidArgumentException
{
    public function __construct(
        /** The key's format. */
        public readonly string $format,
    ) {
        parent::__construct(
            "key format \"{$format}\" is not produced here: encryptToDevice writes the jwe envelope a TPM decrypt key opens;"
            . ' an apple-ecies key needs an Apple-side encryptor'
        );
    }
}
