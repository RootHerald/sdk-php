<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * Friendly tri-state verdict mapped from the EAR status carried in the
 * attestation token.
 *
 *  - ALLOW: device attestation affirming, no concerns; allow the action.
 *  - WARN:  warnings present (reduced assurance / partial fail);
 *           allow with care.
 *  - DENY:  contraindicated — refuse the action.
 */
enum Verdict: string
{
    case ALLOW = 'allow';
    case WARN = 'warn';
    case DENY = 'deny';

    public static function fromEarStatus(?string $earStatus): self
    {
        return match ($earStatus) {
            'affirming' => self::ALLOW,
            'contraindicated' => self::DENY,
            default => self::WARN,
        };
    }
}
