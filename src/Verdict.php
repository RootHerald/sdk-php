<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The verdict values the server emits at verdict.device.verdict, as
 * {@see AttestResult::$verdict} returns them. The same vocabulary in every
 * Root Herald SDK; a response carrying any other token is refused.
 *
 *  - PASS: the device satisfied the policy.
 *  - WARN: the device passed with reduced assurance; the policy says whether
 *          to proceed.
 *  - FAIL: the device did not satisfy the policy, or is not enrolled (see
 *          {@see AttestResult::$enrollmentRequired}).
 */
enum Verdict: string
{
    case PASS = 'pass';
    case WARN = 'warn';
    case FAIL = 'fail';

    /**
     * Read the verdict.device.verdict token. Anything outside the three
     * values the server emits is null, never a guessed verdict.
     */
    public static function fromRaw(?string $raw): ?self
    {
        return self::tryFrom(strtolower(trim((string) $raw)));
    }
}
