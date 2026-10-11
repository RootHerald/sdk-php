<?php

declare(strict_types=1);

namespace Rootherald\Exceptions;

/**
 * The API key's budget cannot pay for a device new to the period (HTTP 429
 * with server code "budget_exhausted" or an X-RootHerald-Quota header).
 * {@see $budget} names the budget that refused. A 429 without that signal is
 * {@see RateLimitedException}.
 */
class QuotaExceededException extends HttpException
{
    public string $errorCode = 'budget_exhausted';

    /**
     * @param array{id: string, name: string}|null $budget the budget that refused, when the server named it
     */
    public function __construct(
        int $status,
        string $body,
        ?string $message = null,
        ?string $serverError = null,
        public readonly ?array $budget = null,
    ) {
        parent::__construct($status, $body, $message, $serverError);
    }
}
