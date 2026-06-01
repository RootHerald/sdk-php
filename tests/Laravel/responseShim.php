<?php

declare(strict_types=1);

use Illuminate\Http\JsonResponse;

/**
 * Tiny shim of Laravel's `response()` helper used by
 * {@see \Rootherald\Laravel\Middleware\GuardDevice}. Provided only when the
 * test runs without a fully-booted Laravel application.
 *
 * @return object{json: callable}
 */
function response()
{
    return new class () {
        public function json(mixed $data = null, int $status = 200): JsonResponse
        {
            return new JsonResponse($data, $status);
        }
    };
}
