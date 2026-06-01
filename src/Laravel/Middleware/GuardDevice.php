<?php

declare(strict_types=1);

namespace Rootherald\Laravel\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Rootherald\Client;
use Rootherald\Exceptions\TokenExpiredException;
use Rootherald\Exceptions\VerificationException;
use Rootherald\Verdict;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware: verify the attestation token attached to a request
 * before allowing the route handler to run.
 *
 * Wire up via the service provider, then attach with the alias:
 *
 *     Route::post('/signup', SignupController::class)
 *         ->middleware(['rootherald.guard:signup']);
 *
 * The verified {@see \Rootherald\AttestationClaims} is stashed on the
 * request attribute bag under `rootherald_claims`.
 */
class GuardDevice
{
    public function __construct(public readonly Client $client)
    {
    }

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next, ?string $action = null, ?string $mode = null): Response
    {
        $token = $this->extractToken($request);
        if ($token === null) {
            return new JsonResponse(['error' => 'missing_attestation_token'], 401);
        }

        try {
            $claims = $this->client->verifyToken($token);
        } catch (TokenExpiredException) {
            return new JsonResponse(['error' => 'token_expired'], 401);
        } catch (VerificationException $e) {
            return new JsonResponse(['error' => 'token_invalid', 'message' => $e->getMessage()], 401);
        }

        if ($claims->verdict === Verdict::DENY) {
            return new JsonResponse(['error' => 'device_denied', 'action' => $action], 403);
        }
        if ($mode === 'strict' && $claims->verdict === Verdict::WARN) {
            return new JsonResponse(['error' => 'device_warned', 'action' => $action], 403);
        }

        $request->attributes->set('rootherald_claims', $claims);
        return $next($request);
    }

    private function extractToken(Request $request): ?string
    {
        $auth = (string) $request->header('Authorization', '');
        if (str_starts_with(strtolower($auth), 'bearer ')) {
            return trim(substr($auth, 7));
        }
        $hdr = (string) $request->header('X-RootHerald-Token', '');
        return $hdr !== '' ? $hdr : null;
    }
}
