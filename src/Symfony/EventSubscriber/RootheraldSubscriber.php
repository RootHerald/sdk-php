<?php

declare(strict_types=1);

namespace Rootherald\Symfony\EventSubscriber;

use Rootherald\Client;
use Rootherald\Exceptions\TokenExpiredException;
use Rootherald\Exceptions\VerificationException;
use Rootherald\Verdict;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Symfony event subscriber: verifies the attestation token on requests whose
 * controller is decorated with `#[Rootherald]` or that match a configured
 * route prefix.
 *
 * Minimal implementation — routes opt in by setting a request attribute
 * `_rootherald_action`. A small controller attribute / annotation can flip
 * this in real apps; we keep the dependency footprint to symfony/http-kernel
 * + symfony/event-dispatcher.
 */
class RootheraldSubscriber implements EventSubscriberInterface
{
    public function __construct(
        public readonly Client $client,
        public readonly bool $denyOnWarn = false,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER => 'onKernelController',
        ];
    }

    public function onKernelController(ControllerEvent $event): void
    {
        $request = $event->getRequest();
        $action = $request->attributes->get('_rootherald_action');
        if ($action === null) {
            return; // Route is not guarded.
        }

        $auth = (string) $request->headers->get('Authorization', '');
        $token = str_starts_with(strtolower($auth), 'bearer ')
            ? trim(substr($auth, 7))
            : (string) $request->headers->get('X-RootHerald-Token', '');

        if ($token === '') {
            $event->setController(static fn () => new JsonResponse(['error' => 'missing_attestation_token'], 401));
            return;
        }

        try {
            $claims = $this->client->verifyToken($token);
        } catch (TokenExpiredException) {
            $event->setController(static fn () => new JsonResponse(['error' => 'token_expired'], 401));
            return;
        } catch (VerificationException $e) {
            $event->setController(static fn () => new JsonResponse(
                ['error' => 'token_invalid', 'message' => $e->getMessage()],
                401,
            ));
            return;
        }

        if ($claims->verdict === Verdict::DENY) {
            $event->setController(static fn () => new JsonResponse(['error' => 'device_denied'], 403));
            return;
        }
        if ($this->denyOnWarn && $claims->verdict === Verdict::WARN) {
            $event->setController(static fn () => new JsonResponse(['error' => 'device_warned'], 403));
            return;
        }

        $request->attributes->set('rootherald_claims', $claims);
    }
}
