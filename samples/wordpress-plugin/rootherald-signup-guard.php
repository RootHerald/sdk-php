<?php
/**
 * Plugin Name: Root Herald Signup Guard
 * Description: Blocks WordPress user registration unless a valid Root Herald attestation token is provided.
 * Version: 0.1.0
 * Author: Root Herald
 * License: Apache-2.0
 *
 * Install:
 *   1. Run `composer require rootherald/rootherald` in your WordPress root.
 *   2. Drop this file into `wp-content/plugins/rootherald-signup-guard/`.
 *   3. Activate via the WP admin.
 *   4. Set `ROOTHERALD_ISSUER` in `wp-config.php`.
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once ABSPATH . 'vendor/autoload.php';

use Rootherald\Client;
use Rootherald\Exceptions\TokenExpiredException;
use Rootherald\Exceptions\VerificationException;
use Rootherald\Verdict;

/**
 * Resolve a singleton Client lazily. WordPress is fork-based; we don't
 * want to construct one per request unless we hit a registration.
 */
function rootherald_client(): Client
{
    static $client = null;
    if ($client === null) {
        $issuer = defined('ROOTHERALD_ISSUER')
            ? ROOTHERALD_ISSUER
            : getenv('ROOTHERALD_ISSUER');
        if (!$issuer) {
            wp_die('Root Herald not configured: ROOTHERALD_ISSUER is missing.');
        }
        $client = new Client(
            issuer: (string) $issuer,
            apiKey: defined('ROOTHERALD_API_KEY') ? ROOTHERALD_API_KEY : null,
            jwksUri: defined('ROOTHERALD_JWKS_URI')
                ? ROOTHERALD_JWKS_URI
                : 'https://rootherald.io/.well-known/jwks.json',
        );
    }
    return $client;
}

/**
 * Hook into WP's user registration. WordPress calls `register_post` (and
 * `register_new_user`) when a new account is being created — we intercept
 * here to reject if the request doesn't carry a valid attestation token.
 */
add_action('register_post', static function ($sanitized_user_login, $user_email, $errors): void {
    $token = $_POST['rootherald_token'] ?? '';
    if (!is_string($token) || $token === '') {
        $errors->add('rootherald_missing', __('Device attestation token is required.', 'rootherald'));
        return;
    }
    try {
        $claims = rootherald_client()->verifyToken((string) $token);
    } catch (TokenExpiredException) {
        $errors->add('rootherald_expired', __('Attestation token expired — please retry.', 'rootherald'));
        return;
    } catch (VerificationException $e) {
        $errors->add('rootherald_invalid', __('Attestation invalid: ', 'rootherald') . esc_html($e->getMessage()));
        return;
    }

    if ($claims->verdict === Verdict::DENY) {
        $errors->add('rootherald_denied', __('Device not permitted to register.', 'rootherald'));
    }
}, 10, 3);
