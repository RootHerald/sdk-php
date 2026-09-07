<?php

/**
 * Sample Laravel route registration for the Root Herald server -> server flow
 * with a certified device key.
 *
 * Drop this snippet into your `routes/web.php` or `routes/api.php`.
 *
 *   ROOTHERALD_SECRET_KEY=rh_sk_... in .env
 */

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Rootherald\Client;
use Rootherald\KeySignatures;
use Rootherald\Verdict;

$rh = new Client(secretKey: env('ROOTHERALD_SECRET_KEY'));

/*
 * 1) Mint a challenge that carries the ask — identity, posture and a signing
 *    key — and hand `challenge` to the client verbatim. What the device must
 *    prove is fixed here, not at verify time.
 */
Route::post('/challenge', function () use ($rh) {
    $challenge = $rh->issueChallenge(
        ask: [Client::ASK_IDENTITY, Client::ASK_POSTURE, Client::ASK_KEY],
        keyPurpose: Client::KEY_PURPOSE_SIGN,
    );

    return [
        'challengeId' => $challenge->challengeId,
        'challenge' => $challenge->challenge,
        'expiresAt' => $challenge->expiresAt,
    ];
});

/*
 * 2) The client quoted over the challenge and POSTs its opaque evidence blob
 *    here with the challenge id; this server appraises it with the rh_sk_
 *    secret key. The client never holds a key or calls Root Herald.
 */
Route::post('/attest', function () use ($rh) {
    $result = $rh->verify(
        evidence: (array) request()->input('evidence', []),
        challengeId: (string) request()->input('challengeId'),
    );

    if ($result->verdict !== Verdict::ALLOW) {
        // An un-enrolled / failing device is a verdict, not an error.
        abort(403, 'attestation denied');
    }

    // The key is present only on a pass for a challenge that asked for one.
    // A real app stores it against the user; the cache stands in here.
    $key = $result->key();
    if ($key !== null) {
        Cache::put("rootherald:key:{$key->keyId}", $key->jwk);
    }

    return ['ok' => true, 'verdict' => $result->verdict->value, 'keyId' => $key?->keyId];
});

/*
 * 3) Later, the device signs something with its TPM-resident key. Check it
 *    against the JWK from the attestation — locally, no Root Herald call.
 *    `message` and `signature` are base64; the signature may be raw r||s or DER.
 */
Route::post('/verify-signature', function () {
    $jwk = Cache::get('rootherald:key:' . (string) request()->input('keyId'));
    if (!is_array($jwk)) {
        abort(404, 'unknown keyId');
    }

    $valid = KeySignatures::verify(
        $jwk,
        (string) base64_decode((string) request()->input('message'), true),
        (string) base64_decode((string) request()->input('signature'), true),
    );

    return response(['valid' => $valid], $valid ? 200 : 403);
});
