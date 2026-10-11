<?php

/**
 * Sample Laravel route registration for the Root Herald server -> server flow
 * with a device-bound signing key.
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
 * 1) Mint a challenge that carries the ask and hand `challenge` to the client
 *    verbatim. What the device must prove is fixed here, not at verify time.
 */
Route::post('/challenge', function () use ($rh) {
    $challenge = $rh->issueChallenge(ask: [Client::ASK_IDENTITY]);

    return [
        'nonce' => $challenge->nonce,
        'challenge' => $challenge->challenge,
        'expiresAt' => $challenge->expiresAt,
    ];
});

/*
 * 2) The client quoted over the challenge and POSTs its opaque evidence blob
 *    here with the nonce; this server appraises it with the rh_sk_ secret
 *    key. The client never holds a key or calls Root Herald. On a pass, mint
 *    a key challenge bound to the device that just answered.
 */
Route::post('/attest', function () use ($rh) {
    $result = $rh->verify(
        evidence: (array) request()->input('evidence', []),
        nonce: (string) request()->input('nonce'),
    );

    if ($result->verdict !== Verdict::PASS) {
        // An un-enrolled / failing device is a verdict, not an error.
        abort(403, 'attestation denied');
    }

    $keyChallenge = $rh->issueKeyChallenge(Client::PURPOSE_SIGN, expectedDevices: [$result->deviceId()]);

    return [
        'ok' => true,
        'deviceId' => $result->deviceId(),
        'nonce' => $keyChallenge->nonce,
        'keyChallenge' => $keyChallenge->keyChallenge,
    ];
});

/*
 * 3) The client's MintKey answered the key challenge with a certification and
 *    kept its key blob. Relay the certification; Root Herald returns the
 *    public half. A real app stores it against the user; the cache stands in.
 */
Route::post('/certify', function () use ($rh) {
    $key = $rh->certifyKey(
        certification: (array) request()->input('certification', []),
        nonce: (string) request()->input('nonce'),
    );

    Cache::put("rootherald:key:{$key->deviceId}", $key->jwk);

    return ['keyId' => $key->keyId, 'alg' => $key->alg, 'hardwareBound' => $key->hardwareBound];
});

/*
 * 4) Later, the device signs something with its key. Check it against the
 *    JWK from the certification — locally, no Root Herald call.
 *    `message` and `signature` are base64; an ES256 signature may be raw
 *    r||s or DER, an RS256 signature is PKCS#1 v1.5.
 */
Route::post('/verify-signature', function () {
    $jwk = Cache::get('rootherald:key:' . (string) request()->input('deviceId'));
    if (!is_array($jwk)) {
        abort(404, 'unknown device');
    }

    $valid = KeySignatures::verify(
        $jwk,
        (string) base64_decode((string) request()->input('message'), true),
        (string) base64_decode((string) request()->input('signature'), true),
    );

    return response(['valid' => $valid], $valid ? 200 : 403);
});
