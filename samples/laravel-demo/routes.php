<?php

/**
 * Sample Laravel route registration for the Root Herald Background-Check client.
 *
 * Drop this snippet into your `routes/web.php` or `routes/api.php`.
 *
 *   ROOTHERALD_SECRET_KEY=rh_sk_... in .env
 */

use Illuminate\Support\Facades\Route;
use Rootherald\BackgroundCheck;
use Rootherald\Verdict;

/*
 * Background-Check (server -> server). The dumb client POSTs its opaque
 * evidence blob to YOUR server; your server appraises it with Root Herald using
 * the rh_sk_ secret key. The client never holds a key or calls Root Herald.
 */
Route::post('/attest', function () {
    $rh = new BackgroundCheck(secretKey: env('ROOTHERALD_SECRET_KEY'));

    // 1) mint a nonce (in production, hand $challenge->nonce to the client
    //    first, then receive the evidence it produced; compressed here).
    $challenge = $rh->issueChallenge();

    // 2) appraise the opaque evidence the client posted.
    $result = $rh->verify(
        evidence: (array) request()->input('evidence', []),
        challengeId: $challenge->challengeId,
    );

    if ($result->verdict !== Verdict::ALLOW) {
        // An un-enrolled / failing device is a verdict, not an error.
        abort(403, 'attestation denied');
    }
    return ['ok' => true, 'verdict' => $result->verdict->value];
});
