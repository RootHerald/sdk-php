# Changelog

## Unreleased

Wire 8.0. Every installation of a client has its own attestation key, created
inside the TPM at enrollment and handed back as an opaque AK blob the client
keeps and passes to every attest and mint. Keys are minted in their own
ceremony. A backend on this version cannot drive a 7.0 client, and the
reverse; the server refuses a 7.0-shaped enroll body with
`400 wire_version_unsupported`.

### Breaking

- `Client::relayEnroll()` takes the 8.0 TPM body `{ ekPublicKey,
  attestationKey: { publicArea, parentPublicArea, qualifiedName }, platform,
  … }` and refuses a flat `akPublicArea` TPM body, a missing or unknown
  `platform`, locally with `\InvalidArgumentException`. The macOS body stays
  flat and the iOS body is unchanged; every body is relayed verbatim, unknown
  fields included.
- Keys are minted by `Client::issueKeyChallenge(string $purpose, ?array
  $expectedDevices = null): KeyChallenge` (`Client::PURPOSE_SIGN` /
  `PURPOSE_DECRYPT`) and `Client::certifyKey(array $certification, string
  $nonce): CertifiedKey`. `Client::ASK_KEY`, `Client::KEY_PURPOSE_SIGN`, the
  `keyPurpose` parameter and `AttestResult::key()` are removed; a challenge
  that still asks for `"key"` raises `InvalidAskException` (400
  `invalid_ask`).
- `Client::issueChallenge(?array $ask = null, ?string $expectedKey = null,
  ?array $expectedDevices = null)` no longer takes `deviceHint`. The
  parameter is gone outright, not kept as an ignored slot: each 7.0
  positional value (`deviceHint` string, `keyPurpose` string in the third
  slot) now meets a parameter of another type and fails with `TypeError`
  before any request, so a stray `'sign'` can never land in `expectedKey`.
  Call it with named arguments.
- `Client::verify()` takes `expectedKey` and `expectedDevices` after
  `requestedDisclosureClass`. Pass the values the challenge was issued with:
  a verdict that does not echo them under `expected` is refused with
  `ExpectedNotEnforcedException`. `AttestResult::expected()` returns the
  echo; `AttestResult::deviceId()` returns `verdict.device.ueid`.
- `CertifiedKey` is `deviceId`, `keyId`, `purpose`, `alg` (`ES256` /
  `RS256` / `ECDH-ES` / `RSA-OAEP-256`), `jwk` (EC P-256 or RSA),
  `hardwareBound`, `certifiedAt`, `format` (decrypt keys only).
  `authPolicy` is gone. A JWK whose family does not fit `alg` is refused.
- `KeySignatures::verify()` accepts an RSA JWK (`kty` RSA, `n`, `e`) as RS256
  (PKCS#1 v1.5 over SHA-256, modulus at least 2048 bits, signature exactly
  the modulus length) beside EC P-256 as ES256. P-384 is no longer accepted:
  no device certifies one.
- A 429 `budget_exhausted` is `QuotaExceededException` with `$budget`
  (`['id', 'name']`); its `errorCode` is `budget_exhausted` and the
  `quota_exceeded` code is gone. A 409 `key_rotation_conflict` is a plain
  `HttpException`, not `ChallengeException`.

### Migration

1. Re-enroll every installation: the client's `EnrollBegin` now returns an
   AK blob, which the client keeps and passes to `Attest` and `MintKey`.
2. Replace `issueChallenge(ask: [ASK_IDENTITY, ASK_KEY], keyPurpose:
   KEY_PURPOSE_SIGN)` plus `$result->key()` with
   `issueKeyChallenge(PURPOSE_SIGN, expectedDevices: [$alias])` and
   `certifyKey($certification, $nonce)`.
3. Drop `deviceHint`; bind a challenge to a device with `expectedDevices`,
   and pass the same value to `verify`.
4. Read `$key->deviceId` to tie the key to the account; `$key->jwk` may be
   RSA.

## Unreleased, wire 7.0 (superseded by the entry above)

### Changed

- `Verdict` is the server's own token: `Verdict::PASS` / `Verdict::WARN` /
  `Verdict::FAIL` (`"pass"` / `"warn"` / `"fail"`) replace `ALLOW` / `WARN` /
  `DENY`, the same vocabulary as every other Root Herald SDK.
  `Verdict::fromRaw()` returns null for any other token and `Client::verify()`
  then throws `HttpException` instead of reading it as `WARN`;
  `Verdict::fromEarStatus()` is removed.
- `AttestResult::key()` is passed through as the server sent it; the server
  withholds it when it must.
- An empty nonce on `Client::verify()` raises `\InvalidArgumentException`,
  not `ChallengeException`; no request is made.
- A 401 carrying `activation_refused` is `ActivationRefusedException`, not
  `InvalidSecretKeyException`. A 429 without `quota_exceeded` or an
  `X-RootHerald-Quota` header is `RateLimitedException`, with
  `$retryAfterSeconds`, not `QuotaExceededException`. A 422 whose code is
  neither `unknown_policy` nor `admission_refused` (`posture_not_bound`) is
  a plain `HttpException` with the code preserved.
- The default timeout is 30 s (`Client::DEFAULT_TIMEOUT_SECONDS`), was 10 s.
- An `httpTransport` may return a `headers` array alongside `status` and
  `body`; the built-in curl transport does.
- `CertifiedKey::$authPolicy` is documented as hex, which is what the server
  sends.

- Wire 7.0: nothing the SDK sends locates a row. `Challenge` is `nonce`,
  `challenge`, `expiresAt`; `challengeId` is gone. `Client::verify()` takes
  `nonce`, the handle from `issueChallenge`, in place of `challengeId`; an
  empty one raises `ChallengeException` before any request is made.
- `Client::relayEnroll(array $blob)` takes no challenge id and sends no query
  string. It returns `RelayEnrollResult { challenge }` only; `deviceId` and
  `challengeId` are gone from the result. `EnrollChallenge` is `enrollmentId`
  plus `credentialBlob` + `encryptedSecret` (TPM) or `challengeNonce`
  (macOS); a 201 without them raises `HttpException`. An iOS blob
  (`platform: "ios"`) needs `iosKeyId`, `iosAttestationObject` and `nonce`,
  and its empty 201 yields a null `challenge`.
- `Client::relayActivate()` requires `enrollmentId` and one of
  `decryptedSecret` / `signature`; a blob keyed by `deviceId` is refused. The
  result is unchanged: `deviceId` is the tenant alias, for the backend only.

### Removed

- Policies bind to API keys. The `policy` parameter is gone from
  `Client::issueChallenge()` and `Client::verify()`; the server refuses the
  field with `400 policy_bound_to_key`. Bind a policy to the key from the
  dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`.
- `PolicyDowngradeException` is removed with the parameter that produced it.
  `UnknownPolicyException` (422 `unknown_policy`) now means a policy bound to
  the key no longer exists.

### Added

- The challenge carries the ask. `Client::issueChallenge()` takes `ask`
  (`Client::ASK_IDENTITY` / `ASK_POSTURE` / `ASK_KEY`) and `keyPurpose`
  after the existing `deviceHint`; `Challenge` gains
  `$challenge`, the string to relay to the client verbatim. Omitting `ask`
  keeps the server default of identity + posture.
- `CertifiedKey`; `AttestResult::key()` returns the key the appraisal
  certified, present only on a passing verdict for a challenge that asked for
  `key`.
- `KeySignatures::verify(array $jwk, string $message, string $signature)`:
  local ECDSA verification of device signatures over SHA-256 (P-256) or
  SHA-384 (P-384) with ext-openssl, accepting raw `r||s` and DER. Returns
  `false` for any malformed signature. `ext-openssl` is now required.
- `HttpException::$serverError` exposes the server's `error` code. A 422
  with `admission_refused` raises `AdmissionRefusedException`; other 422s
  remain `UnknownPolicyException`.

### Fixed

- `samples/laravel-demo` used a `Rootherald\BackgroundCheck` class that does
  not exist; it now uses `Rootherald\Client` and shows the key flow.
- The README claimed `createChallenge()` / `attest()` survive as deprecated
  aliases. They never existed in this package.
