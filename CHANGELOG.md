# Changelog

## Unreleased

### Changed

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
