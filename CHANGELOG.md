# Changelog

## Unreleased

### Added

- The challenge carries the ask. `Client::issueChallenge()` takes `ask`
  (`Client::ASK_IDENTITY` / `ASK_POSTURE` / `ASK_KEY`), `policy` and
  `keyPurpose` after the existing `deviceHint`; `Challenge` gains
  `$challenge`, the string to relay to the client verbatim. Omitting `ask`
  keeps the server default of identity + posture.
- `CertifiedKey`; `AttestResult::key()` returns the key the appraisal
  certified, present only on a passing verdict for a challenge that asked for
  `key`.
- `KeySignatures::verify(array $jwk, string $message, string $signature)`:
  local ECDSA verification of device signatures over SHA-256 (P-256) or
  SHA-384 (P-384) with ext-openssl, accepting raw `r||s` and DER. Returns
  `false` for any malformed signature. `ext-openssl` is now required.
- `Client::relayEnroll(array $blob, ?string $challengeId = null)` sends the
  `challengeId` query parameter so admission runs against that challenge's
  policy; `RelayEnrollResult::$challengeId` echoes it when the server does.
- `HttpException::$serverError` exposes the server's `error` code. New 422
  exceptions keyed on it: `PolicyDowngradeException` (`policy_downgrade`) and
  `AdmissionRefusedException` (`admission_refused`). Other 422s remain
  `UnknownPolicyException`.

### Fixed

- `samples/laravel-demo` used a `Rootherald\BackgroundCheck` class that does
  not exist; it now uses `Rootherald\Client` and shows the key flow.
- The README claimed `createChallenge()` / `attest()` survive as deprecated
  aliases. They never existed in this package.
