# Changelog

## v0.10.0

- Added: `Key.SetPIN` and `Key.ChangePIN` (clientPIN subcommands 0x03 and
  0x04, CTAP 2.1 6.5.5.5 and 6.5.5.6): newPinEnc is the PIN padded to 64 bytes
  and encrypted, pinUvAuthParam covers newPinEnc (setPIN) or newPinEnc then
  pinHashEnc (changePIN). `CheckNewPIN` applies the platform's length rules
  (minPINLength, 63 bytes of UTF-8) before any exchange. `Info.MinPINLength`
  (0x0D) and `Info.ForcePINChange` (0x0C).
- Added: fingerprint enrollment, authenticatorBioEnrollment (6.7): `Key.Bio`
  returns a `Bio` with `SensorInfo`, `EnrollBegin`, `EnrollNext`,
  `EnrollCancel`, `Enroll` (the whole loop, cancelling on failure, at most 256
  rounds), `Enumerate`, `Rename`, `Remove`; `Info.BioMode` picks command 0x09
  (`bioEnroll`) or the prototype command 0x40 (`userVerificationMgmtPreview`,
  libfido2's value; the CTAP 2.1 PS text printed 0x41). `SampleStatus` names
  lastEnrollSampleStatus. Statuses named: `StatusPINAuthInvalid`,
  `StatusInvalidOption`.
- Tests: the software authenticator implements setPIN, changePIN and bio
  enrollment, checking the MACed bytes; fuzz targets for the bio replies and
  the PIN rules. Not run against a real key.

## v0.9.0

- Added: `StatusError`. A refused CTAP2 command now returns `*StatusError`,
  so `errors.As` gives its `Status` instead of the caller matching text. The
  message is unchanged. Named statuses: `StatusOperationDenied`,
  `StatusNoCredentials`, `StatusUserActionTimeout`, `StatusPINInvalid`,
  `StatusPINBlocked`, `StatusPINAuthBlocked`.

## v0.8.0

- Added: `Key.GetAssertions` and `CmdGetNextAssertion` (0x08). One getAssertion
  then authenticatorGetNextAssertion for every further credential announced
  (CTAP 2.1 §6.3), newest first, bounded by the caller. A next assertion's
  hmac-secret output is decrypted with the first request's session when it is
  present, and is nil when absent (§6.3 does not promise it).
- Tests: the software authenticator walks its list, in both behaviours (with
  and without outputs on next assertions), and lies about its count.

## v0.7.0

- Added: the `extensions` parameter of makeCredential (`Extensions`) and
  getAssertion (`GetAssertionRequest.Extensions`), and the extension outputs of
  the authenticator data (`AuthData.ExtensionOutputs`).
- Added: `hmac-secret` (CTAP 2.1, 12.5) under both PIN/UV auth protocols, one or
  two salts (`GetAssertionRequest.HMACSecret`, `Assertion.HMACSecret`).
  `HMACSecret.RequireUV` refuses to return a secret the authenticator derived
  without user verification, which is a different secret and is otherwise
  indistinguishable. Salts, protocol and policy are the caller's.
- Added: `credProtect` (12.1), policies 1, 2 and 3.
- Added: `Key.UVToken`, getPinUvAuthTokenUsingUvWithPermissions (6.5.5.7.3,
  subcommand 0x06), `Key.UVRetries`, `Key.SelectPINProtocol`, the remaining
  permission constants, and the names of statuses 0x3c, 0x3e and 0x3f.
- Tests: a software CTAP 2.1 authenticator written from the specification
  (virtual_test.go) reproduces two traps: the unverified hmac-secret is another
  secret, and a credProtect 3 credential answers "no credentials" to an
  unverified probe. New fuzz targets with a committed corpus.

## v0.6.4

- Fixed: `PINToken` with permissions sent `permissions` under key 0x07 and
  `rpId` under 0x08. CTAP 2.1 (6.5.5, authenticatorClientPIN) numbers them 0x09
  and 0x0A and has no 0x07 or 0x08; a YubiKey 5 answered
  `CTAP2_ERR_MISSING_PARAMETER` (0x14) (#21). No other field of the request
  used those keys (keyAgreement 0x03, pinHashEnc 0x06), so nothing collided.
  The fake authenticator now reads the keys as literals from the specification,
  and a test checks the request's map keys against its table.
