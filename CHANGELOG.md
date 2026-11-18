# Changelog

## v0.12.0

- Added: a name stored ON the key, so it follows the key across ports and
  machines. `Key.SetName`, `Key.ReadName`, `Key.RemoveName`, `Key.NameTokens`,
  `CheckName`, `DecodeName`, `NameRP` ("name.fido"), `MaxNameBytes` (64), and the
  errors `ErrNoName`, `ErrNameRefused`, `ErrNameAmbiguous`. The name is the user
  handle of a discoverable credential under `name.fido`, credProtect level 1.
  It is read with NO touch and NO PIN: getAssertion with `up` false and no
  pinUvAuthParam (CTAP 2.1 6.2.2: step 9 is skipped for up=false; alwaysUv,
  7.2.3 and step 5, bites only when up is true; credProtect 1 is not filtered
  without verification, 7.4 and 7.5; `user.id` is returned, only name,
  displayName and icon are withheld, 12.3). A key that refuses anyway is
  `ErrNameRefused` so a caller can fall back. `SetName` deletes the old name
  FIRST and makes the new one after: the key never holds two, and a failure
  leaves it with none.
- Added: authenticatorCredentialManagement (6.8): `Key.CredMgmt` with
  `Credentials` (enumerateCredentialsBegin and the rest) and `Delete`;
  `Info.CredMgmtMode` picks command 0x0A (`credMgmt`, token with the cm
  permission, bound to no relying party) or the prototype 0x41
  (`credentialMgmtPreview`, a plain getPinToken token).
- Tests: the software authenticator holds several tokens, implements credential
  management and an alwaysUv policy, and can refuse the silent read; fuzz
  targets for name decoding and credential management replies. Not run against a
  real key.

## v0.11.0

- Added: `Select(ctx, []Candidate)`: with several keys attached, ask every one
  for a touch at once and return the first touched (`Selected`). The others are
  sent CTAPHID_CANCEL (`Key.Cancel`) and closed. The request is
  authenticatorSelection (CTAP 2.1 6.9, `CmdSelection`) on a FIDO_2_1 key and,
  as libfido2's touch.c does, a makeCredential with an empty pinUvAuthParam on a
  2.0 key that takes a PIN; a 2.0 key with no PIN cannot be chosen without
  making a credential on it and is reported as an error. Every key's own failure
  is listed (`SelectError`, `Selected.Failures`); keys touched in the same
  instant are named in `Selected.AlsoTouched`; nothing touched is the context's
  error, never another key.
- Added: `Key.Identity`: what a key says about itself without a touch (aaguid,
  PIN set or not, fingerprints enrolled or not), to tell several apart.

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
