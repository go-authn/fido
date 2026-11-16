# Changelog

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
