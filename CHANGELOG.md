# Changelog

## v0.6.4

- Fixed: `PINToken` with permissions sent `permissions` under key 0x07 and
  `rpId` under 0x08. CTAP 2.1 (6.5.5, authenticatorClientPIN) numbers them 0x09
  and 0x0A and has no 0x07 or 0x08; a YubiKey 5 answered
  `CTAP2_ERR_MISSING_PARAMETER` (0x14) (#21). No other field of the request
  used those keys (keyAgreement 0x03, pinHashEnc 0x06), so nothing collided.
  The fake authenticator now reads the keys as literals from the specification,
  and a test checks the request's map keys against its table.
