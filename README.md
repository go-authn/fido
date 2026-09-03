# fido

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/fido.svg)](https://pkg.go.dev/github.com/go-authn/fido)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/fido/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/fido/actions/workflows/ci.yml)

Speaks the FIDO client-to-authenticator protocol to a security key, in pure Go
with `CGO_ENABLED=0`, on any operating system.

```go
k, err := fido.Open(ctx, transport)   // handshake, channel, capabilities
defer k.Close()
fmt.Println(k)                        // YubiKey FIDO (CTAPHID v2, firmware 5.7.4, wink, ctap2, ctap1)
err = k.Wink(ctx)                     // the key blinks: which one is this?
```

Nothing here is platform-specific. A `Transport` moves 64-byte reports to and
from one authenticator, and where those come from — IOKit on macOS, hidraw on
Linux, WebHID in a browser — is somebody else's problem. The macOS one is
[go-macos/fido](https://github.com/go-macos/fido).

## The second factor

An operating system already offers the first: Touch ID, a watch, a passcode.
Those answer *is the person at this machine the one who unlocked it?* A security
key answers a different question: *is the thing they carry present, right now,
and did a human touch it?* Multi-factor means asking both and getting two
independent answers.

## Reading the reference first

In pure Go, client-side, there was nothing to reuse. The reference of the field
is Yubico's **libfido2**, written in C; its one serious Go binding wraps it
through cgo and has not moved in ten months, and the pure-Go candidates are
small and young. So libfido2 and the CTAP specification are read here as
**documentation**, and the code is owned.

Reading them first caught two faults that testing against a key would not have,
because a short ping comes back the same either way:

- **`CTAPHID_KEEPALIVE` is not an answer.** A key waiting for a finger sends one
  about every hundred milliseconds for as long as the person takes. A reader
  that returns the first complete message hands back a status byte instead of
  the reply — and does it early, so it reads as the key talking nonsense rather
  than as a missing feature.
- **The message limit is the framing's, not the length field's.** Two length
  bytes would allow 65535; the framing reaches 7609, because past that the
  sequence numbers run into the high bit and a key reads them as the start of a
  new message. An earlier draft used 65535 and carried a comment asserting the
  framing reached it. The arithmetic was wrong.

## What is here

The CTAPHID framing, the handshake, channel negotiation, capabilities, ping and
wink — covered to 100%, with a fake transport that reassembles what it is sent,
so a key that refuses, a key that stalls, a key that keeps saying it is busy and
another program talking on the same key are all ordinary tests.

`GetInfo` asks a CTAP2 authenticator to describe itself -- versions,
extensions, AAGUID, options -- and is decoded against a reply CAPTURED FROM A
REAL KEY rather than one written by hand from the specification. A fixture
written from the spec only proves the code agrees with whoever wrote the
fixture.

CBOR comes from [fxamacker/cbor](https://github.com/fxamacker/cbor), which is
what `go-webauthn/webauthn` depends on and which ships `CTAP2EncOptions` for
exactly this. Unlike the CTAP client space, CBOR in Go has a reference, so this
uses it.

`MakeCredential` registers a credential and `GetAssertion` asks the
authenticator to sign, with the parameters numbered as the specification
numbers them and the authenticator data parsed -- flags, sign count, credential
id, COSE public key, extensions.

The authenticator-data parser is checked against a sample from
**go-webauthn/webauthn's own tests**: an EXTERNAL witness. Every other fixture
here came from hardware or from this code, so it is the only one that can catch
those two agreeing with each other and both being wrong. It caught something
immediately -- the prose describing that sample says its flags are `0x45`, and
the bytes say `0x41`. The bytes win.

`AuthData.PublicKey` turns the credential's COSE key into a `*ecdsa.PublicKey`,
so a caller can check the signature with the standard library and nothing else.
That is a CONVERSION, not a verification: what counts as valid -- which
algorithms, what to do about a sign counter that went backwards -- belongs to
whoever is protecting something.

All of it has been run against a real YubiKey FIDO 5.7.4: registered, asserted,
and the signature verified against the public key the key itself handed out.

`ClientPIN` is here: both PIN/UV auth protocols, `PINRetries`, `KeyAgreement`
and `PINToken`, and a token wires into `MakeCredential` and `GetAssertion` to
turn "somebody touched the key" into "somebody who knows its PIN touched it".

The two protocols are not a version number. Protocol one hashes the ECDH output
once and uses the same 32 bytes as both AES and HMAC key, with a zero
initialisation vector and a 16-byte truncated HMAC; protocol two derives two
separate keys through HKDF, prepends a fresh IV, and truncates nothing. A
package that treated them as interchangeable would pass every round-trip test
and be wrong on the wire, so a test plays the AUTHENTICATOR's side and checks
that both sides derive the same secret.

The status-code table comes from libfido2's `err.h`, and it had to: an earlier
version was written from memory and five of its entries were wrong. A real key
caught it by answering `0x35` -- no PIN set -- which the table did not name
while claiming `0x2F` meant that.
