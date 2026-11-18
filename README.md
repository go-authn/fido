# fido

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/fido.svg)](https://pkg.go.dev/github.com/go-authn/fido)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/fido/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/fido/actions/workflows/ci.yml)

Speaks the FIDO client-to-authenticator protocol to a security key, in pure Go
with `CGO_ENABLED=0`, on any operating system.

```go
k, err := fido.Open(ctx, transport)   // handshake, channel, capabilities
defer k.Close()
fmt.Println(k)                        // YubiKey FIDO (CTAPHID v2, firmware 5.7.4, wink, ctap2, ctap1) on channel 0x…
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

A key is not trusted to answer what it was asked, either. A reply is refused
unless it carries the command that was sent (CTAP 2.1 §11.2.9 gives each
command's response its own `CMD`, and libfido2 checks it too). A PIN token is
refused unless it has its protocol's length: 16 or 32 bytes under protocol
one, exactly 32 under protocol two (§6.5.6, §6.5.7). Both checks came from a
security review: neither had a demonstrated impact, but nothing else stood
between what a forged key sends and the parser that reads it.

## What is here

The CTAPHID framing, the handshake, channel negotiation, capabilities, ping and
wink — covered to 100%, with a fake transport that reassembles what it is sent,
so a key that refuses, a key that stalls, a key that keeps saying it is busy and
another program talking on the same key are all ordinary tests.

The framing is exported for whoever drives a key some other way: `Split` cuts a
message into 64-byte reports, `NewReassembler` and `Reassembler.Feed` put
replies back together into a `Message`, `ParseInit` reads the `INIT` reply, and
`Key.CBOR` sends a raw CTAP2 command and returns the body, a failing `Status`
turned into an error. go-authn/keyfactor's tests drive their fake key with exactly these.

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

`authenticatorClientPIN` (`CmdClientPIN`) is here: both PIN/UV auth protocols, `PINRetries`, `KeyAgreement`
and `PINToken`, and a token wires into `MakeCredential` and `GetAssertion` to
turn "somebody touched the key" into "somebody who knows its PIN touched it".

`PINToken` with permissions sends the permissions at key 0x09 and the RP id at 0x0A, as
CTAP 2.1 (6.5.5) numbers them; before v0.6.4 it used 0x07 and 0x08, which a
YubiKey answers with `CTAP2_ERR_MISSING_PARAMETER`. A test checks the request's
map keys against the specification's table.

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

## Extensions, hmac-secret, credProtect and built-in verification

`MakeCredentialRequest.Extensions` and `GetAssertionRequest.Extensions` carry
the `extensions` parameter, and `AuthData.ExtensionOutputs` reads what comes
back. `hmac-secret` (CTAP 2.1, 12.5) works under both PIN/UV auth protocols:
register with `Extensions{HMACSecret: true}`, then ask for one or two secrets
with `GetAssertionRequest.HMACSecret` (32-byte salts) and read
`Assertion.HMACSecret`. `credProtect` takes the policies 1, 2 and 3.

`Key.UVToken` obtains a pinUvAuthToken by built-in user verification, such as a
fingerprint sensor (getPinUvAuthTokenUsingUvWithPermissions, subcommand 0x06);
`Key.PINToken` is the PIN alternative, and either token goes into the same
request.

Two traps are covered by tests against a software authenticator written from
the specification (and, with `FIDO_REAL=1`, by go-macos/fido's test on a real
key): an authenticator derives a DIFFERENT hmac-secret for a verified request
than for an unverified one, with nothing in the output to tell them apart, so
`HMACSecret.RequireUV` refuses to return the unverified one; and a credProtect 3
credential answers "no credentials" to a probe made before verification, so
verify first. Which salts, which protocol, and whether a PIN is accepted in
place of a finger are the caller's choices; this package encodes and decodes.

## Setting a PIN, and enrolling fingerprints

`Key.SetPIN` (key has no PIN) and `Key.ChangePIN` implement clientPIN
subcommands 0x03 and 0x04 (CTAP 2.1 6.5.5.5 and 6.5.5.6); give them
`Info.MinPINLength` so a PIN the key would refuse costs no exchange.
`Info.ForcePINChange` says the PIN must be changed before it is used again.

`Key.Bio(info)` drives authenticatorBioEnrollment (6.7) on a key that declares
`bioEnroll` (command 0x09, token with `PermBioEnrollment`) or the prototype
`userVerificationMgmtPreview` (command 0x40, a plain getPinToken token):

```go
b, _ := k.Bio(info)
tok, _ := k.PINToken(ctx, pin, proto, b.Permissions(), "")
id, err := b.Enroll(ctx, tok, 0, func(s fido.EnrollStep) {
	fmt.Println(s.Status, s.Remaining, "samples left")
})
b.Rename(ctx, tok, id, "right index")
```

A bad sample (finger too fast, off-centre, not lifted) does not count and the
loop asks again; an enrollment that fails or is cancelled is cancelled on the
key. Tested against a software authenticator that checks the MACed bytes; not
run against a real key.

## Several keys: choose, never "the first"

The transports list keys (`go-macos/fido` and `go-gnulinux/fido`:
`Devices`/`OpenDevice`), and `Select` chooses among them by touch: every key is
asked for user presence at once (authenticatorSelection, CTAP 2.1 6.9), the
first touched wins and the rest get CTAPHID_CANCEL. `Selected.AlsoTouched` names
keys touched in the same instant, so a caller about to change something can
refuse an ambiguous choice; `Key.Identity` says, without a touch, which key is
which (aaguid, PIN set, fingerprints enrolled).

## Naming a key, on the key

The port a key sits in is not the key, the AAGUID names a model, and most keys
publish no serial. `Key.SetName` stores a name IN the key: a discoverable
credential under the reserved relying party `name.fido` (credProtect 1) whose
user handle is the name (at most 64 bytes of UTF-8, no control characters).
`Key.ReadName` reads it with no touch and no PIN (getAssertion, `up` false, no
pinUvAuthParam). CTAP 2.1 does not make every key answer that, so a refused read
is `ErrNameRefused` and a caller needs a fallback. `SetName` replaces: the old
name is deleted first (credential management, 6.8), so a key never holds two.

## The fido command

`cmd/fido` (its own module: `go install github.com/go-authn/fido/cmd/fido@latest`)
sets a PIN and enrols fingerprints; macOS and Linux (Windows refuses raw HID to
a process that is not elevated).

```
fido list                                 # every key: id, product, serial, aaguid, PIN?, fingerprints? (no touch)
fido info                                 # one key in detail
fido pin set | change
fido fingerprint add [--name N] | list | rename ID NAME | remove ID
```

With several keys attached, `--device ID` names the one to act on (IDs come from
`fido list`; they are matched exactly). Without it the person touches the key to
use; a command that WRITES never runs on "the first", refuses if two keys were
touched together, and always prints which key it is about to change.

## Every discoverable credential: GetAssertions

`Key.GetAssertions(ctx, req, max)` sends one getAssertion and then one
authenticatorGetNextAssertion (0x08, CTAP 2.1 §6.3) per further credential
the authenticator announced (`numberOfCredentials`). With an empty `Allow`
list, that reaches every discoverable credential of the relying party,
newest first. `max` bounds the count, which is the authenticator's word: a
larger announcement is refused before any further command.

§6.3 does not say whether a next assertion carries extension outputs. An
hmac-secret output found in one is decrypted with the first request's
session; a next assertion without one has a nil `HMACSecret`, so the caller
sees what the authenticator actually does. What a real key does is measured
by go-macos/fido's `FIDO_REAL=1` test. An authenticator with a display may
instead let the person pick one credential, and then announces none
(§6.2.2, step 12).
