// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// CmdClientPIN is authenticatorClientPIN.
const CmdClientPIN byte = 0x06

// The subcommands, as the specification numbers them.
//
// Note the gap: getPinUvAuthTokenUsingPinWithPermissions is NINE, not eight.
// Prose summarising the specification puts it at eight; libfido2 sends nine,
// and libfido2 is the thing that talks to authenticators every day.
const (
	subGetPINRetries    = 0x01
	subGetKeyAgreement  = 0x02
	subSetPIN           = 0x03
	subChangePIN        = 0x04
	subGetPINToken      = 0x05
	subGetTokenUsingUV  = 0x06
	subGetUVRetries     = 0x07
	subGetTokenUsingPIN = 0x09
)

// The clientPIN parameter keys.
const (
	cpProtocol       = 0x01
	cpSubCommand     = 0x02
	cpKeyAgreement   = 0x03
	cpPinUvAuthParam = 0x04
	cpNewPinEnc      = 0x05
	cpPinHashEnc     = 0x06
	cpPermissions    = 0x07
	cpRPID           = 0x08

	cpRespKeyAgreement = 0x01
	cpRespToken        = 0x02
	cpRespPINRetries   = 0x03
	cpRespPowerCycle   = 0x04
	cpRespUVRetries    = 0x05
)

// Permissions are what a token is allowed to authorise. An authenticator that
// speaks CTAP 2.1 wants them; one that only speaks 2.0 has no notion of them
// and is asked the older way.
type Permissions uint

// The permissions this package can ask for.
const (
	PermMakeCredential Permissions = 0x01
	PermGetAssertion   Permissions = 0x02
)

// Retries is what an authenticator says about how many attempts are left.
type Retries struct {
	// PIN is how many PIN attempts remain before the authenticator locks. It
	// falls on a wrong PIN and is restored by a correct one.
	PIN int
	// PowerCycle is true when the authenticator will accept no more PINs until
	// it is unplugged and plugged back in -- which is not the same as being
	// locked for good, and telling a person the difference matters.
	PowerCycle bool
}

// PINRetries asks how many attempts are left.
//
// It needs no PIN and no key agreement, which makes it the one clientPIN
// subcommand that can be asked of a key nobody has configured -- and the right
// thing to ask BEFORE prompting somebody, so a prompt is never the last one
// they get.
func (k *Key) PINRetries(ctx context.Context) (Retries, error) {
	if err := k.ctap2Ready(); err != nil {
		return Retries{}, err
	}
	body, err := k.cborCall(ctx, CmdClientPIN, map[int]any{
		cpProtocol:   int(PINProtocolOne),
		cpSubCommand: subGetPINRetries,
	})
	if err != nil {
		return Retries{}, err
	}
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return Retries{}, fmt.Errorf("fido: the retry count is not a CBOR map: %w", err)
	}
	var r Retries
	if err := field(raw, cpRespPINRetries, &r.PIN, "retry count"); err != nil {
		return Retries{}, err
	}
	if m, ok := raw[cpRespPowerCycle]; ok {
		if err := cbor.Unmarshal(m, &r.PowerCycle); err != nil {
			return Retries{}, fmt.Errorf("fido: the power-cycle state: %w", err)
		}
	}
	return r, nil
}

// KeyAgreement asks the authenticator for a public key to agree with.
//
// It is exported because it is the one half of the PIN dance that needs no
// PIN: a key with none set still answers, so this is how a caller checks that
// the whole chain -- CBOR out, COSE in, ECDH -- works before anybody is asked
// for a secret.
func (k *Key) KeyAgreement(ctx context.Context, proto PINProtocol) (*ecdh.PublicKey, error) {
	if err := k.ctap2Ready(); err != nil {
		return nil, err
	}
	body, err := k.cborCall(ctx, CmdClientPIN, map[int]any{
		cpProtocol:   int(proto),
		cpSubCommand: subGetKeyAgreement,
	})
	if err != nil {
		return nil, err
	}
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("fido: the key agreement is not a CBOR map: %w", err)
	}
	m, ok := raw[cpRespKeyAgreement]
	if !ok {
		return nil, fmt.Errorf("fido: the authenticator offered no key to agree with")
	}
	return coseToECDH(m)
}

// Token is a pinUvAuthToken: permission, for a while, to do the things it was
// asked for.
//
// It is deliberately not a plain []byte. A token authenticates every later
// request, so it must be paired with the protocol it was obtained under --
// authenticating with the wrong one produces sixteen bytes where thirty-two
// are expected, which an authenticator reports as a bad PIN rather than as a
// mismatched protocol.
type Token struct {
	keys pinKeys
	raw  []byte
}

// Protocol is the protocol this token belongs to.
func (t Token) Protocol() PINProtocol { return t.keys.proto }

// Valid reports whether the token holds anything.
func (t Token) Valid() bool { return len(t.raw) > 0 }

// authParam is the pinUvAuthParam over data, under this token.
func (t Token) authParam(data []byte) []byte {
	return pinKeys{proto: t.keys.proto, aes: t.raw, hmac: t.raw}.authenticate(data)
}

// PINToken exchanges a PIN for a token.
//
// permissions is what the token will be allowed to authorise, and rpID narrows
// it further. Both are CTAP 2.1; an authenticator that does not list
// "pinUvAuthToken" in its options is asked the CTAP 2.0 way instead, where a
// token authorises everything and neither argument is sent.
//
// The PIN never leaves in the clear: what is sent is the first sixteen bytes
// of its SHA-256, encrypted under a secret agreed for this exchange alone.
//
// A wrong PIN COSTS a retry, and an authenticator that runs out locks until it
// is unplugged, then permanently. [Key.PINRetries] before prompting is not
// politeness.
func (k *Key) PINToken(ctx context.Context, pin string, proto PINProtocol, perms Permissions, rpID string) (Token, error) {
	if err := k.ctap2Ready(); err != nil {
		return Token{}, err
	}
	if pin == "" {
		return Token{}, fmt.Errorf("fido: an empty PIN is not a PIN")
	}
	pub, err := k.KeyAgreement(ctx, proto)
	if err != nil {
		return Token{}, err
	}
	ownCOSE, keys, err := agree(proto, pub)
	if err != nil {
		return Token{}, err
	}
	hashEnc, err := keys.pinHash(pin)
	if err != nil {
		return Token{}, err
	}
	req := map[int]any{
		cpProtocol:     int(proto),
		cpSubCommand:   subGetTokenUsingPIN,
		cpKeyAgreement: ownCOSE,
		cpPinHashEnc:   hashEnc,
		cpPermissions:  uint(perms),
	}
	if rpID != "" {
		req[cpRPID] = rpID
	}
	if perms == 0 {
		// No permissions asked for means the older exchange, where a token
		// authorises everything. Sending permissions of zero is not the same
		// request and some authenticators refuse it.
		req = map[int]any{
			cpProtocol:     int(proto),
			cpSubCommand:   subGetPINToken,
			cpKeyAgreement: ownCOSE,
			cpPinHashEnc:   hashEnc,
		}
	}
	body, err := k.cborCall(ctx, CmdClientPIN, req)
	if err != nil {
		return Token{}, err
	}
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return Token{}, fmt.Errorf("fido: the token reply is not a CBOR map: %w", err)
	}
	var enc []byte
	if err := field(raw, cpRespToken, &enc, "token"); err != nil {
		return Token{}, err
	}
	tok, err := keys.decrypt(enc)
	if err != nil {
		return Token{}, fmt.Errorf("fido: the token will not decrypt: %w", err)
	}
	return Token{keys: keys, raw: tok}, nil
}

// coseToECDH reads a COSE_Key into an ECDH public key.
func coseToECDH(raw cbor.RawMessage) (*ecdh.PublicKey, error) {
	var m map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("fido: the agreement key is not a COSE map: %w", err)
	}
	var x, y []byte
	for _, f := range []struct {
		label int64
		into  *[]byte
		what  string
	}{{coseX, &x, "x"}, {coseY, &y, "y"}} {
		r, ok := m[f.label]
		if !ok {
			return nil, fmt.Errorf("fido: the agreement key has no %s coordinate", f.what)
		}
		if err := cbor.Unmarshal(r, f.into); err != nil {
			return nil, fmt.Errorf("fido: the agreement key's %s coordinate: %w", f.what, err)
		}
	}
	if len(x) != coseP256Size || len(y) != coseP256Size {
		return nil, fmt.Errorf("fido: the agreement key's coordinates are %d and %d bytes; P-256 uses %d",
			len(x), len(y), coseP256Size)
	}
	// Uncompressed point: 0x04 then x then y, which is what crypto/ecdh takes.
	point := append([]byte{0x04}, append(x, y...)...)
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("fido: the agreement key is not a P-256 point: %w", err)
	}
	return pub, nil
}

// ecdhToCOSE writes a public key as the COSE_Key an authenticator expects.
//
// The algorithm is stated as ECDH-ES+HKDF-256 (-25) rather than ES256: this
// key agrees, it does not sign, and an authenticator that checks will refuse
// the wrong one.
func ecdhToCOSE(pub *ecdh.PublicKey) (map[int64]any, error) {
	b := pub.Bytes()
	if len(b) != 1+2*coseP256Size || b[0] != 0x04 {
		return nil, fmt.Errorf("fido: the platform key is %d bytes and not an uncompressed point", len(b))
	}
	x := new(big.Int).SetBytes(b[1 : 1+coseP256Size])
	y := new(big.Int).SetBytes(b[1+coseP256Size:])
	xb := make([]byte, coseP256Size)
	yb := make([]byte, coseP256Size)
	x.FillBytes(xb)
	y.FillBytes(yb)
	return map[int64]any{
		coseKty: coseKtyEC2,
		coseAlg: -25, // ECDH-ES + HKDF-256
		coseCrv: coseCrvP256,
		coseX:   xb,
		coseY:   yb,
	}, nil
}
