// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Extension identifiers, as CTAP 2.1 (12) names them.
const (
	extHMACSecret  = "hmac-secret"
	extCredProtect = "credProtect"
)

// CredProtect is a credential protection policy (CTAP 2.1, 12.1): when an
// authenticator may reveal that a credential exists, and use it.
type CredProtect uint

// The policies, with the specification's numbers.
const (
	// CredProtectOptional (1, userVerificationOptional): the credential may be
	// used with or without user verification. It is the default of an
	// authenticator that does not know the extension.
	CredProtectOptional CredProtect = 1
	// CredProtectOptionalWithList (2, userVerificationOptionalWithCredentialIDList):
	// without verification the credential answers only to a request that NAMES
	// it, and is invisible to discovery.
	CredProtectOptionalWithList CredProtect = 2
	// CredProtectRequired (3, userVerificationRequired): the credential answers
	// to nothing without user verification, and an unverified request is told
	// there are NO credentials, whether or not the one it named exists. A caller
	// must therefore obtain verification BEFORE probing for a credential: a
	// probe that comes first gets "none" from the right key.
	CredProtectRequired CredProtect = 3
)

// Extensions are the extension inputs of a registration (CTAP 2.1, 6.1.2,
// parameter 0x06). Which of them a caller asks for, and with what policy, is the
// caller's decision; this package encodes them and reads the outputs back.
type Extensions struct {
	// HMACSecret asks the authenticator to create the credential with the
	// hmac-secret extension (CTAP 2.1, 12.5), so that [GetAssertionRequest.HMACSecret]
	// can derive secrets from it later.
	HMACSecret bool
	// CredProtect, when not zero, sets the credential protection policy.
	CredProtect CredProtect
	// Other carries extensions this package has no field for, by identifier. The
	// values are encoded as given; naming one of the fields above here as well is
	// an error rather than a silent choice.
	Other map[string]any
}

// encode builds the extensions map, or nil when nothing is asked for.
func (e Extensions) encode() (map[string]any, error) {
	if e.CredProtect > CredProtectRequired {
		return nil, fmt.Errorf("fido: credProtect policy %d is not one of 1, 2, 3", e.CredProtect)
	}
	m := map[string]any{}
	if e.HMACSecret {
		m[extHMACSecret] = true
	}
	if e.CredProtect != 0 {
		m[extCredProtect] = uint(e.CredProtect)
	}
	for id, v := range e.Other {
		if _, dup := m[id]; dup {
			return nil, fmt.Errorf("fido: extension %q is set twice", id)
		}
		m[id] = v
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// ExtensionOutputs are the extension outputs an authenticator put in its
// authenticator data.
type ExtensionOutputs struct {
	// HMACSecret is true when a registration says the credential has the
	// hmac-secret extension. It is not the secret: that comes from an assertion.
	HMACSecret bool
	// CredProtect is the policy the authenticator applied, zero when it said
	// nothing. An authenticator that ignored a requested policy reports the
	// default here, which is how a caller finds out.
	CredProtect CredProtect
	// Raw holds every output, by identifier, undecoded.
	Raw map[string]cbor.RawMessage

	// hmacEnc is an assertion's encrypted hmac-secret output.
	hmacEnc []byte
}

// ExtensionOutputs decodes the extension data of the authenticator data. With no
// extension data it returns the zero value.
func (a AuthData) ExtensionOutputs() (ExtensionOutputs, error) {
	var o ExtensionOutputs
	if len(a.Extensions) == 0 {
		return o, nil
	}
	if err := cbor.Unmarshal(a.Extensions, &o.Raw); err != nil {
		return ExtensionOutputs{}, fmt.Errorf("fido: the extension outputs are not a map of identifiers: %w", err)
	}
	if raw, ok := o.Raw[extHMACSecret]; ok {
		var v any
		if err := cbor.Unmarshal(raw, &v); err != nil {
			return ExtensionOutputs{}, fmt.Errorf("fido: the hmac-secret output: %w", err)
		}
		switch x := v.(type) {
		case bool:
			o.HMACSecret = x
		case []byte:
			o.hmacEnc = x
		default:
			return ExtensionOutputs{}, fmt.Errorf("fido: the hmac-secret output is %T, neither a flag nor a byte string", v)
		}
	}
	if raw, ok := o.Raw[extCredProtect]; ok {
		if err := cbor.Unmarshal(raw, &o.CredProtect); err != nil {
			return ExtensionOutputs{}, fmt.Errorf("fido: the credProtect output: %w", err)
		}
	}
	return o, nil
}

// HMACSecret is the hmac-secret input of an assertion (CTAP 2.1, 12.5): one or
// two salts the authenticator turns into secrets bound to the credential.
type HMACSecret struct {
	// Protocol is the PIN/UV auth protocol the salts travel under. Zero means the
	// request's token protocol when it has a token, else the highest one the
	// authenticator lists.
	Protocol PINProtocol
	// Salt1 is required, Salt2 optional; each is exactly 32 bytes.
	Salt1, Salt2 []byte
	// RequireUV makes the call fail, and return no secret, when the
	// authenticator did not report user verification.
	//
	// An authenticator derives a DIFFERENT secret for a verified request than for
	// an unverified one (CTAP 2.1, 12.5: CredRandomWithUV and
	// CredRandomWithoutUV), and nothing in the output says which. A caller that
	// derives a key from it and forgets to check [AuthData.Flags] gets a wrong
	// key without any error, so a caller that needs the verified secret should
	// set this.
	RequireUV bool
}

// HMACSecretOutput holds the secrets, HMAC-SHA-256(CredRandom, salt), 32 bytes
// each.
type HMACSecretOutput struct {
	First  []byte
	Second []byte // nil when no second salt was sent
}

// ErrHMACSecretNotVerified is returned when [HMACSecret.RequireUV] was set and
// the authenticator did not verify the user.
var ErrHMACSecretNotVerified = errors.New("fido: the authenticator did not verify the user, so its hmac-secret output is the unverified one")

// hmacSaltSize is the size of each salt and each output.
const hmacSaltSize = 32

// The hmac-secret input and output keys (CTAP 2.1, 12.5).
const (
	hsKeyAgreement = 0x01
	hsSaltEnc      = 0x02
	hsSaltAuth     = 0x03
	hsProtocol     = 0x04
)

// hmacSession is what an assertion keeps to read its hmac-secret output.
type hmacSession struct {
	keys  pinKeys
	salts int
	req   HMACSecret
}

// SelectPINProtocol picks the highest PIN/UV auth protocol the authenticator
// lists that this package implements.
func (k *Key) SelectPINProtocol(ctx context.Context) (PINProtocol, error) {
	info, err := k.GetInfo(ctx)
	if err != nil {
		return 0, err
	}
	return pickProtocol(info.PINProtocols)
}

func pickProtocol(listed []uint) (PINProtocol, error) {
	best := PINProtocol(0)
	for _, p := range listed {
		if (p == uint(PINProtocolOne) || p == uint(PINProtocolTwo)) && PINProtocol(p) > best {
			best = PINProtocol(p)
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("fido: the authenticator lists PIN protocols %v, and this package implements 1 and 2", listed)
	}
	return best, nil
}

// hmacInput builds the "hmac-secret" extension input for an assertion.
func (k *Key) hmacInput(ctx context.Context, h HMACSecret, tok Token) (map[int]any, *hmacSession, error) {
	if len(h.Salt1) != hmacSaltSize {
		return nil, nil, fmt.Errorf("fido: hmac-secret salt 1 is %d bytes, and a salt is %d", len(h.Salt1), hmacSaltSize)
	}
	if h.Salt2 != nil && len(h.Salt2) != hmacSaltSize {
		return nil, nil, fmt.Errorf("fido: hmac-secret salt 2 is %d bytes, and a salt is %d", len(h.Salt2), hmacSaltSize)
	}
	proto := h.Protocol
	switch {
	case proto != 0:
	case tok.Valid():
		proto = tok.Protocol()
	default:
		var err error
		if proto, err = k.SelectPINProtocol(ctx); err != nil {
			return nil, nil, err
		}
	}
	pub, err := k.KeyAgreement(ctx, proto)
	if err != nil {
		return nil, nil, err
	}
	own, keys, err := agree(proto, pub)
	if err != nil {
		return nil, nil, err
	}
	salts := append(append([]byte(nil), h.Salt1...), h.Salt2...)
	enc, err := keys.encrypt(salts)
	if err != nil {
		return nil, nil, err
	}
	in := map[int]any{
		hsKeyAgreement: own,
		hsSaltEnc:      enc,
		hsSaltAuth:     keys.authenticate(enc),
		hsProtocol:     int(proto),
	}
	return in, &hmacSession{keys: keys, salts: len(salts) / hmacSaltSize, req: h}, nil
}

// output reads and decrypts the hmac-secret output of an assertion.
func (s *hmacSession) output(a *Assertion) (*HMACSecretOutput, error) {
	if s.req.RequireUV && !a.Parsed.Flags.Has(FlagUV) {
		return nil, ErrHMACSecretNotVerified
	}
	if a.Extensions.hmacEnc == nil {
		return nil, fmt.Errorf("fido: the assertion carries no hmac-secret output; was the credential made with the extension?")
	}
	plain, err := s.keys.decrypt(a.Extensions.hmacEnc)
	if err != nil {
		return nil, fmt.Errorf("fido: the hmac-secret output will not decrypt: %w", err)
	}
	if len(plain) != s.salts*hmacSaltSize {
		return nil, fmt.Errorf("fido: the hmac-secret output is %d bytes, and %d salt(s) give %d",
			len(plain), s.salts, s.salts*hmacSaltSize)
	}
	out := &HMACSecretOutput{First: plain[:hmacSaltSize]}
	if s.salts == 2 {
		out.Second = plain[hmacSaltSize:]
	}
	return out, nil
}
