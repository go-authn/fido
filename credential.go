// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// The CTAP2 commands that make and use credentials.
const (
	CmdMakeCredential byte = 0x01
	CmdGetAssertion   byte = 0x02
)

// AlgES256 is the COSE identifier for ECDSA over P-256 with SHA-256. It is the
// one algorithm every FIDO authenticator supports, which is why it is the
// default here: asking for something else and being refused is a worse first
// experience than asking for the thing that always works.
const AlgES256 int64 = -7

// RelyingParty is the site or program a credential belongs to.
type RelyingParty struct {
	// ID is the domain the credential is scoped to. An authenticator hashes it
	// and never learns it.
	ID string
	// Name is for a person to read on the authenticator's own screen, when it
	// has one.
	Name string
}

// User is who the credential is for, as the authenticator will remember them.
type User struct {
	// ID is an opaque handle chosen by the relying party. It comes BACK in an
	// assertion, so it is how a caller knows who signed in -- and for that
	// reason it must not be an email address or anything else that identifies
	// a person to whoever holds the key.
	ID []byte
	// Name and DisplayName are shown to a person choosing between credentials.
	Name        string
	DisplayName string
}

// Credential names one credential an authenticator holds.
type Credential struct {
	// Type is "public-key" for everything current.
	Type string
	// ID is the credential id the authenticator gave out.
	ID []byte
	// Transports, when known, say how the credential can be reached.
	Transports []string
}

// MakeCredentialRequest is a registration.
type MakeCredentialRequest struct {
	// ClientDataHash is SHA-256 of the client data the caller built. It is
	// hashed here by nobody: what goes into the client data is the caller's
	// business, and the authenticator signs the hash it is given.
	ClientDataHash []byte
	RP             RelyingParty
	User           User
	// Algorithms are COSE identifiers, most preferred first. Empty asks for
	// [AlgES256].
	Algorithms []int64
	// Exclude lists credentials that must NOT be registered again, which is how
	// a relying party stops one key holding two credentials for one account.
	Exclude []Credential
	// Options are the authenticator options for this request, such as "rk" for
	// a discoverable credential and "uv" to demand verification rather than
	// mere presence.
	Options map[string]bool
	// Token, when valid, authorises the request: it is what turns "somebody
	// touched the key" into "somebody who knows its PIN touched the key", and
	// it is the only way to get the verified bit set on an authenticator whose
	// verification IS a PIN.
	Token Token
}

// Attestation is what a registration returns.
type Attestation struct {
	// Format names the attestation statement's shape: "packed", "none", and
	// others.
	Format string
	// AuthData is the raw authenticator data, kept because a signature is over
	// these bytes and re-encoding [Parsed] would not reproduce them.
	AuthData []byte
	Parsed   AuthData
	// Statement is the attestation statement, left as CBOR: verifying it means
	// choosing a certificate library, and that choice is not this package's.
	Statement cbor.RawMessage
}

// GetAssertionRequest asks an authenticator to prove it holds a credential.
type GetAssertionRequest struct {
	RPID           string
	ClientDataHash []byte
	// Allow narrows the request to particular credentials. Leaving it empty
	// asks the authenticator to use a DISCOVERABLE credential, which it only
	// has if one was registered with the "rk" option.
	Allow   []Credential
	Options map[string]bool
	// Token, when valid, authorises the request. See
	// [MakeCredentialRequest.Token].
	Token Token
}

// Assertion is what an authenticator answers with.
type Assertion struct {
	// Credential says which credential answered. An authenticator may leave it
	// out when the request named exactly one.
	Credential Credential
	AuthData   []byte
	Parsed     AuthData
	// Signature covers the authenticator data followed by the client data
	// hash, in that order. Verifying it is the caller's, with the public key
	// from the registration.
	Signature []byte
	// UserID is the user handle, present for a discoverable credential.
	UserID []byte
	// Available is how many credentials could have answered, when the
	// authenticator said. More than one means the caller may ask for the next.
	Available uint
}

// The parameter keys, as the specification numbers them.
const (
	mcClientDataHash    = 0x01
	mcRP                = 0x02
	mcUser              = 0x03
	mcPubKeyCredParams  = 0x04
	mcExcludeList       = 0x05
	mcOptions           = 0x07
	mcPinUvAuthParam    = 0x08
	mcPinUvAuthProtocol = 0x09

	mcRespFmt      = 0x01
	mcRespAuthData = 0x02
	mcRespAttStmt  = 0x03

	gaRPID              = 0x01
	gaClientDataHash    = 0x02
	gaAllowList         = 0x03
	gaOptions           = 0x05
	gaPinUvAuthParam    = 0x06
	gaPinUvAuthProtocol = 0x07

	gaRespCredential = 0x01
	gaRespAuthData   = 0x02
	gaRespSignature  = 0x03
	gaRespUser       = 0x04
	gaRespAvailable  = 0x05
)

// ctap2 encodes in the canonical form CTAP2 requires. An authenticator is
// entitled to refuse anything else, and some do.
var ctap2 = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic("fido: the CBOR library refused its own CTAP2 options: " + err.Error())
	}
	return m
}()

// MakeCredential registers a new credential.
//
// The authenticator will ask for a person: a touch, and a PIN or a fingerprint
// when the request or the authenticator demands verification. It sends
// CTAPHID_KEEPALIVE the whole time it waits, which the transport skips, so the
// only bound on how long this takes is the context.
func (k *Key) MakeCredential(ctx context.Context, r MakeCredentialRequest) (*Attestation, error) {
	if err := k.ctap2Ready(); err != nil {
		return nil, err
	}
	if len(r.ClientDataHash) == 0 {
		return nil, fmt.Errorf("fido: a registration needs a client data hash to sign over")
	}
	if r.RP.ID == "" {
		return nil, fmt.Errorf("fido: a registration needs a relying party id")
	}
	if len(r.User.ID) == 0 {
		return nil, fmt.Errorf("fido: a registration needs a user handle")
	}
	algs := r.Algorithms
	if len(algs) == 0 {
		algs = []int64{AlgES256}
	}
	params := make([]map[string]any, 0, len(algs))
	for _, a := range algs {
		params = append(params, map[string]any{"alg": a, "type": "public-key"})
	}
	req := map[int]any{
		mcClientDataHash:   r.ClientDataHash,
		mcRP:               map[string]any{"id": r.RP.ID, "name": r.RP.Name},
		mcUser:             userMap(r.User),
		mcPubKeyCredParams: params,
	}
	if len(r.Exclude) > 0 {
		req[mcExcludeList] = descriptors(r.Exclude)
	}
	if len(r.Options) > 0 {
		req[mcOptions] = r.Options
	}
	if r.Token.Valid() {
		// The parameter is authenticated over the CLIENT DATA HASH, not over
		// the request: an authenticator checks that the caller who holds the
		// token is the caller who chose what is being signed.
		req[mcPinUvAuthParam] = r.Token.authParam(r.ClientDataHash)
		req[mcPinUvAuthProtocol] = int(r.Token.Protocol())
	}
	body, err := k.cborCall(ctx, CmdMakeCredential, req)
	if err != nil {
		return nil, err
	}

	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("fido: the registration reply is not a CBOR map: %w", err)
	}
	var att Attestation
	if err := field(raw, mcRespFmt, &att.Format, "attestation format"); err != nil {
		return nil, err
	}
	if err := field(raw, mcRespAuthData, &att.AuthData, "authenticator data"); err != nil {
		return nil, err
	}
	if len(att.AuthData) == 0 {
		return nil, fmt.Errorf("fido: the registration carried no authenticator data")
	}
	if att.Parsed, err = ParseAuthData(att.AuthData); err != nil {
		return nil, err
	}
	if !att.Parsed.Flags.Has(FlagAT) {
		return nil, fmt.Errorf("fido: the registration's authenticator data has no credential in it")
	}
	if r, ok := raw[mcRespAttStmt]; ok {
		att.Statement = r
	}
	return &att, nil
}

// GetAssertion asks the authenticator to sign, proving it holds the credential.
func (k *Key) GetAssertion(ctx context.Context, r GetAssertionRequest) (*Assertion, error) {
	if err := k.ctap2Ready(); err != nil {
		return nil, err
	}
	if r.RPID == "" {
		return nil, fmt.Errorf("fido: an assertion needs a relying party id")
	}
	if len(r.ClientDataHash) == 0 {
		return nil, fmt.Errorf("fido: an assertion needs a client data hash to sign over")
	}
	req := map[int]any{
		gaRPID:           r.RPID,
		gaClientDataHash: r.ClientDataHash,
	}
	if len(r.Allow) > 0 {
		req[gaAllowList] = descriptors(r.Allow)
	}
	if len(r.Options) > 0 {
		req[gaOptions] = r.Options
	}
	if r.Token.Valid() {
		req[gaPinUvAuthParam] = r.Token.authParam(r.ClientDataHash)
		req[gaPinUvAuthProtocol] = int(r.Token.Protocol())
	}
	body, err := k.cborCall(ctx, CmdGetAssertion, req)
	if err != nil {
		return nil, err
	}

	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("fido: the assertion reply is not a CBOR map: %w", err)
	}
	var a Assertion
	if err := field(raw, gaRespAuthData, &a.AuthData, "authenticator data"); err != nil {
		return nil, err
	}
	if len(a.AuthData) == 0 {
		return nil, fmt.Errorf("fido: the assertion carried no authenticator data")
	}
	if a.Parsed, err = ParseAuthData(a.AuthData); err != nil {
		return nil, err
	}
	if err := field(raw, gaRespSignature, &a.Signature, "signature"); err != nil {
		return nil, err
	}
	if len(a.Signature) == 0 {
		return nil, fmt.Errorf("fido: the assertion carried no signature, so it proves nothing")
	}
	// The credential and the user are optional: an authenticator asked for one
	// named credential may leave the first out, and only a discoverable one
	// carries a user.
	if m, ok := raw[gaRespCredential]; ok {
		var d struct {
			Type string `cbor:"type"`
			ID   []byte `cbor:"id"`
		}
		if err := cbor.Unmarshal(m, &d); err != nil {
			return nil, fmt.Errorf("fido: the assertion's credential: %w", err)
		}
		a.Credential = Credential{Type: d.Type, ID: d.ID}
	}
	if m, ok := raw[gaRespUser]; ok {
		var u struct {
			ID []byte `cbor:"id"`
		}
		if err := cbor.Unmarshal(m, &u); err != nil {
			return nil, fmt.Errorf("fido: the assertion's user: %w", err)
		}
		a.UserID = u.ID
	}
	if m, ok := raw[gaRespAvailable]; ok {
		if err := cbor.Unmarshal(m, &a.Available); err != nil {
			return nil, fmt.Errorf("fido: the assertion's credential count: %w", err)
		}
	}
	return &a, nil
}

// ctap2Ready refuses a key that cannot speak CTAP2, rather than letting it
// answer CTAPHID_ERROR and leaving the caller to tell that from a fault.
func (k *Key) ctap2Ready() error {
	if !k.caps.Has(CapCBOR) {
		return fmt.Errorf("fido: %s does not speak CTAP2", k.t.Name())
	}
	return nil
}

// cborCall encodes the parameters and sends the command.
func (k *Key) cborCall(ctx context.Context, cmd byte, params map[int]any) ([]byte, error) {
	b, err := ctap2.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("fido: cannot encode the request: %w", err)
	}
	return k.CBOR(ctx, cmd, b)
}

// field decodes a required member of a reply.
func field(raw map[uint64]cbor.RawMessage, key uint64, into any, what string) error {
	m, ok := raw[key]
	if !ok {
		return fmt.Errorf("fido: the reply has no %s", what)
	}
	if err := cbor.Unmarshal(m, into); err != nil {
		return fmt.Errorf("fido: the reply's %s: %w", what, err)
	}
	return nil
}

// userMap builds the user entity, leaving out what was not given: an empty
// name is not the same as a name that is the empty string, and some
// authenticators refuse the latter.
func userMap(u User) map[string]any {
	m := map[string]any{"id": u.ID}
	if u.Name != "" {
		m["name"] = u.Name
	}
	if u.DisplayName != "" {
		m["displayName"] = u.DisplayName
	}
	return m
}

// descriptors builds a credential list.
func descriptors(creds []Credential) []map[string]any {
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		t := c.Type
		if t == "" {
			t = "public-key"
		}
		d := map[string]any{"type": t, "id": c.ID}
		if len(c.Transports) > 0 {
			d["transports"] = c.Transports
		}
		out = append(out, d)
	}
	return out
}
