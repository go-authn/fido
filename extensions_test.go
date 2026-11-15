// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const testRP = "unlock.example.test"

var (
	testCDH = bytes.Repeat([]byte{0x5A}, 32)
	salt1   = bytes.Repeat([]byte{0x11}, 32)
	salt2   = bytes.Repeat([]byte{0x22}, 32)
)

func virtualKey(t *testing.T, v *virtualAuthenticator) *Key {
	t.Helper()
	return ctap2Key(t, CapCBOR, v.reply)
}

// register makes a discoverable credential and returns the authenticator's
// record of it, so a test can compute what the specification says it yields.
func register(t *testing.T, k *Key, v *virtualAuthenticator, ext Extensions, tok Token) (*Attestation, *virtualCredential) {
	t.Helper()
	att, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: testCDH,
		RP:             RelyingParty{ID: testRP},
		User:           User{ID: []byte("slot-1")},
		Options:        map[string]bool{"rk": true},
		Token:          tok,
		Extensions:     ext,
	})
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	return att, v.creds[len(v.creds)-1]
}

func assertWith(k *Key, c *virtualCredential, tok Token, h *HMACSecret) (*Assertion, error) {
	return k.GetAssertion(context.Background(), GetAssertionRequest{
		RPID:           testRP,
		ClientDataHash: testCDH,
		Allow:          []Credential{{ID: c.id}},
		Token:          tok,
		HMACSecret:     h,
	})
}

func TestRegistrationCarriesExtensions(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	att, c := register(t, k, v, Extensions{HMACSecret: true, CredProtect: CredProtectRequired}, Token{})
	if !att.Extensions.HMACSecret || att.Extensions.CredProtect != CredProtectRequired {
		t.Errorf("outputs %+v", att.Extensions)
	}
	if !c.hmac || c.protect != 3 {
		t.Errorf("the authenticator recorded hmac=%v protect=%d", c.hmac, c.protect)
	}
	if got := fmt.Sprint(extKeys(v.lastMCExt)); got != "[credProtect hmac-secret]" {
		t.Errorf("extension identifiers on the wire: %s", got)
	}
	// Written out from CTAP 2.1 12.1 and 12.5: credProtect is an unsigned
	// integer, hmac-secret a boolean.
	var n uint
	var b bool
	if cbor.Unmarshal(v.lastMCExt["credProtect"], &n) != nil || n != 3 ||
		cbor.Unmarshal(v.lastMCExt["hmac-secret"], &b) != nil || !b {
		t.Errorf("extension values on the wire: %x", v.lastMCExt)
	}
}

func extKeys(m map[string]cbor.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestNoExtensionsSendsNoParameter(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	att, _ := register(t, k, v, Extensions{}, Token{})
	if v.lastMCExt != nil || att.Extensions.HMACSecret || att.Parsed.Flags.Has(FlagED) {
		t.Errorf("extensions appeared from nowhere: %v %+v", v.lastMCExt, att.Extensions)
	}
}

func TestExtensionsRefuseWhatIsWrong(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	for name, e := range map[string]Extensions{
		"policy 4":       {CredProtect: 4},
		"duplicate":      {HMACSecret: true, Other: map[string]any{"hmac-secret": true}},
		"duplicate prot": {CredProtect: 1, Other: map[string]any{"credProtect": 1}},
	} {
		_, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
			ClientDataHash: testCDH, RP: RelyingParty{ID: testRP}, User: User{ID: []byte("u")}, Extensions: e,
		})
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if len(v.asked) != 0 {
		t.Errorf("a refused request still reached the authenticator: %v", v.asked)
	}
	// An extension this package has no field for goes out as given.
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: testCDH, RP: RelyingParty{ID: testRP}, User: User{ID: []byte("u")},
		Extensions: Extensions{Other: map[string]any{"credBlob": []byte("x")}},
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(v.lastMCExt["credBlob"], []byte("x")) {
		t.Errorf("credBlob was not sent: %x", v.lastMCExt)
	}
}

func TestHMACSecretUnderBothProtocols(t *testing.T) {
	for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
		t.Run(proto.String(), func(t *testing.T) {
			v := newVirtualAuthenticator(t, "1234")
			k := virtualKey(t, v)
			tok, err := k.PINToken(context.Background(), "1234", proto, PermMakeCredential|PermGetAssertion, testRP)
			if err != nil {
				t.Fatal(err)
			}
			_, c := register(t, k, v, Extensions{HMACSecret: true}, tok)

			first, err := assertWith(k, c, tok, &HMACSecret{Salt1: salt1, Salt2: salt2})
			if err != nil {
				t.Fatalf("GetAssertion: %v", err)
			}
			// Equal to what the specification says, computed without the package.
			if !bytes.Equal(first.HMACSecret.First, c.expected(true, salt1)) ||
				!bytes.Equal(first.HMACSecret.Second, c.expected(true, salt2)) {
				t.Error("the secrets are not HMAC-SHA-256(CredRandomWithUV, salt)")
			}
			// Stable: the same salt, a new exchange, the same secret.
			again, err := assertWith(k, c, tok, &HMACSecret{Salt1: salt1})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again.HMACSecret.First, first.HMACSecret.First) || again.HMACSecret.Second != nil {
				t.Error("one salt did not give the first secret back alone")
			}
			// The salts travelled under the token's protocol.
			var in map[uint64]cbor.RawMessage
			_ = cbor.Unmarshal(v.lastGAExt["hmac-secret"], &in)
			var p int
			_ = cbor.Unmarshal(in[hsProtocol], &p)
			if p != int(proto) {
				t.Errorf("salts under protocol %d, token under %d", p, proto)
			}
			// The signature is over authData || clientDataHash and verifies.
			pub := &c.key.PublicKey
			digest := sha256.Sum256(append(append([]byte(nil), first.AuthData...), testCDH...))
			if !ecdsa.VerifyASN1(pub, digest[:], first.Signature) {
				t.Error("the assertion signature does not verify")
			}
			if !first.Parsed.Flags.Has(FlagED) || first.Extensions.Raw["hmac-secret"] == nil {
				t.Errorf("extension data missing: %+v", first.Extensions)
			}
		})
	}
}

// Trap 1: the secret of an unverified request is a different secret, and
// nothing in it says so.
func TestTrapUnverifiedSecretIsAnotherSecret(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true}, Token{})

	plain, err := assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Parsed.Flags.Has(FlagUV) {
		t.Fatal("an unverified request came back verified")
	}
	tok, err := k.UVToken(context.Background(), PINProtocolTwo, PermGetAssertion, testRP)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := assertWith(k, c, tok, &HMACSecret{Salt1: salt1})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Parsed.Flags.Has(FlagUV) {
		t.Fatal("a verified request came back unverified")
	}
	if bytes.Equal(plain.HMACSecret.First, verified.HMACSecret.First) {
		t.Fatal("verified and unverified requests gave the SAME secret; the fake no longer reproduces the trap")
	}
	if !bytes.Equal(plain.HMACSecret.First, c.expected(false, salt1)) {
		t.Error("the unverified secret is not the CredRandomWithoutUV one")
	}

	// The option that closes the trap: no secret at all rather than the wrong one.
	got, err := assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1, RequireUV: true})
	if !errors.Is(err, ErrHMACSecretNotVerified) || got != nil {
		t.Errorf("RequireUV without verification: %v, %v", got, err)
	}
	got, err = assertWith(k, c, tok, &HMACSecret{Salt1: salt1, RequireUV: true})
	if err != nil || !bytes.Equal(got.HMACSecret.First, verified.HMACSecret.First) {
		t.Errorf("RequireUV with verification: %v", err)
	}
}

// Trap 2: under credProtect 3 an unverified probe, even naming the right
// credential id on the right key, is told there is nothing there.
func TestTrapCredProtect3ProbeBeforeVerification(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true, CredProtect: CredProtectRequired}, Token{})

	_, err := assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1})
	if err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Fatalf("an unverified probe of a credProtect 3 credential: %v", err)
	}
	// Verification FIRST, then the probe, and now it is there.
	tok, err := k.UVToken(context.Background(), PINProtocolTwo, PermGetAssertion, testRP)
	if err != nil {
		t.Fatal(err)
	}
	a, err := assertWith(k, c, tok, &HMACSecret{Salt1: salt1, RequireUV: true})
	if err != nil {
		t.Fatalf("after verification: %v", err)
	}
	if !bytes.Equal(a.Credential.ID, c.id) {
		t.Error("another credential answered")
	}
}

func TestCredProtect2HidesFromDiscoveryNotFromTheList(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true, CredProtect: CredProtectOptionalWithList}, Token{})
	if _, err := assertWith(k, c, Token{}, nil); err != nil {
		t.Errorf("named, unverified: %v", err)
	}
	discover := func(tok Token) error {
		_, err := k.GetAssertion(context.Background(), GetAssertionRequest{RPID: testRP, ClientDataHash: testCDH, Token: tok})
		return err
	}
	if err := discover(Token{}); err == nil {
		t.Error("an unverified discovery found a credProtect 2 credential")
	}
	tok, err := k.PINToken(context.Background(), "1234", PINProtocolOne, PermGetAssertion, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := discover(tok); err != nil {
		t.Errorf("verified discovery: %v", err)
	}
}

// The PIN is an equal alternative to the finger: either way the request is
// verified, and either way it is the same secret.
func TestPINAndFingerGiveTheSameSecret(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true, CredProtect: CredProtectRequired}, Token{})
	ctx := context.Background()
	viaPIN, err := k.PINToken(ctx, "1234", PINProtocolTwo, PermGetAssertion, testRP)
	if err != nil {
		t.Fatal(err)
	}
	a, err := assertWith(k, c, viaPIN, &HMACSecret{Salt1: salt1, RequireUV: true})
	if err != nil {
		t.Fatal(err)
	}
	// A new token replaces the last, so the first is used before the second is
	// asked for.
	viaUV, err := k.UVToken(ctx, PINProtocolOne, PermGetAssertion, testRP)
	if err != nil {
		t.Fatal(err)
	}
	b, err := assertWith(k, c, viaUV, &HMACSecret{Salt1: salt1, RequireUV: true, Protocol: PINProtocolTwo})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.HMACSecret.First, b.HMACSecret.First) {
		t.Error("PIN and fingerprint verification gave different secrets")
	}
}

func TestUVToken(t *testing.T) {
	ctx := context.Background()
	for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
		v := newVirtualAuthenticator(t, "1234")
		k := virtualKey(t, v)
		tok, err := k.UVToken(ctx, proto, PermMakeCredential|PermGetAssertion, testRP)
		if err != nil || !tok.Valid() || tok.Protocol() != proto {
			t.Fatalf("%v: %v", proto, err)
		}
		// The request the authenticator saw is the specification's: 0x06 with
		// permissions at 0x09 and the rp id at 0x0A, and no PIN hash.
		if !slices.Equal(v.asked, []string{"clientPIN/2", "clientPIN/6"}) {
			t.Errorf("commands: %v", v.asked)
		}
		var keys []uint64
		for key := range v.lastTokenReq {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []uint64{0x01, 0x02, 0x03, 0x09, 0x0A}) {
			t.Errorf("request keys %v, want protocol, subcommand, keyAgreement, permissions 9, rpId 10", keys)
		}
		// The token authorises a registration.
		att, _ := register(t, k, v, Extensions{}, tok)
		if !att.Parsed.Flags.Has(FlagUV) {
			t.Error("a token from built-in verification did not verify the registration")
		}
	}
}

func TestUVTokenRefusals(t *testing.T) {
	ctx := context.Background()
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	if _, err := k.UVToken(ctx, PINProtocolTwo, 0, ""); err == nil {
		t.Error("a token with no permissions was asked for")
	}
	n, err := k.UVRetries(ctx)
	if err != nil || n != 5 {
		t.Fatalf("UVRetries %d, %v", n, err)
	}
	v.finger = false
	_, err = k.UVToken(ctx, PINProtocolTwo, PermGetAssertion, "")
	if err == nil || !strings.Contains(err.Error(), "did not match") {
		t.Errorf("no finger: %v", err)
	}
	if n, _ = k.UVRetries(ctx); n != 4 {
		t.Errorf("a refused verification left %d retries, want 4", n)
	}
	v.uvRetries = 0
	if _, err = k.UVToken(ctx, PINProtocolTwo, PermGetAssertion, ""); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("blocked: %v", err)
	}
	// Unsupported protocol, and a key that does not speak CTAP2.
	if _, err = k.UVToken(ctx, 3, PermGetAssertion, ""); err == nil {
		t.Error("protocol 3 accepted")
	}
	old := ctap2Key(t, 0, v.reply)
	if _, err := old.UVToken(ctx, PINProtocolTwo, PermGetAssertion, ""); err == nil {
		t.Error("a CTAP1-only key was asked")
	}
	if _, err := old.UVRetries(ctx); err == nil {
		t.Error("a CTAP1-only key was asked for UV retries")
	}
}

func TestATokenIsBoundToItsPermissionsAndRP(t *testing.T) {
	ctx := context.Background()
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true}, Token{})

	onlyMake, _ := k.UVToken(ctx, PINProtocolTwo, PermMakeCredential, testRP)
	if _, err := assertWith(k, c, onlyMake, nil); err == nil {
		t.Error("a makeCredential token authorised a getAssertion")
	}
	other, _ := k.UVToken(ctx, PINProtocolTwo, PermGetAssertion, "elsewhere.example.test")
	if _, err := assertWith(k, c, other, nil); err == nil {
		t.Error("a token for another relying party was accepted")
	}
	// A token of one protocol is refused under the other's parameter.
	tok, _ := k.UVToken(ctx, PINProtocolTwo, PermGetAssertion, testRP)
	forged := Token{keys: pinKeys{proto: PINProtocolOne}, raw: tok.raw}
	if _, err := assertWith(k, c, forged, nil); err == nil {
		t.Error("a protocol mismatch was accepted")
	}
}

func TestHMACSecretInputIsChecked(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true}, Token{})
	for name, h := range map[string]*HMACSecret{
		"short salt 1": {Salt1: salt1[:31]},
		"no salt 1":    {},
		"short salt 2": {Salt1: salt1, Salt2: salt2[:5]},
		"protocol 3":   {Salt1: salt1, Protocol: 3},
	} {
		if _, err := assertWith(k, c, Token{}, h); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	n := len(v.asked)
	_, _ = assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1[:1]})
	if len(v.asked) != n {
		t.Error("a bad salt reached the authenticator")
	}
	// Setting hmac-secret both ways is a mistake, not a choice.
	_, err := k.GetAssertion(context.Background(), GetAssertionRequest{
		RPID: testRP, ClientDataHash: testCDH,
		HMACSecret: &HMACSecret{Salt1: salt1}, Extensions: map[string]any{"hmac-secret": 1},
	})
	if err == nil {
		t.Error("hmac-secret set twice was accepted")
	}
	// Other extension inputs pass through.
	if _, err := k.GetAssertion(context.Background(), GetAssertionRequest{
		RPID: testRP, ClientDataHash: testCDH, Allow: []Credential{{ID: c.id}},
		Extensions: map[string]any{"credBlob": true},
	}); err != nil {
		t.Fatal(err)
	}
	if v.lastGAExt["credBlob"] == nil {
		t.Error("credBlob not sent")
	}
}

func TestSelectPINProtocol(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		listed []uint
		want   PINProtocol
	}{{[]uint{1}, 1}, {[]uint{1, 2}, 2}, {[]uint{2, 1, 9}, 2}} {
		v := newVirtualAuthenticator(t, "1234", tc.listed...)
		got, err := virtualKey(t, v).SelectPINProtocol(ctx)
		if err != nil || got != tc.want {
			t.Errorf("%v: %v, %v", tc.listed, got, err)
		}
	}
	v := newVirtualAuthenticator(t, "1234", 9)
	if _, err := virtualKey(t, v).SelectPINProtocol(ctx); err == nil {
		t.Error("an unknown protocol was selected")
	}
	if _, err := ctap2Key(t, 0, v.reply).SelectPINProtocol(ctx); err == nil {
		t.Error("a CTAP1-only key was asked")
	}
	// With no protocol and no token, the highest the key lists is used, and a
	// key that lists only protocol 1 gets protocol 1.
	v1 := newVirtualAuthenticator(t, "1234", 1)
	k := virtualKey(t, v1)
	_, c := register(t, k, v1, Extensions{HMACSecret: true}, Token{})
	if _, err := assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1}); err != nil {
		t.Fatal(err)
	}
	var in map[uint64]cbor.RawMessage
	_ = cbor.Unmarshal(v1.lastGAExt["hmac-secret"], &in)
	var p int
	_ = cbor.Unmarshal(in[hsProtocol], &p)
	if p != 1 {
		t.Errorf("protocol %d chosen on a protocol-1 key", p)
	}
	// A key that lists nothing usable fails the assertion before the exchange.
	vz := newVirtualAuthenticator(t, "1234", 9)
	kz := virtualKey(t, vz)
	if _, err := assertWith(kz, &virtualCredential{id: []byte("x")}, Token{}, &HMACSecret{Salt1: salt1}); err == nil {
		t.Error("no usable protocol, yet no error")
	}
}

func TestHMACSecretOutputFailures(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true}, Token{})
	ask := func() error {
		_, err := assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1, Protocol: PINProtocolTwo})
		return err
	}
	v.tamper = func(_ int, _, enc []byte) []byte { return enc[:20] }
	if err := ask(); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("a ragged output: %v", err)
	}
	v.tamper = func(proto int, key, _ []byte) []byte {
		return pinCrypt(t, proto, key, make([]byte, 16), true)
	}
	if err := ask(); err == nil || !strings.Contains(err.Error(), "16 bytes") {
		t.Errorf("a short output: %v", err)
	}
	v.tamper = nil

	// A credential made WITHOUT hmac-secret gives no output, and is said so.
	_, plain := register(t, k, v, Extensions{}, Token{})
	_, err := assertWith(k, plain, Token{}, &HMACSecret{Salt1: salt1})
	if err == nil || !strings.Contains(err.Error(), "no hmac-secret output") {
		t.Errorf("no extension on the credential: %v", err)
	}
	// Without a failing IV source the same request is fine, and with one it is
	// refused before it is sent.
	if err := ask(); err != nil {
		t.Fatal(err)
	}
	old := randRead
	t.Cleanup(func() { randRead = old })
	randRead = func([]byte) (int, error) { return 0, errors.New("no randomness") }
	if err := ask(); err == nil {
		t.Error("a failed IV was ignored")
	}
}

func TestExtensionOutputsParse(t *testing.T) {
	ext := func(v any) AuthData {
		return AuthData{Extensions: mustCBOR(t, v)}
	}
	if o, err := (AuthData{}).ExtensionOutputs(); err != nil || o.HMACSecret || o.Raw != nil {
		t.Errorf("no extension data: %+v %v", o, err)
	}
	o, err := ext(map[string]any{"hmac-secret": true, "credProtect": uint(2), "x": 1}).ExtensionOutputs()
	if err != nil || !o.HMACSecret || o.CredProtect != 2 || len(o.Raw) != 3 {
		t.Errorf("%+v %v", o, err)
	}
	o, err = ext(map[string]any{"hmac-secret": []byte("ciphertext")}).ExtensionOutputs()
	if err != nil || o.HMACSecret || string(o.hmacEnc) != "ciphertext" {
		t.Errorf("%+v %v", o, err)
	}
	for name, a := range map[string]AuthData{
		"not a map":     ext(5),
		"wrong type":    ext(map[string]any{"hmac-secret": 7}),
		"unhashable":    {Extensions: []byte{0xa1, 0x6b, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't', 0xa1, 0xa1, 0x01, 0x01, 0x02}},
		"protect text":  ext(map[string]any{"credProtect": "three"}),
		"protect minus": ext(map[string]any{"credProtect": -1}),
	} {
		if _, err := a.ExtensionOutputs(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// A reply whose extension data cannot be read is an error, on both commands.
func TestRepliesWithBrokenExtensionData(t *testing.T) {
	badExt := mustCBOR(t, 5)
	ad := append(build(FlagUP|FlagED, 1, nil), badExt...)
	k := ctap2Key(t, CapCBOR, func(cmd byte, _ []byte) []byte {
		if cmd == CmdGetAssertion {
			return append([]byte{0}, mustCBOR(t, map[uint64]any{gaRespAuthData: ad, gaRespSignature: []byte("s")})...)
		}
		reg := append(build(FlagUP|FlagAT|FlagED, 1, nil), attested(t, []byte("id"), badExt)...)
		return append([]byte{0}, mustCBOR(t, map[uint64]any{mcRespFmt: "none", mcRespAuthData: reg})...)
	})
	if _, err := k.GetAssertion(context.Background(), GetAssertionRequest{RPID: testRP, ClientDataHash: testCDH}); err == nil {
		t.Error("assertion: no error")
	}
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: testCDH, RP: RelyingParty{ID: testRP}, User: User{ID: []byte("u")},
	}); err == nil {
		t.Error("registration: no error")
	}
}

// The protocol 2 key derivation, checked against RFC 5869 written out by hand
// in the virtual authenticator, and protocol 1 against a plain SHA-256.
func TestSharedSecretDerivationMatchesTheSpecification(t *testing.T) {
	z := bytes.Repeat([]byte{0x42}, 32)
	k2, err := deriveKeys(PINProtocolTwo, z)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k2.aes, hkdfSHA256(z, "CTAP2 AES key")) || !bytes.Equal(k2.hmac, hkdfSHA256(z, "CTAP2 HMAC key")) {
		t.Error("protocol 2 keys differ from RFC 5869")
	}
	if bytes.Equal(k2.aes, k2.hmac) {
		t.Error("protocol 2 must use two different keys")
	}
	h := sha256.Sum256(z)
	k1, _ := deriveKeys(PINProtocolOne, z)
	if !bytes.Equal(k1.aes, h[:]) || !bytes.Equal(k1.hmac, h[:]) {
		t.Error("protocol 1 key is not SHA-256 of the secret")
	}
}

func TestUVTokenAndHMACSecretFailWhenTheAgreementKeyCannotBeMade(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, c := register(t, k, v, Extensions{HMACSecret: true}, Token{})
	old := newECDHKey
	t.Cleanup(func() { newECDHKey = old })
	newECDHKey = func() (*ecdh.PrivateKey, error) { return nil, errors.New("no key") }
	if _, err := k.UVToken(context.Background(), PINProtocolTwo, PermGetAssertion, ""); err == nil {
		t.Error("UVToken: no error")
	}
	if _, err := assertWith(k, c, Token{}, &HMACSecret{Salt1: salt1, Protocol: PINProtocolTwo}); err == nil {
		t.Error("hmac-secret: no error")
	}
}

func TestUVRetriesReplies(t *testing.T) {
	for name, body := range map[string][]byte{
		"not a map":  {0x05},
		"no count":   mustCBOR(t, map[uint64]any{1: 1}),
		"wrong type": mustCBOR(t, map[uint64]any{cpRespUVRetries: "x"}),
	} {
		k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return append([]byte{0}, body...) })
		if _, err := k.UVRetries(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0x01} })
	if _, err := k.UVRetries(context.Background()); err == nil {
		t.Error("a refusal was not an error")
	}
}

func TestPermissionNumbersAreTheSpecifications(t *testing.T) {
	for p, want := range map[Permissions]uint{
		PermMakeCredential: 1, PermGetAssertion: 2, PermCredentialManagement: 4,
		PermBioEnrollment: 8, PermLargeBlobWrite: 0x10, PermAuthenticatorConfig: 0x20,
	} {
		if uint(p) != want {
			t.Errorf("permission %#x, want %#x", uint(p), want)
		}
	}
}
