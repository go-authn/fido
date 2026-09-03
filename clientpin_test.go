// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// pinAuthenticator is a fake that plays the authenticator's HALF of the PIN
// dance: its own ECDH key, its own derivation, its own check of the encrypted
// PIN hash. Faking only the transport would let a wrong derivation pass.
type pinAuthenticator struct {
	t       *testing.T
	priv    *ecdh.PrivateKey
	pin     string
	token   []byte
	retries int
	// asked records the subcommands it was sent, in order.
	asked []int
}

func newPINAuthenticator(t *testing.T, pin string) *pinAuthenticator {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		t.Fatal(err)
	}
	return &pinAuthenticator{t: t, priv: priv, pin: pin, token: tok, retries: 8}
}

// reply answers a clientPIN command the way an authenticator does.
func (a *pinAuthenticator) reply(cmd byte, params []byte) []byte {
	a.t.Helper()
	if cmd != CmdClientPIN {
		a.t.Errorf("the authenticator was sent command %#02x", cmd)
		return []byte{byte(StatusOK)}
	}
	var req map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(params, &req); err != nil {
		a.t.Fatalf("the request is not a CBOR map: %v", err)
	}
	var sub, proto int
	if err := cbor.Unmarshal(req[cpSubCommand], &sub); err != nil {
		a.t.Fatalf("no subcommand: %v", err)
	}
	if err := cbor.Unmarshal(req[cpProtocol], &proto); err != nil {
		a.t.Fatalf("no protocol: %v", err)
	}
	a.asked = append(a.asked, sub)

	switch sub {
	case subGetPINRetries:
		b, _ := cbor.Marshal(map[uint64]any{cpRespPINRetries: a.retries, cpRespPowerCycle: false})
		return append([]byte{byte(StatusOK)}, b...)

	case subGetKeyAgreement:
		pub := a.priv.PublicKey().Bytes()
		b, _ := cbor.Marshal(map[uint64]any{cpRespKeyAgreement: map[int64]any{
			coseKty: coseKtyEC2, coseAlg: -25, coseCrv: coseCrvP256,
			coseX: pub[1:33], coseY: pub[33:],
		}})
		return append([]byte{byte(StatusOK)}, b...)

	case subGetPINToken, subGetTokenUsingPIN:
		// Agree from the authenticator's side, then check the PIN the way a
		// real one does: decrypt the hash and compare.
		var cose cbor.RawMessage
		if err := cbor.Unmarshal(req[cpKeyAgreement], &cose); err != nil {
			a.t.Fatalf("no key agreement in the token request: %v", err)
		}
		platform, err := coseToECDH(cose)
		if err != nil {
			a.t.Fatalf("the platform's key will not read: %v", err)
		}
		secret, err := a.priv.ECDH(platform)
		if err != nil {
			a.t.Fatal(err)
		}
		keys, err := deriveKeys(PINProtocol(proto), secret)
		if err != nil {
			a.t.Fatal(err)
		}
		var hashEnc []byte
		if err := cbor.Unmarshal(req[cpPinHashEnc], &hashEnc); err != nil {
			a.t.Fatalf("no encrypted PIN hash: %v", err)
		}
		got, err := keys.decrypt(hashEnc)
		if err != nil {
			a.t.Fatalf("the PIN hash will not decrypt: %v", err)
		}
		want := sha256.Sum256([]byte(a.pin))
		if !bytes.Equal(got, want[:16]) {
			a.retries--
			return []byte{0x31} // the PIN was wrong
		}
		enc, err := keys.encrypt(a.token)
		if err != nil {
			a.t.Fatal(err)
		}
		b, _ := cbor.Marshal(map[uint64]any{cpRespToken: enc})
		return append([]byte{byte(StatusOK)}, b...)
	}
	return []byte{0x01} // a command it does not know
}

func TestPINRetriesNeedsNoPIN(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	r, err := k.PINRetries(context.Background())
	if err != nil {
		t.Fatalf("PINRetries: %v", err)
	}
	if r.PIN != 8 || r.PowerCycle {
		t.Errorf("retries came back as %+v", r)
	}
	if len(a.asked) != 1 || a.asked[0] != subGetPINRetries {
		t.Errorf("the authenticator was asked %v", a.asked)
	}
}

func TestKeyAgreementNeedsNoPIN(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	pub, err := k.KeyAgreement(context.Background(), PINProtocolOne)
	if err != nil {
		t.Fatalf("KeyAgreement: %v", err)
	}
	if !pub.Equal(a.priv.PublicKey()) {
		t.Error("the key that came back is not the authenticator's")
	}
}

// TestAPINBuysAToken exercises the whole dance, with the authenticator
// checking the PIN from its own side.
func TestAPINBuysAToken(t *testing.T) {
	for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
		t.Run(proto.String(), func(t *testing.T) {
			a := newPINAuthenticator(t, "correct horse")
			k := ctap2Key(t, CapCBOR, a.reply)
			tok, err := k.PINToken(context.Background(), "correct horse", proto, PermGetAssertion, "example.test")
			if err != nil {
				t.Fatalf("PINToken: %v", err)
			}
			if !tok.Valid() {
				t.Fatal("the token is empty")
			}
			if tok.Protocol() != proto {
				t.Errorf("the token says %v", tok.Protocol())
			}
			if !bytes.Equal(tok.raw, a.token) {
				t.Error("the token that came back is not the one the authenticator issued")
			}
			// With permissions asked for, the CTAP 2.1 subcommand is the one
			// sent -- NINE, which is where prose summarising the specification
			// says eight.
			if last := a.asked[len(a.asked)-1]; last != subGetTokenUsingPIN {
				t.Errorf("the token was asked for with subcommand %d, want %d", last, subGetTokenUsingPIN)
			}
			// And the parameter it produces has the protocol's length.
			want := 16
			if proto == PINProtocolTwo {
				want = 32
			}
			if got := len(tok.authParam([]byte("hash"))); got != want {
				t.Errorf("%v authenticated with %d bytes, want %d", proto, got, want)
			}
		})
	}
}

// TestNoPermissionsAsksTheOlderWay: sending permissions of zero is not the
// same request as sending none, and some authenticators refuse it.
func TestNoPermissionsAsksTheOlderWay(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	if _, err := k.PINToken(context.Background(), "1234", PINProtocolOne, 0, ""); err != nil {
		t.Fatalf("PINToken: %v", err)
	}
	if last := a.asked[len(a.asked)-1]; last != subGetPINToken {
		t.Errorf("subcommand %d was sent, want the older %d", last, subGetPINToken)
	}
}

func TestAWrongPINCostsARetry(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	_, err := k.PINToken(context.Background(), "9999", PINProtocolOne, PermGetAssertion, "")
	if err == nil {
		t.Fatal("a wrong PIN was accepted")
	}
	if !strings.Contains(err.Error(), "PIN was wrong") {
		t.Errorf("the error says %q, which does not say the PIN was wrong", err)
	}
	if a.retries != 7 {
		t.Errorf("%d retries left; a wrong PIN costs one", a.retries)
	}
}

func TestAPINIsRefusedBeforeItIsSent(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	if _, err := k.PINToken(context.Background(), "", PINProtocolOne, 0, ""); err == nil {
		t.Error("an empty PIN was sent")
	}
	if len(a.asked) != 0 {
		t.Errorf("the authenticator was asked %v for an empty PIN", a.asked)
	}
}

func TestNothingPINRelatedIsSentToACTAP1OnlyKey(t *testing.T) {
	asked := false
	k := ctap2Key(t, CapWink, func(byte, []byte) []byte { asked = true; return []byte{0} })
	ctx := context.Background()
	if _, err := k.PINRetries(ctx); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("PINRetries = %v", err)
	}
	if _, err := k.KeyAgreement(ctx, PINProtocolOne); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("KeyAgreement = %v", err)
	}
	if _, err := k.PINToken(ctx, "1234", PINProtocolOne, 0, ""); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("PINToken = %v", err)
	}
	if asked {
		t.Error("a CTAP1-only key was asked anyway")
	}
}

func TestATokenAuthorisesARequest(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	tok, err := k.PINToken(context.Background(), "1234", PINProtocolTwo, PermMakeCredential, "example.test")
	if err != nil {
		t.Fatalf("PINToken: %v", err)
	}

	// Now a registration under that token, watching what goes out.
	var seen map[uint64]cbor.RawMessage
	reply := mustCBOR(t, map[uint64]any{mcRespFmt: "none", mcRespAuthData: referenceAuthData(t)})
	k2 := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd == CmdMakeCredential {
			seen = decodeRequest(t, params)
		}
		return append([]byte{byte(StatusOK)}, reply...)
	})
	hash := []byte("0123456789abcdef0123456789abcdef")
	if _, err := k2.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: hash,
		RP:             RelyingParty{ID: "example.test"},
		User:           User{ID: []byte("u")},
		Token:          tok,
	}); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	var param []byte
	if err := cbor.Unmarshal(seen[mcPinUvAuthParam], &param); err != nil {
		t.Fatalf("no pinUvAuthParam was sent: %v", err)
	}
	// The parameter is over the CLIENT DATA HASH, so an authenticator can tell
	// that whoever holds the token chose what is being signed.
	if !bytes.Equal(param, tok.authParam(hash)) {
		t.Error("the parameter is not the token's authentication of the client data hash")
	}
	var sentProto int
	if err := cbor.Unmarshal(seen[mcPinUvAuthProtocol], &sentProto); err != nil {
		t.Fatalf("no protocol was sent alongside: %v", err)
	}
	if PINProtocol(sentProto) != PINProtocolTwo {
		t.Errorf("protocol %d was sent with a protocol-two token", sentProto)
	}

	// And an assertion, the same way.
	var seenGA map[uint64]cbor.RawMessage
	gaReply := mustCBOR(t, map[uint64]any{
		gaRespAuthData: build(FlagUP|FlagUV, 1, nil), gaRespSignature: []byte("s"),
	})
	k3 := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd == CmdGetAssertion {
			seenGA = decodeRequest(t, params)
		}
		return append([]byte{byte(StatusOK)}, gaReply...)
	})
	if _, err := k3.GetAssertion(context.Background(), GetAssertionRequest{
		RPID: "example.test", ClientDataHash: hash, Token: tok,
	}); err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}
	if _, sent := seenGA[gaPinUvAuthParam]; !sent {
		t.Error("an assertion under a token sent no pinUvAuthParam")
	}
}

// TestAnInvalidTokenAuthorisesNothing: the zero Token must not put an empty
// parameter on the wire, which an authenticator would read as a failed
// verification rather than as none attempted.
func TestAnInvalidTokenAuthorisesNothing(t *testing.T) {
	var seen map[uint64]cbor.RawMessage
	reply := mustCBOR(t, map[uint64]any{mcRespFmt: "none", mcRespAuthData: referenceAuthData(t)})
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd == CmdMakeCredential {
			seen = decodeRequest(t, params)
		}
		return append([]byte{byte(StatusOK)}, reply...)
	})
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")},
	}); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	if _, sent := seen[mcPinUvAuthParam]; sent {
		t.Error("a request with no token still carried a pinUvAuthParam")
	}
	if _, sent := seen[mcPinUvAuthProtocol]; sent {
		t.Error("a request with no token still named a protocol")
	}
}

func TestTheCOSEAgreementKeyRoundTrips(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ecdhToCOSE(priv.PublicKey())
	if err != nil {
		t.Fatalf("ecdhToCOSE: %v", err)
	}
	// The algorithm is ECDH-ES+HKDF-256, not ES256: this key agrees, it does
	// not sign, and an authenticator that checks refuses the wrong one.
	if m[coseAlg] != -25 {
		t.Errorf("the agreement key claims algorithm %v, want -25", m[coseAlg])
	}
	raw, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := coseToECDH(raw)
	if err != nil {
		t.Fatalf("coseToECDH: %v", err)
	}
	if !back.Equal(priv.PublicKey()) {
		t.Error("the key did not survive the round trip")
	}
}

func TestTheAgreementKeyRefusesWhatItCannotRead(t *testing.T) {
	for _, c := range []struct {
		name string
		key  any
		want string
	}{
		{"not a map", 42, "not a COSE map"},
		{"no x", map[int64]any{coseY: make([]byte, 32)}, "no x coordinate"},
		{"no y", map[int64]any{coseX: make([]byte, 32)}, "no y coordinate"},
		{"an x that is not bytes", map[int64]any{coseX: "x", coseY: make([]byte, 32)}, "x coordinate"},
		{"coordinates of the wrong width", map[int64]any{coseX: make([]byte, 8), coseY: make([]byte, 32)}, "P-256 uses 32"},
		{"a point not on the curve", map[int64]any{coseX: make([]byte, 32), coseY: make([]byte, 32)}, "not a P-256 point"},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := cbor.Marshal(c.key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coseToECDH(raw); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

func TestAKeyAgreementReplyThatIsNotOne(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply []byte
		want  string
	}{
		{"not a map", []byte{byte(StatusOK), 0x01}, "not a CBOR map"},
		{"no key in it", append([]byte{byte(StatusOK)}, mustCBOR(t, map[uint64]any{})...), "offered no key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return c.reply })
			if _, err := k.KeyAgreement(context.Background(), PINProtocolOne); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q", err)
			}
		})
	}
}

func TestARetryReplyThatIsNotOne(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply []byte
		want  string
	}{
		{"not a map", []byte{byte(StatusOK), 0x01}, "not a CBOR map"},
		{"no count", append([]byte{byte(StatusOK)}, mustCBOR(t, map[uint64]any{})...), "retry count"},
		{"a power-cycle state that is not a boolean", append([]byte{byte(StatusOK)},
			mustCBOR(t, map[uint64]any{cpRespPINRetries: 3, cpRespPowerCycle: "yes"})...), "power-cycle"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return c.reply })
			if _, err := k.PINRetries(context.Background()); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q", err)
			}
		})
	}
}

func TestATokenReplyThatIsNotOne(t *testing.T) {
	a := newPINAuthenticator(t, "1234")
	for _, c := range []struct {
		name  string
		token func(keys pinKeys) any
		want  string
	}{
		{"an empty token", func(pinKeys) any { return []byte{} }, "not a whole number of AES blocks"},
		{"a token that will not decrypt", func(pinKeys) any { return []byte{1, 2, 3} }, "will not decrypt"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
				var req map[uint64]cbor.RawMessage
				if err := cbor.Unmarshal(params, &req); err != nil {
					t.Fatal(err)
				}
				var sub int
				cbor.Unmarshal(req[cpSubCommand], &sub)
				if sub != subGetPINToken && sub != subGetTokenUsingPIN {
					return a.reply(cmd, params)
				}
				b, _ := cbor.Marshal(map[uint64]any{cpRespToken: c.token(pinKeys{})})
				return append([]byte{byte(StatusOK)}, b...)
			})
			if _, err := k.PINToken(context.Background(), "1234", PINProtocolOne, 0, ""); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
	// And a reply with no token at all.
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		var req map[uint64]cbor.RawMessage
		cbor.Unmarshal(params, &req)
		var sub int
		cbor.Unmarshal(req[cpSubCommand], &sub)
		if sub != subGetPINToken && sub != subGetTokenUsingPIN {
			return a.reply(cmd, params)
		}
		return append([]byte{byte(StatusOK)}, mustCBOR(t, map[uint64]any{})...)
	})
	if _, err := k.PINToken(context.Background(), "1234", PINProtocolOne, 0, ""); err == nil ||
		!strings.Contains(err.Error(), "token") {
		t.Errorf("a reply with no token = %v", err)
	}
	// And one that is not a map.
	k2 := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		var req map[uint64]cbor.RawMessage
		cbor.Unmarshal(params, &req)
		var sub int
		cbor.Unmarshal(req[cpSubCommand], &sub)
		if sub != subGetPINToken && sub != subGetTokenUsingPIN {
			return a.reply(cmd, params)
		}
		return []byte{byte(StatusOK), 0x01}
	})
	if _, err := k2.PINToken(context.Background(), "1234", PINProtocolOne, 0, ""); err == nil ||
		!strings.Contains(err.Error(), "not a CBOR map") {
		t.Errorf("a token reply that is not a map = %v", err)
	}
}

// TestTheKeyAgreementCanFailPartWay covers the paths where the exchange starts
// and something in it refuses: the agreement command itself, and the platform
// key that will not encode.
func TestTheKeyAgreementCanFailPartWay(t *testing.T) {
	// The agreement subcommand refuses, so the token dance stops there.
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0x35} })
	if _, err := k.PINToken(context.Background(), "1234", PINProtocolOne, 0, ""); err == nil ||
		!strings.Contains(err.Error(), "no PIN is set") {
		t.Errorf("PINToken with no PIN set on the key = %v", err)
	}
	if _, err := k.KeyAgreement(context.Background(), PINProtocolOne); err == nil {
		t.Error("KeyAgreement succeeded against a refusal")
	}
	if _, err := k.PINRetries(context.Background()); err == nil {
		t.Error("PINRetries succeeded against a refusal")
	}
	// An unimplemented protocol never reaches the wire: agree refuses first.
	a := newPINAuthenticator(t, "1234")
	k2 := ctap2Key(t, CapCBOR, a.reply)
	if _, err := k2.PINToken(context.Background(), "1234", PINProtocol(7), 0, ""); err == nil {
		t.Error("an unimplemented protocol was sent")
	}
}

// TestEcdhToCOSERefusesWhatIsNotAPoint. The check cannot be reached through the
// public API -- crypto/ecdh only produces uncompressed points -- so it is
// exercised directly rather than deleted: it is the guard that would catch a
// future curve whose encoding differs.
func TestEcdhToCOSERefusesWhatIsNotAPoint(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ecdhToCOSE(priv.PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "uncompressed point") {
		t.Errorf("an X25519 key = %v", err)
	}
}

// TestAKeyOnAnotherCurve covers the two places that would matter the day a
// second curve appears: an ECDH that will not agree, and a platform key whose
// encoding is not an uncompressed P-256 point. Both are unreachable today
// because everything here is P-256 -- and both are exactly what a future curve
// would walk into.
func TestAKeyOnAnotherCurve(t *testing.T) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A P-256 platform key cannot agree with an X25519 authenticator.
	if _, _, err := agree(PINProtocolOne, x.PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "will not agree") {
		t.Errorf("agree across curves = %v", err)
	}

	// And with BOTH sides on X25519 the agreement succeeds, so the refusal
	// lands where the key is encoded for the wire instead.
	old := newECDHKey
	t.Cleanup(func() { newECDHKey = old })
	newECDHKey = func() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		var req map[uint64]cbor.RawMessage
		if err := cbor.Unmarshal(params, &req); err != nil {
			t.Fatal(err)
		}
		var sub int
		if err := cbor.Unmarshal(req[cpSubCommand], &sub); err != nil {
			t.Fatal(err)
		}
		if sub == subGetKeyAgreement {
			// Answer with an X25519 point dressed as a COSE key, so the
			// agreement itself succeeds.
			pub := x.PublicKey().Bytes()
			b, _ := cbor.Marshal(map[uint64]any{cpRespKeyAgreement: map[int64]any{
				coseKty: coseKtyEC2, coseAlg: -25, coseCrv: coseCrvP256,
				coseX: pub, coseY: pub,
			}})
			return append([]byte{byte(StatusOK)}, b...)
		}
		return a.reply(cmd, params)
	})
	_, err = k.PINToken(context.Background(), "1234", PINProtocolOne, 0, "")
	if err == nil {
		t.Fatal("a key on another curve was accepted")
	}
	if !strings.Contains(err.Error(), "P-256 point") && !strings.Contains(err.Error(), "uncompressed point") {
		t.Errorf("the error says %q, which does not name the curve problem", err)
	}
}

// TestAPINHashThatCannotBeEncrypted: protocol two needs randomness to encrypt,
// and the PIN hash is the first thing it encrypts.
func TestAPINHashThatCannotBeEncrypted(t *testing.T) {
	old := randRead
	t.Cleanup(func() { randRead = old })
	a := newPINAuthenticator(t, "1234")
	k := ctap2Key(t, CapCBOR, a.reply)
	// Fail only once the agreement is done, so the failure lands on the hash.
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := k.PINToken(context.Background(), "1234", PINProtocolTwo, 0, ""); err == nil ||
		!strings.Contains(err.Error(), "initialisation vector") {
		t.Errorf("PINToken with no randomness = %v", err)
	}
}
