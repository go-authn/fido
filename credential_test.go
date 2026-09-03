// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// decodeRequest reads back what the package sent, so a test asserts on the
// PARAMETERS an authenticator would see rather than on the Go call.
func decodeRequest(t *testing.T, params []byte) map[uint64]cbor.RawMessage {
	t.Helper()
	var m map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(params, &m); err != nil {
		t.Fatalf("the request this package sent is not a CBOR map: %v", err)
	}
	return m
}

func str(t *testing.T, raw cbor.RawMessage) string {
	t.Helper()
	var s string
	if err := cbor.Unmarshal(raw, &s); err != nil {
		t.Fatalf("not a string: %v", err)
	}
	return s
}

func TestMakeCredentialSendsWhatTheSpecificationNumbers(t *testing.T) {
	var seen map[uint64]cbor.RawMessage
	body := referenceAuthData(t)
	reply, err := cbor.Marshal(map[uint64]any{
		mcRespFmt:      "none",
		mcRespAuthData: body,
		mcRespAttStmt:  map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd != CmdMakeCredential {
			t.Errorf("command %#02x, want makeCredential", cmd)
		}
		seen = decodeRequest(t, params)
		return append([]byte{byte(StatusOK)}, reply...)
	})

	att, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("0123456789abcdef0123456789abcdef"),
		RP:             RelyingParty{ID: "example.test", Name: "Example"},
		User:           User{ID: []byte("user-handle"), Name: "ada", DisplayName: "Ada"},
	})
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	if att.Format != "none" {
		t.Errorf("format %q", att.Format)
	}
	if !att.Parsed.Flags.Has(FlagAT) || len(att.Parsed.CredentialID) != 64 {
		t.Errorf("the authenticator data was not parsed: %v", att.Parsed)
	}

	// The parameters, by number.
	var rp struct {
		ID   string `cbor:"id"`
		Name string `cbor:"name"`
	}
	if err := cbor.Unmarshal(seen[mcRP], &rp); err != nil || rp.ID != "example.test" {
		t.Errorf("relying party came out as %+v (%v)", rp, err)
	}
	var algs []struct {
		Alg  int64  `cbor:"alg"`
		Type string `cbor:"type"`
	}
	if err := cbor.Unmarshal(seen[mcPubKeyCredParams], &algs); err != nil {
		t.Fatalf("algorithms: %v", err)
	}
	if len(algs) != 1 || algs[0].Alg != AlgES256 || algs[0].Type != "public-key" {
		t.Errorf("algorithms came out as %+v, want ES256 by default", algs)
	}
	if _, sent := seen[mcExcludeList]; sent {
		t.Error("an empty exclude list was sent; leaving it out is not the same as sending nothing")
	}
	if _, sent := seen[mcOptions]; sent {
		t.Error("empty options were sent")
	}
}

// TestAUserWithNoNameSendsNoName: an empty name is not a name that is the
// empty string, and some authenticators refuse the latter.
func TestAUserWithNoNameSendsNoName(t *testing.T) {
	var seen map[uint64]cbor.RawMessage
	reply, _ := cbor.Marshal(map[uint64]any{
		mcRespFmt: "none", mcRespAuthData: referenceAuthData(t),
	})
	k := ctap2Key(t, CapCBOR, func(_ byte, params []byte) []byte {
		seen = decodeRequest(t, params)
		return append([]byte{byte(StatusOK)}, reply...)
	})
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("h"),
		RP:             RelyingParty{ID: "example.test"},
		User:           User{ID: []byte("u")},
	}); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	var user map[string]cbor.RawMessage
	if err := cbor.Unmarshal(seen[mcUser], &user); err != nil {
		t.Fatal(err)
	}
	if _, sent := user["name"]; sent {
		t.Error("a name nobody gave was sent as an empty string")
	}
	if _, sent := user["id"]; !sent {
		t.Error("the user handle was not sent")
	}
}

func TestMakeCredentialRefusesAnIncompleteRequest(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0} })
	for _, c := range []struct {
		name string
		req  MakeCredentialRequest
		want string
	}{
		{"no client data hash", MakeCredentialRequest{RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")}}, "client data hash"},
		{"no relying party", MakeCredentialRequest{ClientDataHash: []byte("h"), User: User{ID: []byte("u")}}, "relying party id"},
		{"no user handle", MakeCredentialRequest{ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}}, "user handle"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := k.MakeCredential(context.Background(), c.req); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

func TestMakeCredentialRefusesAReplyThatIsNotOne(t *testing.T) {
	noAT, _ := cbor.Marshal(map[uint64]any{
		mcRespFmt:      "none",
		mcRespAuthData: build(FlagUP, 1, nil), // no credential in it
	})
	noAuthData, _ := cbor.Marshal(map[uint64]any{mcRespFmt: "none"})
	emptyAuthData, _ := cbor.Marshal(map[uint64]any{mcRespFmt: "none", mcRespAuthData: []byte{}})
	badAuthData, _ := cbor.Marshal(map[uint64]any{mcRespFmt: "none", mcRespAuthData: []byte{1, 2}})

	for _, c := range []struct {
		name  string
		reply []byte
		want  string
	}{
		{"not a map", []byte{0x01}, "not a CBOR map"},
		{"no format", mustCBOR(t, map[uint64]any{mcRespAuthData: []byte("x")}), "attestation format"},
		{"no authenticator data", noAuthData, "authenticator data"},
		{"empty authenticator data", emptyAuthData, "carried no authenticator data"},
		{"authenticator data that will not parse", badAuthData, "header alone"},
		{"no credential in it", noAT, "no credential in it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte {
				return append([]byte{byte(StatusOK)}, c.reply...)
			})
			_, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
				ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")},
			})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGetAssertionSendsAndReads(t *testing.T) {
	var seen map[uint64]cbor.RawMessage
	authData := build(FlagUP|FlagUV, 7, nil)
	reply := mustCBOR(t, map[uint64]any{
		gaRespCredential: map[string]any{"type": "public-key", "id": []byte("cred-1")},
		gaRespAuthData:   authData,
		gaRespSignature:  []byte("signature"),
		gaRespUser:       map[string]any{"id": []byte("user-handle")},
		gaRespAvailable:  uint(2),
	})
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd != CmdGetAssertion {
			t.Errorf("command %#02x, want getAssertion", cmd)
		}
		seen = decodeRequest(t, params)
		return append([]byte{byte(StatusOK)}, reply...)
	})

	a, err := k.GetAssertion(context.Background(), GetAssertionRequest{
		RPID:           "example.test",
		ClientDataHash: []byte("hash"),
		Allow:          []Credential{{ID: []byte("cred-1")}},
		Options:        map[string]bool{"up": true},
	})
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}
	if string(a.Signature) != "signature" || string(a.UserID) != "user-handle" {
		t.Errorf("assertion came back as %+v", a)
	}
	if string(a.Credential.ID) != "cred-1" || a.Credential.Type != "public-key" {
		t.Errorf("credential %+v", a.Credential)
	}
	if a.Available != 2 || !a.Parsed.Flags.Has(FlagUV) || a.Parsed.SignCount != 7 {
		t.Errorf("assertion details %+v", a)
	}
	if got := str(t, seen[gaRPID]); got != "example.test" {
		t.Errorf("relying party id sent as %q", got)
	}
	// A credential with no type given goes out as "public-key" rather than as
	// an empty string, which an authenticator would reject.
	var allow []struct {
		Type string `cbor:"type"`
		ID   []byte `cbor:"id"`
	}
	if err := cbor.Unmarshal(seen[gaAllowList], &allow); err != nil {
		t.Fatal(err)
	}
	if len(allow) != 1 || allow[0].Type != "public-key" {
		t.Errorf("allow list went out as %+v", allow)
	}
}

func TestGetAssertionRefusesWhatCannotBeAsked(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0} })
	for _, c := range []struct {
		name string
		req  GetAssertionRequest
		want string
	}{
		{"no relying party", GetAssertionRequest{ClientDataHash: []byte("h")}, "relying party id"},
		{"no client data hash", GetAssertionRequest{RPID: "a"}, "client data hash"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := k.GetAssertion(context.Background(), c.req); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q", err)
			}
		})
	}
}

// TestAnAssertionWithNoSignatureProvesNothing, and must not come back as a
// success a caller might act on.
func TestAnAssertionWithNoSignatureProvesNothing(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply map[uint64]any
		want  string
	}{
		{"no authenticator data", map[uint64]any{gaRespSignature: []byte("s")}, "authenticator data"},
		{"empty authenticator data", map[uint64]any{gaRespAuthData: []byte{}, gaRespSignature: []byte("s")}, "carried no authenticator data"},
		{"authenticator data that will not parse", map[uint64]any{gaRespAuthData: []byte{1}, gaRespSignature: []byte("s")}, "header alone"},
		{"no signature", map[uint64]any{gaRespAuthData: build(FlagUP, 1, nil)}, "signature"},
		{"an empty signature", map[uint64]any{gaRespAuthData: build(FlagUP, 1, nil), gaRespSignature: []byte{}}, "proves nothing"},
		{"a credential that will not decode", map[uint64]any{
			gaRespAuthData: build(FlagUP, 1, nil), gaRespSignature: []byte("s"),
			gaRespCredential: "not a map"}, "assertion's credential"},
		{"a user that will not decode", map[uint64]any{
			gaRespAuthData: build(FlagUP, 1, nil), gaRespSignature: []byte("s"),
			gaRespUser: "not a map"}, "assertion's user"},
		{"a count that will not decode", map[uint64]any{
			gaRespAuthData: build(FlagUP, 1, nil), gaRespSignature: []byte("s"),
			gaRespAvailable: "not a number"}, "credential count"},
	} {
		t.Run(c.name, func(t *testing.T) {
			reply := mustCBOR(t, c.reply)
			k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte {
				return append([]byte{byte(StatusOK)}, reply...)
			})
			_, err := k.GetAssertion(context.Background(), GetAssertionRequest{
				RPID: "a", ClientDataHash: []byte("h"),
			})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
	// And a reply that is not a map at all.
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{byte(StatusOK), 0x01} })
	if _, err := k.GetAssertion(context.Background(), GetAssertionRequest{
		RPID: "a", ClientDataHash: []byte("h"),
	}); err == nil || !strings.Contains(err.Error(), "not a CBOR map") {
		t.Errorf("a reply that is not a map = %v", err)
	}
}

func TestNeitherCommandIsSentToACTAP1OnlyKey(t *testing.T) {
	asked := false
	k := ctap2Key(t, CapWink, func(byte, []byte) []byte { asked = true; return []byte{0} })
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")},
	}); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("MakeCredential on a CTAP1-only key = %v", err)
	}
	if _, err := k.GetAssertion(context.Background(), GetAssertionRequest{
		RPID: "a", ClientDataHash: []byte("h"),
	}); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("GetAssertion on a CTAP1-only key = %v", err)
	}
	if asked {
		t.Error("a key that cannot speak CTAP2 was asked anyway")
	}
}

// TestAnExcludeListAndOptionsAreSentWhenGiven, which the earlier test only
// checked the absence of.
func TestAnExcludeListAndOptionsAreSentWhenGiven(t *testing.T) {
	var seen map[uint64]cbor.RawMessage
	reply := mustCBOR(t, map[uint64]any{mcRespFmt: "none", mcRespAuthData: referenceAuthData(t)})
	k := ctap2Key(t, CapCBOR, func(_ byte, params []byte) []byte {
		seen = decodeRequest(t, params)
		return append([]byte{byte(StatusOK)}, reply...)
	})
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("h"),
		RP:             RelyingParty{ID: "a"},
		User:           User{ID: []byte("u")},
		Algorithms:     []int64{-257, AlgES256},
		Exclude:        []Credential{{Type: "public-key", ID: []byte("old"), Transports: []string{"usb"}}},
		Options:        map[string]bool{"rk": true},
	}); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	if _, sent := seen[mcExcludeList]; !sent {
		t.Error("the exclude list was not sent")
	}
	var opts map[string]bool
	if err := cbor.Unmarshal(seen[mcOptions], &opts); err != nil || !opts["rk"] {
		t.Errorf("options went out as %v (%v)", opts, err)
	}
	var algs []struct {
		Alg int64 `cbor:"alg"`
	}
	if err := cbor.Unmarshal(seen[mcPubKeyCredParams], &algs); err != nil {
		t.Fatal(err)
	}
	if len(algs) != 2 || algs[0].Alg != -257 {
		t.Errorf("algorithms went out as %+v, and order is a preference", algs)
	}
}

// TestARequestThatCannotBeEncoded. The check is defensive -- nothing the public
// API accepts can reach it -- so it is exercised directly rather than removed:
// cborCall is where a future parameter type would fail, and failing there with
// a sentence beats a panic from inside the CBOR library.
func TestARequestThatCannotBeEncoded(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0} })
	_, err := k.cborCall(context.Background(), CmdGetInfo, map[int]any{1: make(chan int)})
	if err == nil || !strings.Contains(err.Error(), "cannot encode the request") {
		t.Errorf("an unencodable request = %v", err)
	}
}

// TestAReplyFieldOfTheWrongType: a present field this package cannot read means
// the reply is not what it claims, which is an error rather than a zero value.
func TestAReplyFieldOfTheWrongType(t *testing.T) {
	reply := mustCBOR(t, map[uint64]any{
		mcRespFmt:      42, // a number where the format goes
		mcRespAuthData: referenceAuthData(t),
	})
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte {
		return append([]byte{byte(StatusOK)}, reply...)
	})
	_, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")},
	})
	if err == nil || !strings.Contains(err.Error(), "attestation format") {
		t.Errorf("a format that is a number = %v", err)
	}
}

// TestAnAttestationStatementIsKeptWhenSent, and its absence is not an error:
// the "none" format has no statement worth keeping.
func TestAnAttestationStatementIsKeptWhenSent(t *testing.T) {
	with := mustCBOR(t, map[uint64]any{
		mcRespFmt: "packed", mcRespAuthData: referenceAuthData(t),
		mcRespAttStmt: map[string]any{"alg": AlgES256, "sig": []byte("sig")},
	})
	without := mustCBOR(t, map[uint64]any{
		mcRespFmt: "none", mcRespAuthData: referenceAuthData(t),
	})
	req := MakeCredentialRequest{
		ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")},
	}
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte {
		return append([]byte{byte(StatusOK)}, with...)
	})
	att, err := k.MakeCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	if len(att.Statement) == 0 {
		t.Error("the attestation statement was dropped")
	}
	var stmt map[string]cbor.RawMessage
	if err := cbor.Unmarshal(att.Statement, &stmt); err != nil || stmt["sig"] == nil {
		t.Errorf("the statement did not survive as CBOR: %v", err)
	}

	k2 := ctap2Key(t, CapCBOR, func(byte, []byte) []byte {
		return append([]byte{byte(StatusOK)}, without...)
	})
	att2, err := k2.MakeCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("MakeCredential with no statement: %v", err)
	}
	if att2.Statement != nil {
		t.Error("a statement appeared where none was sent")
	}
}

// TestNobodyTouchedTheKey is the ordinary failure, not an exotic one: the
// person walked away, or never noticed the key was blinking. Both commands
// must report it in words rather than as a malformed reply.
func TestNobodyTouchedTheKey(t *testing.T) {
	refuse := func(byte, []byte) []byte { return []byte{0x3A} } // action timed out
	k := ctap2Key(t, CapCBOR, refuse)
	if _, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: []byte("h"), RP: RelyingParty{ID: "a"}, User: User{ID: []byte("u")},
	}); err == nil || !strings.Contains(err.Error(), "did not touch") {
		t.Errorf("a registration nobody touched = %v", err)
	}
	k2 := ctap2Key(t, CapCBOR, refuse)
	if _, err := k2.GetAssertion(context.Background(), GetAssertionRequest{
		RPID: "a", ClientDataHash: []byte("h"),
	}); err == nil || !strings.Contains(err.Error(), "did not touch") {
		t.Errorf("an assertion nobody touched = %v", err)
	}
}
