// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// referenceAuthData is a registration's authenticator data taken from the test
// suite of go-webauthn/webauthn, the reference WebAuthn implementation in Go.
//
// It is an EXTERNAL witness. Every other fixture in this package was produced
// by hardware or by this code; this one was produced by neither, so it is the
// only one that can catch the two agreeing with each other and both being
// wrong.
func referenceAuthData(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/webauthn-reference-authdata.b64")
	if err != nil {
		t.Fatalf("the reference sample is missing: %v", err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("the reference sample is not base64: %v", err)
	}
	return b
}

func TestParseAuthDataOnTheReferenceSample(t *testing.T) {
	a, err := ParseAuthData(referenceAuthData(t))
	if err != nil {
		t.Fatalf("ParseAuthData: %v", err)
	}
	// Flags 0x41: a person touched it, and a credential follows. NOT verified
	// -- the prose describing this sample elsewhere says 0x45, and the bytes
	// say 0x41. The bytes win.
	if byte(a.Flags) != 0x41 {
		t.Errorf("flags %#02x, want 0x41", byte(a.Flags))
	}
	if !a.Flags.Has(FlagUP) || !a.Flags.Has(FlagAT) {
		t.Error("the flags do not say present and attested")
	}
	if a.Flags.Has(FlagUV) {
		t.Error("the flags claim the person was verified, which this sample does not say")
	}
	if a.SignCount != 0 {
		t.Errorf("sign count %d", a.SignCount)
	}
	if len(a.CredentialID) != 64 {
		t.Errorf("credential id is %d bytes, want 64", len(a.CredentialID))
	}
	// The public key is CBOR of unstated length, and finding where it ends is
	// the hard part of this layout. It ends exactly at the end of the data:
	// one byte over or under and the check below fails.
	if len(a.COSEKey) != 77 {
		t.Errorf("public key is %d bytes, want 77", len(a.COSEKey))
	}
	var key map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(a.COSEKey, &key); err != nil {
		t.Errorf("the public key is not a COSE map: %v", err)
	}
	if len(a.Extensions) != 0 {
		t.Errorf("%d bytes of extensions in a sample that has none", len(a.Extensions))
	}
	if got := a.String(); !strings.Contains(got, "present") || !strings.Contains(got, "attested") {
		t.Errorf("String() = %q", got)
	}
}

// build makes authenticator data with the given flags and tail.
func build(flags Flags, count uint32, tail []byte) []byte {
	b := make([]byte, authDataHeader)
	for i := range b[:32] {
		b[i] = byte(i)
	}
	b[32] = byte(flags)
	binary.BigEndian.PutUint32(b[33:37], count)
	return append(b, tail...)
}

// attested builds the attested credential data section.
func attested(t *testing.T, credID []byte, extra []byte) []byte {
	t.Helper()
	key, err := cbor.Marshal(map[int64]any{1: 2, 3: -7})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, aaguidLen)
	for i := range out {
		out[i] = 0xAB
	}
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(credID)))
	out = append(out, n[:]...)
	out = append(out, credID...)
	out = append(out, key...)
	return append(out, extra...)
}

func TestParseAuthDataWithoutACredential(t *testing.T) {
	// An assertion: present, verified, nothing else.
	a, err := ParseAuthData(build(FlagUP|FlagUV, 42, nil))
	if err != nil {
		t.Fatalf("ParseAuthData: %v", err)
	}
	if !a.Flags.Has(FlagUV) || a.SignCount != 42 {
		t.Errorf("got %v", a)
	}
	if a.CredentialID != nil || a.COSEKey != nil {
		t.Error("an assertion came back carrying a credential")
	}
	if got := a.String(); strings.Contains(got, "credential") {
		t.Errorf("String() = %q, which mentions a credential", got)
	}
}

func TestParseAuthDataWithExtensions(t *testing.T) {
	ext, err := cbor.Marshal(map[string]bool{"hmac-secret": true})
	if err != nil {
		t.Fatal(err)
	}
	// Extensions after a credential, which is the awkward case: where the
	// public key ends decides where the extensions begin.
	a, err := ParseAuthData(build(FlagUP|FlagAT|FlagED, 1, attested(t, []byte("credential-id"), ext)))
	if err != nil {
		t.Fatalf("ParseAuthData: %v", err)
	}
	if string(a.CredentialID) != "credential-id" {
		t.Errorf("credential id %q", a.CredentialID)
	}
	var got map[string]bool
	if err := cbor.Unmarshal(a.Extensions, &got); err != nil || !got["hmac-secret"] {
		t.Errorf("extensions %x decoded as %v (%v)", a.Extensions, got, err)
	}
	// And extensions with NO credential, where they start right after the
	// header.
	b, err := ParseAuthData(build(FlagUP|FlagED, 1, ext))
	if err != nil {
		t.Fatalf("ParseAuthData without a credential: %v", err)
	}
	if len(b.Extensions) == 0 {
		t.Error("the extensions were not read")
	}
}

func TestParseAuthDataRefusesWhatDoesNotAddUp(t *testing.T) {
	longID := make([]byte, 8)
	tooLong := attested(t, longID, nil)
	binary.BigEndian.PutUint16(tooLong[aaguidLen:aaguidLen+2], 9999) // claims more than follows

	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"nothing at all", nil, "header alone"},
		{"a truncated header", make([]byte, 36), "header alone"},
		{"attested but too short for its own header", build(FlagUP|FlagAT, 1, []byte{1, 2, 3}), "too few for its own header"},
		{"a credential id longer than what follows", build(FlagUP|FlagAT, 1, tooLong), "9999 bytes and"},
		{"a public key that is not CBOR", build(FlagUP|FlagAT, 1, append(attested(t, []byte("x"), nil)[:aaguidLen+2+1], 0xFF, 0xFF)), "not CBOR"},
		{"extensions that are not CBOR", build(FlagUP|FlagED, 1, []byte{0xFF, 0xFF}), "not CBOR"},
		{"bytes nothing accounts for", build(FlagUP, 1, []byte{1, 2, 3}), "no flag accounts for"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseAuthData(c.in); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

func TestFlagsRead(t *testing.T) {
	all := FlagUP | FlagUV | FlagBE | FlagBS | FlagAT | FlagED
	got := all.String()
	for _, want := range []string{"present", "verified", "backup-eligible", "backed-up", "attested", "extensions"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not mention %q", got, want)
		}
	}
	if !all.Has(FlagUP | FlagUV) {
		t.Error("Has of two set bits said no")
	}
	if (FlagUP).Has(FlagUP | FlagUV) {
		t.Error("Has said yes for a bit that is not set")
	}
	if got := Flags(0).String(); !strings.Contains(got, "none") {
		t.Errorf("no flags at all renders as %q", got)
	}
}
