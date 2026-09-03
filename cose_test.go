// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// coseOf builds a COSE_Key from whatever labels a test wants, so a malformed
// one can be described exactly rather than approximated.
func coseOf(t *testing.T, m map[int64]any) cbor.RawMessage {
	t.Helper()
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// realP256 is a genuine key, so a test that expects success is not testing
// against numbers somebody made up.
func realP256(t *testing.T) (*ecdsa.PrivateKey, cbor.RawMessage) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := make([]byte, coseP256Size)
	y := make([]byte, coseP256Size)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return k, coseOf(t, map[int64]any{
		coseKty: coseKtyEC2, coseAlg: AlgES256, coseCrv: coseCrvP256,
		coseX: x, coseY: y,
	})
}

// TestPublicKeyOnTheReferenceSample: the sample from go-webauthn's tests
// carries a real credential, and its key must come out usable. This is the
// check that the COSE key's EXTENT was right -- a key cut one byte short does
// not decode, and one cut long is not on the curve.
func TestPublicKeyOnTheReferenceSample(t *testing.T) {
	a, err := ParseAuthData(referenceAuthData(t))
	if err != nil {
		t.Fatalf("ParseAuthData: %v", err)
	}
	pub, err := a.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Error("the key is not on P-256")
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		t.Error("the point is not on the curve, so the coordinates were misread")
	}
}

// TestAKeyThatVerifiesWhatItSigned is the whole point: convert, then check a
// signature the matching private key made.
func TestAKeyThatVerifiesWhatItSigned(t *testing.T) {
	priv, cose := realP256(t)
	a := AuthData{Flags: FlagAT, COSEKey: cose}
	pub, err := a.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	digest := [32]byte{1, 2, 3}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("a signature made by the matching private key did not verify")
	}
	if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Error("the coordinates did not survive the round trip")
	}
}

func TestPublicKeyRefusesWhatItCannotUse(t *testing.T) {
	_, good := realP256(t)
	var goodMap map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(good, &goodMap); err != nil {
		t.Fatal(err)
	}
	short := make([]byte, coseP256Size-1)

	for _, c := range []struct {
		name string
		key  cbor.RawMessage
		want string
	}{
		{"no credential at all", nil, "no credential"},
		{"not a COSE map", cbor.RawMessage{0x01}, "not a COSE map"},
		{"no key type", coseOf(t, map[int64]any{coseAlg: AlgES256, coseCrv: 1}), "states no key type"},
		{"no algorithm", coseOf(t, map[int64]any{coseKty: 2, coseCrv: 1}), "states no algorithm"},
		{"no curve", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256}), "states no curve"},
		{"a key type that is not a number", coseOf(t, map[int64]any{coseKty: "two", coseAlg: AlgES256, coseCrv: 1}), "key type"},
		{"RSA rather than EC", coseOf(t, map[int64]any{coseKty: 3, coseAlg: -257, coseCrv: 1}), "only P-256"},
		{"the wrong curve", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256, coseCrv: 2}), "only P-256"},
		{"no x", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256, coseCrv: 1, coseY: make([]byte, 32)}), "no x coordinate"},
		{"no y", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256, coseCrv: 1, coseX: make([]byte, 32)}), "no y coordinate"},
		{"an x that is not bytes", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256, coseCrv: 1, coseX: "x", coseY: make([]byte, 32)}), "x coordinate"},
		{"a coordinate of the wrong width", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256, coseCrv: 1, coseX: short, coseY: make([]byte, 32)}), "P-256 uses 32"},
		{"a point that is not on the curve", coseOf(t, map[int64]any{coseKty: 2, coseAlg: AlgES256, coseCrv: 1, coseX: make([]byte, 32), coseY: make([]byte, 32)}), "not on P-256"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := AuthData{COSEKey: c.key}
			if _, err := a.PublicKey(); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
	// The positive control: the same shape with real numbers is accepted, so
	// the refusals are about the keys and not about the function.
	if _, err := (AuthData{COSEKey: good}).PublicKey(); err != nil {
		t.Errorf("a real key was refused: %v", err)
	}
}

// TestACoordinateIsNotPadded. A short coordinate could be left-padded into
// something that looks valid; that would turn a malformed key into one that
// verifies nothing, silently.
func TestACoordinateIsNotPadded(t *testing.T) {
	priv, _ := realP256(t)
	x := make([]byte, coseP256Size)
	y := make([]byte, coseP256Size)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	a := AuthData{COSEKey: coseOf(t, map[int64]any{
		coseKty: coseKtyEC2, coseAlg: AlgES256, coseCrv: coseCrvP256,
		coseX: x[1:], coseY: y, // one byte short
	})}
	if _, err := a.PublicKey(); err == nil {
		t.Fatal("a 31-byte coordinate was accepted")
	}
}
