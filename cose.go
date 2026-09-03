// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// The COSE_Key labels used here, as RFC 8152 numbers them. Negative labels are
// per-algorithm; these are the EC2 ones.
const (
	coseKty = 1
	coseAlg = 3
	coseCrv = -1
	coseX   = -2
	coseY   = -3

	coseKtyEC2   = 2
	coseCrvP256  = 1
	coseP256Size = 32
)

// PublicKey turns the credential's COSE key into an ECDSA public key.
//
// Only P-256 with ES256 is decoded, which is not a limitation in practice: it
// is the one algorithm every FIDO authenticator supports and the one this
// package asks for by default. Anything else is refused by name rather than
// half-decoded, because a key of the wrong curve that verified nothing would be
// worse than no key at all.
//
// This is a CONVERSION and not a verification. Checking a signature needs a
// decision about what counts as valid -- which algorithms, what to do with a
// sign counter that went backwards -- and that decision belongs to whoever is
// protecting something. crypto/ecdsa is the standard library, so returning one
// of its keys imposes no choice on anybody.
//
// The signature an assertion carries is over the authenticator data followed by
// the client data hash, in that order, hashed with SHA-256:
//
//	signed := append(append([]byte{}, a.AuthData...), clientDataHash...)
//	digest := sha256.Sum256(signed)
//	ok := ecdsa.VerifyASN1(pub, digest[:], a.Signature)
func (a AuthData) PublicKey() (*ecdsa.PublicKey, error) {
	if len(a.COSEKey) == 0 {
		return nil, fmt.Errorf("fido: this authenticator data carries no credential, so there is no key in it")
	}
	var m map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(a.COSEKey, &m); err != nil {
		return nil, fmt.Errorf("fido: the credential's key is not a COSE map: %w", err)
	}
	var kty, alg, crv int64
	for _, f := range []struct {
		label int64
		into  *int64
		what  string
	}{
		{coseKty, &kty, "key type"},
		{coseAlg, &alg, "algorithm"},
		{coseCrv, &crv, "curve"},
	} {
		r, ok := m[f.label]
		if !ok {
			return nil, fmt.Errorf("fido: the credential's key states no %s", f.what)
		}
		if err := cbor.Unmarshal(r, f.into); err != nil {
			return nil, fmt.Errorf("fido: the credential's %s: %w", f.what, err)
		}
	}
	if kty != coseKtyEC2 || alg != AlgES256 || crv != coseCrvP256 {
		return nil, fmt.Errorf("fido: the credential's key is kty %d, algorithm %d, curve %d; only P-256 with ES256 is decoded here",
			kty, alg, crv)
	}
	var x, y []byte
	for _, f := range []struct {
		label int64
		into  *[]byte
		what  string
	}{{coseX, &x, "x"}, {coseY, &y, "y"}} {
		r, ok := m[f.label]
		if !ok {
			return nil, fmt.Errorf("fido: the credential's key has no %s coordinate", f.what)
		}
		if err := cbor.Unmarshal(r, f.into); err != nil {
			return nil, fmt.Errorf("fido: the credential's %s coordinate: %w", f.what, err)
		}
	}
	// A coordinate of the wrong width is not padded here. P-256 coordinates
	// are 32 bytes and a shorter one means the key is not what it says it is;
	// left-padding it would turn a malformed key into a valid-looking one that
	// verifies nothing.
	if len(x) != coseP256Size || len(y) != coseP256Size {
		return nil, fmt.Errorf("fido: the credential's coordinates are %d and %d bytes; P-256 uses %d",
			len(x), len(y), coseP256Size)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("fido: the credential's point is not on P-256")
	}
	return pub, nil
}
