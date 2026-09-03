// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestBothSidesDeriveTheSameSecret is the invariant the whole PIN dance rests
// on. It is checked by playing the authenticator as well as the platform: if
// the two derivations disagree, nothing else in this file can be right, and no
// amount of round-tripping against oneself would notice.
func TestBothSidesDeriveTheSameSecret(t *testing.T) {
	for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
		t.Run(proto.String(), func(t *testing.T) {
			// The authenticator's key.
			authPriv, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			// The platform agrees with it.
			ownCOSE, platform, err := agree(proto, authPriv.PublicKey())
			if err != nil {
				t.Fatalf("agree: %v", err)
			}
			// The authenticator agrees back, from its side -- reading the
			// platform's key off the wire the way it really would, which also
			// checks that what agree produces is what coseToECDH accepts.
			ownWire, err := cbor.Marshal(ownCOSE)
			if err != nil {
				t.Fatal(err)
			}
			ownPub, err := coseToECDH(ownWire)
			if err != nil {
				t.Fatalf("the platform's key will not read back: %v", err)
			}
			secret, err := authPriv.ECDH(ownPub)
			if err != nil {
				t.Fatal(err)
			}
			authenticator, err := deriveKeys(proto, secret)
			if err != nil {
				t.Fatalf("deriveKeys: %v", err)
			}
			if !bytes.Equal(platform.aes, authenticator.aes) {
				t.Error("the two sides derived different AES keys")
			}
			if !bytes.Equal(platform.hmac, authenticator.hmac) {
				t.Error("the two sides derived different HMAC keys")
			}
			// And what one encrypts, the other reads.
			msg := bytes.Repeat([]byte("sixteen bytes!!!"), 2)
			enc, err := platform.encrypt(msg)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := authenticator.decrypt(enc)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Error("the authenticator read something else")
			}
		})
	}
}

// TestTheTwoProtocolsAreGenuinelyDifferent. Protocol two exists to separate
// the encryption key from the authentication key and to stop reusing one
// initialisation vector; a package that treated them as a version number would
// pass every round-trip test and be wrong on the wire.
func TestTheTwoProtocolsAreGenuinelyDifferent(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)

	one, err := deriveKeys(PINProtocolOne, secret)
	if err != nil {
		t.Fatal(err)
	}
	two, err := deriveKeys(PINProtocolTwo, secret)
	if err != nil {
		t.Fatal(err)
	}
	// One: the same 32 bytes serve both purposes, and they are SHA-256 of the
	// secret.
	if !bytes.Equal(one.aes, one.hmac) {
		t.Error("protocol one derived two different keys")
	}
	sum := sha256.Sum256(secret)
	if !bytes.Equal(one.aes, sum[:]) {
		t.Error("protocol one's key is not SHA-256 of the secret")
	}
	// Two: two different keys, neither of them the plain hash.
	if bytes.Equal(two.aes, two.hmac) {
		t.Error("protocol two derived the same key twice, which is what it exists to avoid")
	}
	if bytes.Equal(two.aes, sum[:]) || bytes.Equal(two.hmac, sum[:]) {
		t.Error("protocol two used the plain hash rather than HKDF")
	}

	// One truncates its HMAC to sixteen bytes and two does not. Sending the
	// wrong length is refused by an authenticator.
	if got := len(one.authenticate([]byte("x"))); got != 16 {
		t.Errorf("protocol one authenticated with %d bytes, want 16", got)
	}
	if got := len(two.authenticate([]byte("x"))); got != 32 {
		t.Errorf("protocol two authenticated with %d bytes, want 32", got)
	}

	// One uses a zero IV, so it is deterministic. Two uses a fresh one and
	// prepends it, so it is not -- and is a block longer.
	msg := []byte("sixteen bytes!!!")
	a1, _ := one.encrypt(msg)
	b1, _ := one.encrypt(msg)
	if !bytes.Equal(a1, b1) {
		t.Error("protocol one is not deterministic, so its IV is not zero")
	}
	if len(a1) != aes.BlockSize {
		t.Errorf("protocol one produced %d bytes for one block", len(a1))
	}
	a2, _ := two.encrypt(msg)
	b2, _ := two.encrypt(msg)
	if bytes.Equal(a2, b2) {
		t.Error("protocol two produced the same ciphertext twice, so its IV is not fresh")
	}
	if len(a2) != 2*aes.BlockSize {
		t.Errorf("protocol two produced %d bytes; one block plus a prepended IV is %d", len(a2), 2*aes.BlockSize)
	}
	// And it still decrypts, which is what proves the IV travelled.
	if got, err := two.decrypt(a2); err != nil || !bytes.Equal(got, msg) {
		t.Errorf("protocol two round trip: %q (%v)", got, err)
	}
}

func TestAPINHashIsSixteenBytesOfTheDigest(t *testing.T) {
	keys, err := deriveKeys(PINProtocolOne, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := keys.pinHash("1234")
	if err != nil {
		t.Fatalf("pinHash: %v", err)
	}
	if len(enc) != aes.BlockSize {
		t.Errorf("the encrypted hash is %d bytes; sixteen of the digest is one block", len(enc))
	}
	got, err := keys.decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("1234"))
	if !bytes.Equal(got, sum[:16]) {
		t.Error("what was encrypted is not the first sixteen bytes of the PIN's SHA-256")
	}
	// The other half never travels.
	if bytes.Contains(enc, sum[16:]) {
		t.Error("the second half of the digest appears in the ciphertext")
	}
	if _, err := keys.pinHash(""); err == nil {
		t.Error("an empty PIN was accepted")
	}
}

func TestTheProtocolsRefuseWhatTheyCannotDo(t *testing.T) {
	if _, err := deriveKeys(PINProtocol(3), make([]byte, 32)); err == nil {
		t.Error("an unimplemented protocol was accepted")
	} else if !strings.Contains(err.Error(), "PIN protocol 3") {
		t.Errorf("the error says %q, which does not name the protocol", err)
	}
	one, _ := deriveKeys(PINProtocolOne, make([]byte, 32))
	two, _ := deriveKeys(PINProtocolTwo, make([]byte, 32))
	for _, c := range []struct {
		name string
		run  func() error
		want string
	}{
		{"nothing to encrypt", func() error { _, err := one.encrypt(nil); return err }, "whole number of AES blocks"},
		{"a part block", func() error { _, err := one.encrypt(make([]byte, 17)); return err }, "whole number of AES blocks"},
		{"nothing to decrypt", func() error { _, err := one.decrypt(nil); return err }, "whole number of AES blocks"},
		{"a part block back", func() error { _, err := one.decrypt(make([]byte, 5)); return err }, "whole number of AES blocks"},
		{"too few bytes for an IV", func() error { _, err := two.decrypt(make([]byte, 4)); return err }, "hold an initialisation vector"},
		{"an IV and nothing else", func() error { _, err := two.decrypt(make([]byte, aes.BlockSize)); return err }, "whole number of AES blocks"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
	// A derived key that is not an AES key cannot happen through the public
	// API; the check is exercised directly so a future protocol that derives a
	// different length fails with a sentence rather than a panic.
	bad := pinKeys{proto: PINProtocolOne, aes: make([]byte, 7), hmac: make([]byte, 7)}
	if _, err := bad.encrypt(make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "not an AES key") {
		t.Errorf("a 7-byte key = %v", err)
	}
	if _, err := bad.decrypt(make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "not an AES key") {
		t.Errorf("a 7-byte key on the way back = %v", err)
	}
}

func TestAgreeRefusesAKeyThatWillNotAgree(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := agree(PINProtocol(9), priv.PublicKey()); err == nil {
		t.Error("agree accepted an unimplemented protocol")
	}
}

func TestProtocolsAreNamed(t *testing.T) {
	if got := PINProtocolOne.String(); got != "PIN protocol 1" {
		t.Errorf("PINProtocolOne = %q", got)
	}
	if got := PINProtocolTwo.String(); got != "PIN protocol 2" {
		t.Errorf("PINProtocolTwo = %q", got)
	}
}

// TestWhatCannotFailIsStillHandled. With crypto/rand none of these can happen
// -- since Go 1.24 rand.Read panics rather than returning an error -- so the
// handling is unreachable in practice. It is kept because a future reader with
// a different source would need it, and driven here so it is not dead weight
// nobody has ever run.
func TestWhatCannotFailIsStillHandled(t *testing.T) {
	boom := errors.New("no entropy")

	t.Run("no randomness for an initialisation vector", func(t *testing.T) {
		old := randRead
		t.Cleanup(func() { randRead = old })
		randRead = func([]byte) (int, error) { return 0, boom }
		two, err := deriveKeys(PINProtocolTwo, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := two.encrypt(make([]byte, 16)); err == nil ||
			!strings.Contains(err.Error(), "initialisation vector") {
			t.Errorf("encrypt with no randomness = %v", err)
		}
		// Protocol one needs none: its vector is zeroes.
		one, _ := deriveKeys(PINProtocolOne, make([]byte, 32))
		if _, err := one.encrypt(make([]byte, 16)); err != nil {
			t.Errorf("protocol one needed randomness it should not: %v", err)
		}
	})

	t.Run("no key to agree with", func(t *testing.T) {
		old := newECDHKey
		t.Cleanup(func() { newECDHKey = old })
		newECDHKey = func() (*ecdh.PrivateKey, error) { return nil, boom }
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := agree(PINProtocolOne, priv.PublicKey()); err == nil ||
			!strings.Contains(err.Error(), "make a key to agree with") {
			t.Errorf("agree with no key = %v", err)
		}
	})

	t.Run("HKDF refusing", func(t *testing.T) {
		old := hkdfKey
		t.Cleanup(func() { hkdfKey = old })
		calls := 0
		hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, n int) ([]byte, error) {
			calls++
			if calls == 1 {
				return nil, boom
			}
			return old(h, secret, salt, info, n)
		}
		if _, err := deriveKeys(PINProtocolTwo, make([]byte, 32)); err == nil ||
			!strings.Contains(err.Error(), "HMAC key") {
			t.Errorf("the first HKDF failing = %v", err)
		}
		// And the second, which is a different message.
		calls = 1
		if _, err := deriveKeys(PINProtocolTwo, make([]byte, 32)); err != nil {
			t.Errorf("the second call should have succeeded: %v", err)
		}
		calls = 0
		hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, n int) ([]byte, error) {
			calls++
			if calls == 2 {
				return nil, boom
			}
			return old(h, secret, salt, info, n)
		}
		if _, err := deriveKeys(PINProtocolTwo, make([]byte, 32)); err == nil ||
			!strings.Contains(err.Error(), "AES key") {
			t.Errorf("the second HKDF failing = %v", err)
		}
	})

	// An agreement whose derivation refuses: the ECDH succeeded and the
	// protocol did not.
	t.Run("a protocol nothing implements", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := agree(PINProtocol(4), priv.PublicKey()); err == nil {
			t.Error("agree accepted protocol 4")
		}
	})
}

// TestOurOwnKeyIsCheckedFirst. agree encodes the platform's key before it
// touches the authenticator's: our own key not fitting the wire format is our
// fault, and finding out before the exchange is both more honest and the only
// way the check is reachable.
func TestOurOwnKeyIsCheckedFirst(t *testing.T) {
	old := newECDHKey
	t.Cleanup(func() { newECDHKey = old })
	newECDHKey = func() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

	auth, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = agree(PINProtocolOne, auth.PublicKey())
	if err == nil {
		t.Fatal("agree encoded a key that is not a P-256 point")
	}
	// The complaint is about OUR key, not about the authenticator's refusal to
	// agree -- which is what "checked first" means.
	if !strings.Contains(err.Error(), "uncompressed point") {
		t.Errorf("the error says %q, which is not about the platform's own key", err)
	}
}
