// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
)

// The randomness and the key generator are seams. Neither can fail with
// crypto/rand -- since Go 1.24 rand.Read panics rather than returning an error
// -- so the handling below is unreachable in practice and is kept anyway: it is
// what a future reader with a different source would need, and a test drives it
// so it is not dead weight nobody has ever run.
var (
	randRead   = rand.Read
	newECDHKey = func() (*ecdh.PrivateKey, error) { return ecdh.P256().GenerateKey(rand.Reader) }
	hkdfKey    = func(h func() hash.Hash, secret, salt []byte, info string, n int) ([]byte, error) {
		return hkdf.Key(h, secret, salt, info, n)
	}
)

// PINProtocol is a PIN/UV auth protocol version.
//
// Two exist and they differ in more than a number: protocol one hashes the
// ECDH output once and truncates its HMAC to sixteen bytes, protocol two
// derives two separate keys through HKDF and truncates nothing. An
// authenticator says which it supports in [Info.PINProtocols].
type PINProtocol int

// The protocols. Higher is better where an authenticator offers both:
// protocol two separates the encryption key from the authentication key and
// uses a fresh initialisation vector per message.
const (
	PINProtocolOne PINProtocol = 1
	PINProtocolTwo PINProtocol = 2
)

// String names the protocol.
func (p PINProtocol) String() string { return fmt.Sprintf("PIN protocol %d", int(p)) }

// pinKeys are the keys derived from one ECDH exchange.
//
// Protocol one uses the same 32 bytes for both, which is exactly the
// difference protocol two exists to remove.
type pinKeys struct {
	proto PINProtocol
	aes   []byte
	hmac  []byte
}

// deriveKeys turns an ECDH shared point into the keys the protocol uses.
//
// Protocol one: SHA-256 over the shared secret, and the same 32 bytes serve as
// both the AES key and the HMAC key.
//
// Protocol two: two HKDF-SHA-256 expansions of the same secret, with a
// thirty-two-byte zero salt and the info strings "CTAP2 HMAC key" and
// "CTAP2 AES key". The HMAC key comes FIRST in the concatenation, which is the
// order libfido2 writes and the order that matters if the two are ever
// serialised together.
func deriveKeys(proto PINProtocol, secret []byte) (pinKeys, error) {
	switch proto {
	case PINProtocolOne:
		sum := sha256.Sum256(secret)
		k := make([]byte, len(sum))
		copy(k, sum[:])
		return pinKeys{proto: proto, aes: k, hmac: k}, nil
	case PINProtocolTwo:
		salt := make([]byte, sha256.Size)
		hmacKey, err := hkdfKey(sha256.New, secret, salt, "CTAP2 HMAC key", sha256.Size)
		if err != nil {
			return pinKeys{}, fmt.Errorf("fido: deriving the HMAC key: %w", err)
		}
		aesKey, err := hkdfKey(sha256.New, secret, salt, "CTAP2 AES key", sha256.Size)
		if err != nil {
			return pinKeys{}, fmt.Errorf("fido: deriving the AES key: %w", err)
		}
		return pinKeys{proto: proto, aes: aesKey, hmac: hmacKey}, nil
	}
	return pinKeys{}, fmt.Errorf("fido: %s is not one this package implements", proto)
}

// encrypt encrypts plaintext for the authenticator.
//
// Both protocols use AES-256-CBC with no padding, so the plaintext must be a
// whole number of blocks -- everything CTAP2 sends this way already is. They
// differ in the initialisation vector: protocol one uses zeroes, protocol two
// uses a fresh random one and PREPENDS it to the ciphertext.
func (k pinKeys) encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("fido: %d bytes is not a whole number of AES blocks", len(plaintext))
	}
	block, err := aes.NewCipher(k.aes)
	if err != nil {
		return nil, fmt.Errorf("fido: the derived key is not an AES key: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if k.proto == PINProtocolTwo {
		if _, err := randRead(iv); err != nil {
			return nil, fmt.Errorf("fido: cannot make an initialisation vector: %w", err)
		}
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	if k.proto == PINProtocolTwo {
		return append(iv, out...), nil
	}
	return out, nil
}

// decrypt reverses [pinKeys.encrypt].
func (k pinKeys) decrypt(ciphertext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if k.proto == PINProtocolTwo {
		if len(ciphertext) < aes.BlockSize {
			return nil, fmt.Errorf("fido: %d bytes is too few to hold an initialisation vector", len(ciphertext))
		}
		copy(iv, ciphertext[:aes.BlockSize])
		ciphertext = ciphertext[aes.BlockSize:]
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("fido: %d bytes is not a whole number of AES blocks", len(ciphertext))
	}
	block, err := aes.NewCipher(k.aes)
	if err != nil {
		return nil, fmt.Errorf("fido: the derived key is not an AES key: %w", err)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

// authenticate is the pinUvAuthParam over data.
//
// Protocol one truncates the HMAC to sixteen bytes and protocol two does not.
// Sending the full thirty-two where sixteen are expected is refused by the
// authenticator, and sending sixteen where thirty-two are expected likewise,
// so the truncation is not cosmetic.
func (k pinKeys) authenticate(data []byte) []byte {
	mac := hmac.New(sha256.New, k.hmac)
	mac.Write(data)
	sum := mac.Sum(nil)
	if k.proto == PINProtocolOne {
		return sum[:16]
	}
	return sum
}

// pinHash is what an authenticator is given instead of the PIN: the first
// sixteen bytes of its SHA-256, encrypted.
//
// Sixteen and not thirty-two, which is one AES block. The other half of the
// hash is never sent and never needed.
func (k pinKeys) pinHash(pin string) ([]byte, error) {
	if pin == "" {
		return nil, fmt.Errorf("fido: an empty PIN is not a PIN")
	}
	sum := sha256.Sum256([]byte(pin))
	return k.encrypt(sum[:16])
}

// agree performs the ECDH exchange with the authenticator's public key and
// returns the platform's public key to send back, along with the derived keys.
//
// The shared secret is the x coordinate of the point, which is what
// crypto/ecdh returns -- so nothing here has to do curve arithmetic by hand.
func agree(proto PINProtocol, authenticator *ecdh.PublicKey) (own map[int64]any, keys pinKeys, err error) {
	priv, err := newECDHKey()
	if err != nil {
		return nil, pinKeys{}, fmt.Errorf("fido: cannot make a key to agree with: %w", err)
	}
	// Encoded BEFORE the exchange. Our own key not being what the wire format
	// expects is our fault and is worth finding out before the authenticator is
	// involved at all -- and it puts the check where a test can reach it.
	own, err = ecdhToCOSE(priv.PublicKey())
	if err != nil {
		return nil, pinKeys{}, err
	}
	secret, err := priv.ECDH(authenticator)
	if err != nil {
		return nil, pinKeys{}, fmt.Errorf("fido: the authenticator's key will not agree: %w", err)
	}
	keys, err = deriveKeys(proto, secret)
	if err != nil {
		return nil, pinKeys{}, err
	}
	return own, keys, nil
}
