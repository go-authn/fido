// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"fmt"
	"unicode/utf8"
)

// The PIN limits of CTAP 2.1 6.5.5.5: a PIN is at least minPINLength code
// points (4 when the authenticator does not say) and its UTF-8 form at most 63
// bytes, so that the 64-byte block it is padded into always keeps one zero byte.
const (
	// DefaultMinPINLength is the minimum when getInfo has no minPINLength.
	DefaultMinPINLength = 4
	// MaxPINBytes is the longest PIN, in UTF-8 bytes.
	MaxPINBytes = 63
	pinBlock    = 64
)

// CheckNewPIN applies the platform's half of the PIN policy before the
// authenticator is asked, so a PIN that cannot be accepted costs no exchange
// and no retry. minLen is [Info.MinPINLength]; zero means [DefaultMinPINLength].
// The authenticator may still refuse a PIN on a policy of its own
// (CTAP2_ERR_PIN_POLICY_VIOLATION).
//
// CTAP 2.1 asks for the PIN in Unicode Normalization Form C. This package does
// not normalise (the standard library has no NFC): a PIN with composed and
// decomposed spellings must be given in NFC by the caller.
func CheckNewPIN(pin string, minLen uint) error {
	return checkNewPIN(utf8.ValidString(pin), utf8.RuneCountInString(pin), len(pin), minLen)
}

// CheckNewPINBytes is [CheckNewPIN] for a PIN held as a slice. It only reads
// pin and keeps nothing of it.
func CheckNewPINBytes(pin []byte, minLen uint) error {
	return checkNewPIN(utf8.Valid(pin), utf8.RuneCount(pin), len(pin), minLen)
}

// checkNewPIN is the policy over what was measured of the PIN, so that the
// string and slice forms cannot drift apart and neither converts to the other.
func checkNewPIN(valid bool, runes, size int, minLen uint) error {
	if minLen == 0 {
		minLen = DefaultMinPINLength
	}
	if !valid {
		return fmt.Errorf("fido: the PIN is not valid UTF-8")
	}
	// The key supplies minLen. Compared as unsigned: int(minLen) of a value
	// above MaxInt is negative and the check would pass everything.
	if uint64(runes) < uint64(minLen) {
		return fmt.Errorf("fido: the PIN has %d characters; this authenticator wants at least %d", runes, minLen)
	}
	if size > MaxPINBytes {
		return fmt.Errorf("fido: the PIN is %d bytes in UTF-8; the most CTAP allows is %d", size, MaxPINBytes)
	}
	return nil
}

// paddedPIN is the PIN right-padded with zero bytes to 64 (CTAP 2.1 6.5.5.5).
// The caller wipes it.
func paddedPIN[T string | []byte](pin T) []byte {
	b := make([]byte, pinBlock)
	copy(b, pin)
	return b
}

// SetPIN sets the first PIN of an authenticator that has none: setPIN
// (clientPIN subcommand 0x03, CTAP 2.1 6.5.5.5). newPinEnc is the PIN padded to
// 64 bytes and encrypted under the agreed secret, and pinUvAuthParam is the MAC
// of newPinEnc; there is no pinHashEnc.
//
// minLen is the authenticator's [Info.MinPINLength]. An authenticator that
// already has a PIN answers CTAP2_ERR_PIN_AUTH_INVALID: use [Key.ChangePIN].
//
// Deprecated: a string cannot be wiped; use [Key.SetPINBytes]. This form
// copies newPIN into a slice, calls that one and wipes the copy.
func (k *Key) SetPIN(ctx context.Context, proto PINProtocol, newPIN string, minLen uint) error {
	b := []byte(newPIN)
	defer wipe(b)
	return k.SetPINBytes(ctx, proto, b, minLen)
}

// SetPINBytes is [Key.SetPIN] for a PIN held as a slice, so that the caller
// can wipe it. The requests are the same. newPIN is only read: the one copy
// made (the 64-byte block that is encrypted) is wiped before the call
// returns, and wiping newPIN itself is the caller's.
func (k *Key) SetPINBytes(ctx context.Context, proto PINProtocol, newPIN []byte, minLen uint) error {
	if err := k.ctap2Ready(); err != nil {
		return err
	}
	if err := CheckNewPINBytes(newPIN, minLen); err != nil {
		return err
	}
	keys, ownCOSE, err := k.agreeWith(ctx, proto)
	if err != nil {
		return err
	}
	padded := paddedPIN(newPIN)
	defer wipe(padded)
	newPinEnc, err := keys.encrypt(padded)
	if err != nil {
		return err
	}
	_, err = k.cborCall(ctx, CmdClientPIN, map[int]any{
		cpProtocol:       int(proto),
		cpSubCommand:     subSetPIN,
		cpKeyAgreement:   ownCOSE,
		cpNewPinEnc:      newPinEnc,
		cpPinUvAuthParam: keys.authenticate(newPinEnc),
	})
	return err
}

// ChangePIN replaces the PIN: changePIN (clientPIN subcommand 0x04, CTAP 2.1
// 6.5.5.6). pinHashEnc proves the current PIN and newPinEnc carries the new
// one; pinUvAuthParam is the MAC of newPinEnc followed by pinHashEnc.
//
// A wrong current PIN costs a retry, as in [Key.PINToken]: read
// [Key.PINRetries] first. When [Info.ForcePINChange] is set the authenticator
// refuses a new PIN equal to the current one.
//
// Deprecated: a string cannot be wiped; use [Key.ChangePINBytes]. This form
// copies both PINs into slices, calls that one and wipes the copies.
func (k *Key) ChangePIN(ctx context.Context, proto PINProtocol, curPIN, newPIN string, minLen uint) error {
	cur, nw := []byte(curPIN), []byte(newPIN)
	defer wipe(cur)
	defer wipe(nw)
	return k.ChangePINBytes(ctx, proto, cur, nw, minLen)
}

// ChangePINBytes is [Key.ChangePIN] for PINs held as slices, so that the
// caller can wipe them. The requests are the same. Both are only read, and
// the copies made (the digest of curPIN, the padded block of newPIN) are wiped
// before the call returns; wiping curPIN and newPIN is the caller's.
func (k *Key) ChangePINBytes(ctx context.Context, proto PINProtocol, curPIN, newPIN []byte, minLen uint) error {
	if err := k.ctap2Ready(); err != nil {
		return err
	}
	if len(curPIN) == 0 {
		return fmt.Errorf("fido: an empty PIN is not a PIN")
	}
	if err := CheckNewPINBytes(newPIN, minLen); err != nil {
		return err
	}
	keys, ownCOSE, err := k.agreeWith(ctx, proto)
	if err != nil {
		return err
	}
	hashEnc, err := keys.pinHash(curPIN)
	if err != nil {
		return err
	}
	padded := paddedPIN(newPIN)
	defer wipe(padded)
	newPinEnc, err := keys.encrypt(padded)
	if err != nil {
		return err
	}
	_, err = k.cborCall(ctx, CmdClientPIN, map[int]any{
		cpProtocol:       int(proto),
		cpSubCommand:     subChangePIN,
		cpKeyAgreement:   ownCOSE,
		cpPinHashEnc:     hashEnc,
		cpNewPinEnc:      newPinEnc,
		cpPinUvAuthParam: keys.authenticate(append(append([]byte(nil), newPinEnc...), hashEnc...)),
	})
	return err
}

// agreeWith performs getKeyAgreement and the ECDH, returning the derived keys
// and the platform key to send back.
func (k *Key) agreeWith(ctx context.Context, proto PINProtocol) (pinKeys, map[int64]any, error) {
	pub, err := k.KeyAgreement(ctx, proto)
	if err != nil {
		return pinKeys{}, nil, err
	}
	ownCOSE, keys, err := agree(proto, pub)
	if err != nil {
		return pinKeys{}, nil, err
	}
	return keys, ownCOSE, nil
}
