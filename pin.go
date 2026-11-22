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
	if minLen == 0 {
		minLen = DefaultMinPINLength
	}
	if !utf8.ValidString(pin) {
		return fmt.Errorf("fido: the PIN is not valid UTF-8")
	}
	// The key supplies minLen. Compared as unsigned: int(minLen) of a value
	// above MaxInt is negative and the check would pass everything.
	if n := utf8.RuneCountInString(pin); uint64(n) < uint64(minLen) {
		return fmt.Errorf("fido: the PIN has %d characters; this authenticator wants at least %d", n, minLen)
	}
	if len(pin) > MaxPINBytes {
		return fmt.Errorf("fido: the PIN is %d bytes in UTF-8; the most CTAP allows is %d", len(pin), MaxPINBytes)
	}
	return nil
}

// paddedPIN is the PIN right-padded with zero bytes to 64 (CTAP 2.1 6.5.5.5).
// The caller wipes it.
func paddedPIN(pin string) []byte {
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
func (k *Key) SetPIN(ctx context.Context, proto PINProtocol, newPIN string, minLen uint) error {
	if err := k.ctap2Ready(); err != nil {
		return err
	}
	if err := CheckNewPIN(newPIN, minLen); err != nil {
		return err
	}
	keys, ownCOSE, err := k.agreeWith(ctx, proto)
	if err != nil {
		return err
	}
	padded := paddedPIN(newPIN)
	defer clear(padded)
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
func (k *Key) ChangePIN(ctx context.Context, proto PINProtocol, curPIN, newPIN string, minLen uint) error {
	if err := k.ctap2Ready(); err != nil {
		return err
	}
	if curPIN == "" {
		return fmt.Errorf("fido: an empty PIN is not a PIN")
	}
	if err := CheckNewPIN(newPIN, minLen); err != nil {
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
	defer clear(padded)
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
