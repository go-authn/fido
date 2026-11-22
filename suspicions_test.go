// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"strings"
	"testing"
)

// Suspicion 9, the retry counts: CTAP 2.1 6.5.5.2 and 6.5.5.3 define them as
// unsigned. A key that answers a negative number is lying, and every caller
// that compares with 0 would read it as "not blocked".
func TestANegativeRetryCountIsRefused(t *testing.T) {
	for _, n := range []int{-1, -8, -1 << 31} {
		pin := mustCBOR(t, map[uint64]any{cpRespPINRetries: n})
		k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return append([]byte{byte(StatusOK)}, pin...) })
		if r, err := k.PINRetries(context.Background()); err == nil {
			t.Errorf("PINRetries accepted %d (%+v)", n, r)
		}
		uv := mustCBOR(t, map[uint64]any{cpRespUVRetries: n})
		k = ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return append([]byte{byte(StatusOK)}, uv...) })
		if got, err := k.UVRetries(context.Background()); err == nil {
			t.Errorf("UVRetries accepted %d (%d)", n, got)
		}
	}
	// Control: the honest edge.
	ok := mustCBOR(t, map[uint64]any{cpRespPINRetries: 0})
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return append([]byte{byte(StatusOK)}, ok...) })
	if r, err := k.PINRetries(context.Background()); err != nil || r.PIN != 0 {
		t.Errorf("zero retries: %+v %v", r, err)
	}
}

// Suspicion 9, MinPINLength: the key supplies it. int(minLen) turned a value
// above MaxInt into a negative bound, so "at least minLen characters" became
// "at least nothing". A bound no PIN can meet (over 63 bytes) is refused by
// name instead.
func TestAMinPINLengthNoPINCanMeet(t *testing.T) {
	for _, min := range []uint{MaxPINBytes + 1, 1 << 31, 1 << 32, 1 << 63, ^uint(0)} {
		err := CheckNewPIN("1", min)
		if err == nil {
			t.Errorf("min %d: a one-character PIN was accepted", min)
			continue
		}
		if !strings.Contains(err.Error(), "at least") {
			t.Errorf("min %d: %v", min, err)
		}
	}
	if err := CheckNewPIN(strings.Repeat("a", 63), MaxPINBytes); err != nil {
		t.Errorf("the largest honest minimum: %v", err)
	}
}
