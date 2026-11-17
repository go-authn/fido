// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"crypto/ecdh"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestCheckNewPIN(t *testing.T) {
	for name, c := range map[string]struct {
		pin  string
		min  uint
		want string // substring of the error; empty means accepted
	}{
		"four characters":      {"1234", 0, ""},
		"three characters":     {"123", 0, "at least 4"},
		"below a stated min":   {"12345", 6, "at least 6"},
		"unicode counts runes": {"éééé", 0, ""},
		"63 bytes":             {strings.Repeat("a", 63), 0, ""},
		"64 bytes":             {strings.Repeat("a", 64), 0, "most CTAP allows is 63"},
		"multibyte too long":   {strings.Repeat("é", 32), 0, "most CTAP allows is 63"},
		"not UTF-8":            {"12\xff45", 0, "not valid UTF-8"},
	} {
		err := CheckNewPIN(c.pin, c.min)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestPaddedPINIs64Bytes(t *testing.T) {
	b := paddedPIN("1234")
	if len(b) != 64 || string(b[:4]) != "1234" || b[4] != 0 || b[63] != 0 {
		t.Fatalf("%x", b)
	}
}

func TestSetPINOnAFreshKey(t *testing.T) {
	for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
		v := newVirtualAuthenticator(t, "")
		k := virtualKey(t, v)
		if err := k.SetPIN(context.Background(), proto, "s3cret-pin", 0); err != nil {
			t.Fatalf("proto %d: %v", proto, err)
		}
		if v.pin != "s3cret-pin" {
			t.Fatalf("the authenticator holds %q", v.pin)
		}
		// Byte level (6.5.5.5): the request has protocol, subCommand 3, key
		// agreement, newPinEnc and pinUvAuthParam, and NO pinHashEnc.
		var keys []uint64
		for key := range v.lastPINReq {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []uint64{cpProtocol, cpSubCommand, cpKeyAgreement, cpPinUvAuthParam, cpNewPinEnc}) {
			t.Errorf("request keys %v", keys)
		}
		var enc []byte
		_ = cbor.Unmarshal(v.lastPINReq[cpNewPinEnc], &enc)
		want := 64
		if proto == PINProtocolTwo {
			want = 64 + 16 // the IV is prepended
		}
		if len(enc) != want {
			t.Errorf("proto %d: newPinEnc is %d bytes, want %d", proto, len(enc), want)
		}
		// The key now has a PIN and hands out a token for it.
		if _, err := k.PINToken(context.Background(), "s3cret-pin", proto, PermGetAssertion, ""); err != nil {
			t.Errorf("the new PIN does not open a token: %v", err)
		}
	}
}

func TestSetPINRefusals(t *testing.T) {
	ctx := context.Background()
	// A key that has a PIN says CTAP2_ERR_PIN_AUTH_INVALID.
	v := newVirtualAuthenticator(t, "1234")
	err := virtualKey(t, v).SetPIN(ctx, PINProtocolTwo, "abcdef", 0)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 0x33 {
		t.Errorf("PIN already set: %v", err)
	}
	// A PIN the platform can see is too short costs no exchange.
	v = newVirtualAuthenticator(t, "")
	k := virtualKey(t, v)
	if err := k.SetPIN(ctx, PINProtocolTwo, "123", 0); err == nil || len(v.asked) != 0 {
		t.Errorf("short PIN: %v asked %v", err, v.asked)
	}
	// The authenticator's own policy (minPINLength) is enforced even when the
	// platform believes the default.
	v.minPIN = 8
	if err := k.SetPIN(ctx, PINProtocolTwo, "123456", 0); !errors.As(err, &se) || se.Status != 0x37 {
		t.Errorf("policy violation: %v", err)
	}
	if v.pin != "" {
		t.Error("a PIN below the policy was stored")
	}
	// An unsupported protocol fails at the key agreement.
	v1 := newVirtualAuthenticator(t, "", 1)
	if err := virtualKey(t, v1).SetPIN(ctx, PINProtocolTwo, "abcdef", 0); err == nil {
		t.Error("protocol 2 accepted by a protocol-1 key")
	}
	// Randomness failing (protocol 2 needs an IV).
	old := randRead
	t.Cleanup(func() { randRead = old })
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if err := virtualKey(t, newVirtualAuthenticator(t, "")).SetPIN(ctx, PINProtocolTwo, "abcdef", 0); err == nil {
		t.Error("an IV-less request was sent")
	}
}

func TestPINCommandsStopWhenTheKeyAgreementCannotBeMade(t *testing.T) {
	old := newECDHKey
	t.Cleanup(func() { newECDHKey = old })
	newECDHKey = func() (*ecdh.PrivateKey, error) { return nil, errors.New("no key") }
	k := virtualKey(t, newVirtualAuthenticator(t, ""))
	if err := k.SetPIN(context.Background(), PINProtocolTwo, "abcdef", 0); err == nil {
		t.Error("SetPIN went on without a shared secret")
	}
}

func TestChangePIN(t *testing.T) {
	ctx := context.Background()
	for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
		v := newVirtualAuthenticator(t, "1234")
		k := virtualKey(t, v)
		if err := k.ChangePIN(ctx, proto, "1234", "new-pin-9", 0); err != nil {
			t.Fatalf("proto %d: %v", proto, err)
		}
		if v.pin != "new-pin-9" {
			t.Fatalf("the authenticator holds %q", v.pin)
		}
		// 6.5.5.6: pinHashEnc is present and the MAC covers newPinEnc || pinHashEnc
		// (the virtual authenticator verified exactly that).
		if _, has := v.lastPINReq[cpPinHashEnc]; !has {
			t.Error("no pinHashEnc")
		}
	}
}

func TestChangePINRefusals(t *testing.T) {
	ctx := context.Background()
	var se *StatusError
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	// A wrong current PIN costs a retry.
	if err := k.ChangePIN(ctx, PINProtocolTwo, "9999", "abcdef", 0); !errors.As(err, &se) || se.Status != StatusPINInvalid {
		t.Errorf("wrong current PIN: %v", err)
	}
	if v.pinTries != 7 || v.pin != "1234" {
		t.Errorf("tries %d pin %q", v.pinTries, v.pin)
	}
	// No retries left.
	v.pinTries = 0
	if err := k.ChangePIN(ctx, PINProtocolTwo, "1234", "abcdef", 0); !errors.As(err, &se) || se.Status != StatusPINBlocked {
		t.Errorf("blocked: %v", err)
	}
	v.pinTries = 8
	// forcePINChange: the new PIN must differ from the current one.
	v.forceChange = true
	if err := k.ChangePIN(ctx, PINProtocolTwo, "1234", "1234", 0); !errors.As(err, &se) || se.Status != 0x37 {
		t.Errorf("same PIN while a change is forced: %v", err)
	}
	if err := k.ChangePIN(ctx, PINProtocolTwo, "1234", "abcdef", 0); err != nil || v.forceChange {
		t.Errorf("forced change: %v force=%v", err, v.forceChange)
	}
	// Nothing set.
	if err := virtualKey(t, newVirtualAuthenticator(t, "")).ChangePIN(ctx, PINProtocolTwo, "1234", "abcdef", 0); !errors.As(err, &se) || se.Status != 0x35 {
		t.Errorf("no PIN set: %v", err)
	}
	// Local checks send nothing.
	v = newVirtualAuthenticator(t, "1234")
	k = virtualKey(t, v)
	if err := k.ChangePIN(ctx, PINProtocolTwo, "", "abcdef", 0); err == nil || !strings.Contains(err.Error(), "empty PIN") {
		t.Errorf("empty current: %v", err)
	}
	if err := k.ChangePIN(ctx, PINProtocolTwo, "1234", "ab", 0); err == nil {
		t.Error("short new PIN accepted")
	}
	if len(v.asked) != 0 {
		t.Errorf("asked %v", v.asked)
	}
	// Unsupported protocol.
	if err := virtualKey(t, newVirtualAuthenticator(t, "1234", 1)).ChangePIN(ctx, PINProtocolTwo, "1234", "abcdef", 0); err == nil {
		t.Error("protocol 2 accepted by a protocol-1 key")
	}
	// Randomness failing: first at pinHashEnc, then at newPinEnc.
	old := randRead
	t.Cleanup(func() { randRead = old })
	for failAt := 1; failAt <= 2; failAt++ {
		calls := 0
		randRead = func(b []byte) (int, error) {
			calls++
			if calls == failAt {
				return 0, errors.New("no entropy")
			}
			return old(b)
		}
		if err := virtualKey(t, newVirtualAuthenticator(t, "1234")).ChangePIN(ctx, PINProtocolTwo, "1234", "abcdef", 0); err == nil {
			t.Errorf("failure %d ignored", failAt)
		}
	}
}

func TestPINCommandsNeedACTAP2Key(t *testing.T) {
	k := ctap2Key(t, CapWink, func(byte, []byte) []byte { t.Error("asked"); return []byte{0} })
	ctx := context.Background()
	if err := k.SetPIN(ctx, PINProtocolTwo, "abcdef", 0); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("SetPIN %v", err)
	}
	if err := k.ChangePIN(ctx, PINProtocolTwo, "1234", "abcdef", 0); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("ChangePIN %v", err)
	}
}

func TestInfoCarriesTheMinimumAndTheForcedChange(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	v.minPIN, v.forceChange = 6, true
	info, err := virtualKey(t, v).GetInfo(context.Background())
	if err != nil || info.MinPINLength != 6 || !info.ForcePINChange {
		t.Fatalf("%+v %v", info, err)
	}
	info, _ = virtualKey(t, newVirtualAuthenticator(t, "1234")).GetInfo(context.Background())
	if info.MinPINLength != 0 || info.ForcePINChange {
		t.Errorf("fields appeared from nowhere: %+v", info)
	}
	// The statuses added for these commands have names.
	for _, s := range []Status{0x03, 0x17, StatusInvalidOption, 0x30, 0x40} {
		if strings.HasPrefix(s.String(), "CTAP2 status") {
			t.Errorf("%#02x has no name", byte(s))
		}
	}
}
