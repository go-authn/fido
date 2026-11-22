// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
)

// recordingKey is a key over v that logs every CBOR request it is sent, in
// order, whole: command byte then parameters.
func recordingKey(t *testing.T, v *virtualAuthenticator) (*Key, *[]string) {
	t.Helper()
	var log []string
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		log = append(log, string(append([]byte{cmd}, params...)))
		return v.reply(cmd, params)
	})
	return k, &log
}

// deterministic fixes our half of every exchange (the ECDH key and the IVs), so
// that two runs of the same call put the same bytes on the wire.
func deterministic(t *testing.T) {
	t.Helper()
	oldKey, oldRand := newECDHKey, randRead
	t.Cleanup(func() { newECDHKey, randRead = oldKey, oldRand })
	newECDHKey = func() (*ecdh.PrivateKey, error) {
		return ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{0x11}, 32))
	}
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0xA5
		}
		return len(b), nil
	}
}

// wipes replaces wipe with a recorder: it keeps what each wiped slice held
// just before, then wipes it as the real one does.
func wipes(t *testing.T) *[][]byte {
	t.Helper()
	var seen [][]byte
	old := wipe
	t.Cleanup(func() { wipe = old })
	wipe = func(b []byte) {
		seen = append(seen, slices.Clone(b))
		clear(b)
	}
	return &seen
}

// holds counts the wiped slices equal to want.
func holds(seen [][]byte, want []byte) int {
	n := 0
	for _, s := range seen {
		if bytes.Equal(s, want) {
			n++
		}
	}
	return n
}

func TestTheBytesFormsPutTheBytesOfTheStringFormsOnTheWire(t *testing.T) {
	ctx := context.Background()
	type op struct {
		name  string
		start string // the PIN the authenticator holds before
		str   func(k *Key, p PINProtocol) error
		byts  func(k *Key, p PINProtocol) error
	}
	ops := []op{
		{"token with permissions", "1234",
			func(k *Key, p PINProtocol) error {
				_, err := k.PINToken(ctx, "1234", p, PermGetAssertion, "example.test")
				return err
			},
			func(k *Key, p PINProtocol) error {
				_, err := k.PINTokenBytes(ctx, []byte("1234"), p, PermGetAssertion, "example.test")
				return err
			}},
		{"token, the older way", "1234",
			func(k *Key, p PINProtocol) error { _, err := k.PINToken(ctx, "1234", p, 0, ""); return err },
			func(k *Key, p PINProtocol) error {
				_, err := k.PINTokenBytes(ctx, []byte("1234"), p, 0, "")
				return err
			}},
		{"set", "",
			func(k *Key, p PINProtocol) error { return k.SetPIN(ctx, p, "s3cret-pin", 0) },
			func(k *Key, p PINProtocol) error { return k.SetPINBytes(ctx, p, []byte("s3cret-pin"), 0) }},
		{"change", "1234",
			func(k *Key, p PINProtocol) error { return k.ChangePIN(ctx, p, "1234", "new-pin-9", 0) },
			func(k *Key, p PINProtocol) error {
				return k.ChangePINBytes(ctx, p, []byte("1234"), []byte("new-pin-9"), 0)
			}},
	}
	for _, o := range ops {
		for _, proto := range []PINProtocol{PINProtocolOne, PINProtocolTwo} {
			// One authenticator and one key, both forms in turn: the
			// authenticator's own key is the same, so the requests may be equal.
			v := newVirtualAuthenticator(t, o.start)
			deterministic(t)
			k, log := recordingKey(t, v)
			if err := o.str(k, proto); err != nil {
				t.Fatalf("%s, protocol %d, string: %v", o.name, proto, err)
			}
			fromString := slices.Clone(*log)
			v.pin = o.start
			*log = nil
			if err := o.byts(k, proto); err != nil {
				t.Fatalf("%s, protocol %d, bytes: %v", o.name, proto, err)
			}
			// Same requests, same number, same order: the key holds one token
			// at a time, so one more or one fewer is a different protocol.
			if len(fromString) == 0 || !slices.Equal(fromString, *log) {
				t.Errorf("%s, protocol %d: the bytes form sent %d requests that differ from the string form's %d",
					o.name, proto, len(*log), len(fromString))
			}
		}
	}
}

func TestEveryCopyOfAPINIsWiped(t *testing.T) {
	ctx := context.Background()
	digest := sha256.Sum256([]byte("1234"))
	padded := func(s string) []byte { return append([]byte(s), make([]byte, pinBlock-len(s))...) }

	t.Run("token, bytes form: the digest", func(t *testing.T) {
		seen := wipes(t)
		pin := []byte("1234")
		if _, err := virtualKey(t, newVirtualAuthenticator(t, "1234")).PINTokenBytes(ctx, pin, PINProtocolTwo, PermGetAssertion, ""); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 1 || holds(*seen, digest[:]) != 1 {
			t.Errorf("wiped %x, want the digest alone", *seen)
		}
		if string(pin) != "1234" {
			t.Errorf("the caller's slice was changed to %q: wiping it is the caller's", pin)
		}
	})
	t.Run("token, string form: the copy as well", func(t *testing.T) {
		seen := wipes(t)
		if _, err := virtualKey(t, newVirtualAuthenticator(t, "1234")).PINToken(ctx, "1234", PINProtocolTwo, PermGetAssertion, ""); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 2 || holds(*seen, digest[:]) != 1 || holds(*seen, []byte("1234")) != 1 {
			t.Errorf("wiped %q", *seen)
		}
	})
	t.Run("set, bytes form: the padded block", func(t *testing.T) {
		seen := wipes(t)
		pin := []byte("s3cret-pin")
		if err := virtualKey(t, newVirtualAuthenticator(t, "")).SetPINBytes(ctx, PINProtocolTwo, pin, 0); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 1 || holds(*seen, padded("s3cret-pin")) != 1 {
			t.Errorf("wiped %q", *seen)
		}
		if string(pin) != "s3cret-pin" {
			t.Errorf("the caller's slice was changed to %q", pin)
		}
	})
	t.Run("set, string form: the copy as well", func(t *testing.T) {
		seen := wipes(t)
		if err := virtualKey(t, newVirtualAuthenticator(t, "")).SetPIN(ctx, PINProtocolTwo, "s3cret-pin", 0); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 2 || holds(*seen, padded("s3cret-pin")) != 1 || holds(*seen, []byte("s3cret-pin")) != 1 {
			t.Errorf("wiped %q", *seen)
		}
	})
	t.Run("change, bytes form: the digest and the padded block", func(t *testing.T) {
		seen := wipes(t)
		cur, nw := []byte("1234"), []byte("new-pin-9")
		if err := virtualKey(t, newVirtualAuthenticator(t, "1234")).ChangePINBytes(ctx, PINProtocolTwo, cur, nw, 0); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 2 || holds(*seen, digest[:]) != 1 || holds(*seen, padded("new-pin-9")) != 1 {
			t.Errorf("wiped %q", *seen)
		}
		if string(cur) != "1234" || string(nw) != "new-pin-9" {
			t.Errorf("the caller's slices were changed to %q and %q", cur, nw)
		}
	})
	t.Run("change, string form: both copies as well", func(t *testing.T) {
		seen := wipes(t)
		if err := virtualKey(t, newVirtualAuthenticator(t, "1234")).ChangePIN(ctx, PINProtocolTwo, "1234", "new-pin-9", 0); err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 4 || holds(*seen, []byte("1234")) != 1 || holds(*seen, []byte("new-pin-9")) != 1 {
			t.Errorf("wiped %q", *seen)
		}
	})
}

func TestCheckNewPINBytesJudgesAsTheStringFormDoes(t *testing.T) {
	for name, c := range map[string]struct {
		pin string
		min uint
	}{
		"four characters":    {"1234", 0},
		"three characters":   {"123", 0},
		"below a stated min": {"12345", 6},
		"unicode":            {"éééé", 0},
		"63 bytes":           {strings.Repeat("a", 63), 0},
		"64 bytes":           {strings.Repeat("a", 64), 0},
		"multibyte too long": {strings.Repeat("é", 32), 0},
		"not UTF-8":          {"12\xff45", 0},
		"empty":              {"", 0},
	} {
		s, b := CheckNewPIN(c.pin, c.min), CheckNewPINBytes([]byte(c.pin), c.min)
		if (s == nil) != (b == nil) || s != nil && s.Error() != b.Error() {
			t.Errorf("%s: string says %v, bytes say %v", name, s, b)
		}
	}
	if got := paddedPIN([]byte("1234")); !bytes.Equal(got, paddedPIN("1234")) || len(got) != pinBlock {
		t.Errorf("padded slice %x", got)
	}
}
