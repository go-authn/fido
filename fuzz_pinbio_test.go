// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"testing"
	"unicode/utf8"
)

// The bio enrollment replies are read from a device the program does not
// control, like every other reply: no input may panic, and what is accepted
// must hold what the parsers promise.
func FuzzBioReplies(f *testing.F) {
	t := &testing.T{}
	f.Add(cborOf(t, map[uint64]any{brKind: 1, brMaxSamples: 4, brMaxName: 16}))
	f.Add(cborOf(t, map[uint64]any{brTemplateID: []byte{1, 2}, brLastStatus: 0, brRemaining: 3}))
	f.Add(cborOf(t, map[uint64]any{brTemplateInfos: []map[uint64]any{{bpTemplateID: []byte{1}, bpName: "left"}, {bpTemplateID: []byte{2}}}}))
	f.Add([]byte{})
	f.Add([]byte{0xa1, 0x07, 0x9f, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := parseSensorInfo(b); err == nil && (s.MaxSamples < 0 || s.MaxNameLength < 0) {
			t.Fatalf("negative counts accepted: %+v", s)
		}
		if s, err := parseEnrollStep(b, true); err == nil && (s.Remaining < 0 || len(s.TemplateID) == 0) {
			t.Fatalf("an enrollment step that cannot be used: %+v", s)
		}
		if s, err := parseEnrollStep(b, false); err == nil && s.Remaining < 0 {
			t.Fatalf("negative samples remaining: %+v", s)
		}
		if es, err := parseEnrollments(b); err == nil {
			for _, e := range es {
				_ = e.Name
			}
		}
		_ = SampleStatus(len(b)).String()
	})
}

func FuzzCheckNewPIN(f *testing.F) {
	for _, s := range []string{"", "1234", "é", "\xff", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		f.Add(s, uint(0))
	}
	f.Fuzz(func(t *testing.T, pin string, min uint) {
		if CheckNewPIN(pin, min) != nil {
			return
		}
		// An accepted PIN always fits the 64-byte block with a byte to spare,
		// and the block holds it intact.
		if len(pin) > MaxPINBytes || !utf8.ValidString(pin) {
			t.Fatalf("accepted %q", pin)
		}
		b := paddedPIN(pin)
		if len(b) != 64 || string(b[:len(pin)]) != pin || b[63] != 0 {
			t.Fatalf("padding %x", b)
		}
	})
}
