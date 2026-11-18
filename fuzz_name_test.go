// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"testing"
	"unicode/utf8"
)

// What a key holds as its name is read from a device the program does not
// control, and printed on a terminal: a name that decodes is always valid
// UTF-8 within the cap with no control or invisible character, and decoding
// agrees with the check a name passes on the way in.
func FuzzDecodeName(f *testing.F) {
	for _, s := range []string{"desk key", "clé ✓", "", "a\x00b", "a\x1b[31mred", "\xff\xfe", "a‮b", string(make([]byte, 65))} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, id []byte) {
		name, err := DecodeName(id)
		if (CheckName(string(id)) == nil) != (err == nil) {
			t.Fatalf("DecodeName and CheckName disagree on %q", id)
		}
		if err != nil {
			return
		}
		if name != string(id) || !utf8.ValidString(name) || len(name) == 0 || len(name) > MaxNameBytes {
			t.Fatalf("accepted %q", name)
		}
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("a control character in %q", name)
			}
		}
	})
}

// The credential management replies are read the same way.
func FuzzManagedCredential(f *testing.F) {
	t := &testing.T{}
	f.Add(cborOf(t, map[uint64]any{
		cmrUser:         map[string]any{"id": []byte("u"), "name": "n"},
		cmrCredentialID: map[string]any{"id": []byte{1}, "type": "public-key"},
		cmrTotalCreds:   2,
	}), true)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, b []byte, begin bool) {
		m, total, err := parseManaged(b, begin)
		if err != nil {
			return
		}
		if len(m.ID) == 0 || len(m.User.ID) > managedUserIDMax || (begin && total < 1) || (!begin && total != 0) {
			t.Fatalf("accepted %+v total %d", m, total)
		}
	})
}
