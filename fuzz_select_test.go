// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import "testing"

// A key's getInfo reply decides how Select asks it and how Identity renders
// it, so what those read from a device the program does not control is fuzzed:
// no reply may panic them, and the identity line never comes out empty.
func FuzzIdentityFromInfo(f *testing.F) {
	f.Add(realGetInfoForFuzz(f))
	f.Add([]byte{0xa1, 0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '1'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := parseInfo(b)
		if err != nil {
			return
		}
		id := identityOf("K", info)
		if id.String() == "" {
			t.Fatal("an empty identity line")
		}
		if id.PINSet && !id.PINCapable {
			t.Fatalf("a PIN set on a key that cannot have one: %+v", id)
		}
		if id.FingerprintsEnrolled && !id.FingerprintCapable {
			t.Fatalf("fingerprints enrolled on a key with no sensor: %+v", id)
		}
	})
}

func realGetInfoForFuzz(f *testing.F) []byte {
	f.Helper()
	b, err := ctap2.Marshal(map[uint64]any{
		infoVersions: []string{"FIDO_2_1"},
		infoOptions:  map[string]bool{"clientPin": true, "bioEnroll": false},
	})
	if err != nil {
		f.Fatal(err)
	}
	return b
}
