// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mds

import (
	"errors"
	"testing"
)

// FuzzParse: whatever the bytes, parsing neither panics nor returns an error
// that is not one of the package's, and what parses has the shape promised.
// The seeds are in testdata/fuzz/FuzzParse.
func FuzzParse(f *testing.F) {
	f.Add([]byte("e30.e30.e30"))
	f.Add([]byte("eyJhbGciOiJFUzI1NiJ9.eyJubyI6MSwibmV4dFVwZGF0ZSI6IjIwMjYtMTItMDEiLCJlbnRyaWVzIjpbe31dfQ.AA"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, blob []byte) {
		b, err := parseUnverified(blob)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("foreign error: %v", err)
			}
			return
		}
		if b.No < 0 || len(b.Entries) > MaxEntries || b.NextUpdate().IsZero() {
			t.Fatalf("%+v", b)
		}
		for i := range b.Entries {
			e := &b.Entries[i]
			_ = e.Description()
			_, _ = e.RootCertificates()
			if e.AAGUID != "" {
				if got, ok := NormalizeAAGUID(e.AAGUID); ok && b.Lookup(got) == nil {
					t.Fatalf("an entry the lookup cannot find: %q", e.AAGUID)
				}
			}
		}
		_ = b.Search("yubikey")
	})
}

// FuzzVerify: nobody holds the key of the pinned root's chain, so NO input
// may verify against it. A nil error here is a forgery.
func FuzzVerify(f *testing.F) {
	f.Add([]byte("e30.e30.e30"))
	f.Add([]byte("eyJhbGciOiJSUzI1NiIsIng1YyI6WyJBQUFBIl19.e30.AA"))
	f.Fuzz(func(t *testing.T, blob []byte) {
		if _, err := Verify(blob, Options{CRL: func(string) ([]byte, error) { return nil, errors.New("offline") }}); err == nil {
			t.Fatalf("a blob verified against the pinned root: %q", blob)
		}
	})
}
