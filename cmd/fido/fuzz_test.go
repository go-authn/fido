package main

import (
	"os"
	"path/filepath"
	"testing"

	authn "github.com/go-authn/fido"
)

// The alias table is a file a person (or another program) can edit: whatever
// it holds, loading it never panics and yields only usable names under
// non-empty keys.
func FuzzAliasTable(f *testing.F) {
	for _, s := range []string{"", "k\tdesk\n", "garbage", "\t\n\n", "k\ta\x1bb\n", "a\tb\na\tc\n", "k\t" + string(make([]byte, 100)) + "\n"} {
		f.Add([]byte(s))
	}
	dir := f.TempDir()
	old := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	f.Cleanup(func() { userConfigDir = old })
	path := filepath.Join(dir, "fido", "names")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := loadAliases()
		if err != nil {
			return
		}
		for k, name := range m {
			if k == "" || authn.CheckName(name) != nil {
				t.Fatalf("loaded %q => %q", k, name)
			}
		}
	})
}

// An envelope is a file from anywhere: decoding it and deriving the verifier's
// inputs never panics, and whatever decodes re-encodes to something that decodes
// to the same envelope.
func FuzzEnvelope(f *testing.F) {
	good, _ := encodeEnvelope(envelope{RPID: attestRPID, ClientDataJSON: []byte(`{"challenge":"AAAA"}`), ClientDataHash: make([]byte, 32), AttestationObject: []byte{0xa0}})
	for _, s := range [][]byte{nil, good, good[:len(good)/2], append(append([]byte(nil), good...), 0), {0xa0}, {0xbf, 0xff}, []byte("garbage")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := decodeEnvelope(b)
		if err != nil {
			return
		}
		e.verifyInputs() //nolint:errcheck // must not panic
		again, err := encodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		e2, err := decodeEnvelope(again)
		if err != nil || e2.RPID != e.RPID || string(e2.ClientDataJSON) != string(e.ClientDataJSON) ||
			string(e2.ClientDataHash) != string(e.ClientDataHash) || string(e2.AttestationObject) != string(e.AttestationObject) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
