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
