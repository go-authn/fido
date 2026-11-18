package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRefs replaces the secret manager: ref -> PIN, anything else is missing.
func fakeRefs(t *testing.T, refs map[string]string) *[]string {
	t.Helper()
	var asked []string
	old := readRef
	readRef = func(_ context.Context, ref string) ([]byte, error) {
		asked = append(asked, ref)
		if v, ok := refs[ref]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("secretsource: no such entry: " + ref)
	}
	t.Cleanup(func() { readRef = old })
	return &asked
}

func TestPinFromEveryCommand(t *testing.T) {
	asked := fakeRefs(t, map[string]string{"keychain:fido/key": "1234", "keychain:fido/new": "5678"})

	f := newFake()
	delete(f.info.Options, "clientPin")
	use(t, f, nil)
	if _, _, err := run("pin", "set", "--pin-from", "keychain:fido/key"); err != nil || f.setPIN != "1234" {
		t.Fatalf("pin set: %v %q", err, f.setPIN)
	}

	f = newFake()
	use(t, f, nil)
	if _, _, err := run("pin", "change", "--pin-from", "keychain:fido/key", "--new-pin-from", "keychain:fido/new"); err != nil || f.curPIN != "1234" || f.newPIN != "5678" {
		t.Fatalf("pin change: %v %q %q", err, f.curPIN, f.newPIN)
	}
	// A file for one secret and a manager for the other.
	if _, _, err := run("pin", "change", "--pin-file", secretFile(t, "viafile", 0o600), "--new-pin-from", "keychain:fido/new"); err != nil || f.curPIN != "viafile" || f.newPIN != "5678" {
		t.Fatalf("mixed: %v %q %q", err, f.curPIN, f.newPIN)
	}

	for _, args := range [][]string{{"add"}, {"list"}, {"rename", "01", "x"}, {"remove", "01"}} {
		f = newFake()
		use(t, f, nil)
		if _, _, err := run(append([]string{"fingerprint"}, append(args, "--pin-from", "keychain:fido/key")...)...); err != nil || f.tokenPIN != "1234" {
			t.Errorf("fingerprint %v: %v %q", args, err, f.tokenPIN)
		}
	}
	if len(*asked) == 0 {
		t.Fatal("the manager was never asked")
	}
}

func TestPinFromRefusals(t *testing.T) {
	fakeRefs(t, nil)
	f := newFake()
	use(t, f, nil)
	pf := secretFile(t, "1234", 0o600)
	for _, args := range [][]string{
		{"pin", "change", "--pin-file", pf, "--pin-from", "keychain:a/b"},
		{"pin", "change", "--new-pin-file", pf, "--new-pin-from", "keychain:a/b"},
		{"pin", "set", "--pin-file", pf, "--pin-from", "keychain:a/b"},
		{"fingerprint", "list", "--pin-file", pf, "--pin-from", "keychain:a/b"},
	} {
		if _, _, err := run(args...); err == nil || !strings.Contains(err.Error(), "none of the others can be") {
			t.Errorf("%v: both flags must be refused: %v", args, err)
		}
	}
	// A missing entry stops before the key is touched with a PIN.
	if _, _, err := run("fingerprint", "list", "--pin-from", "keychain:a/b"); err == nil || !strings.Contains(err.Error(), "no such entry") || f.tokenPIN != "" {
		t.Errorf("missing entry: %v %q", err, f.tokenPIN)
	}
}

func TestReadRefDefault(t *testing.T) {
	// The real resolver: a bad reference is refused, a file reference works.
	if _, err := readRef(context.Background(), "no-scheme"); err == nil {
		t.Error("a scheme-less reference must be refused")
	}
	if b, err := readRef(context.Background(), "file:"+secretFile(t, "abc\n", 0o600)); err != nil || string(b) != "abc" {
		t.Errorf("%q %v", b, err)
	}
}
