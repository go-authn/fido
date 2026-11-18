package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

type storeCall struct {
	ref, pin string
	o        secretsource.StoreOptions
}

// manager fakes the write side; failOn makes the n-th store (1-based) fail.
// log is shared with the fake key so the ORDER of store and key calls shows.
func manager(t *testing.T, failOn ...int) *[]storeCall {
	t.Helper()
	var calls []storeCall
	oldS, oldG := storePIN, generatePIN
	t.Cleanup(func() { storePIN, generatePIN = oldS, oldG })
	storePIN = func(_ context.Context, ref string, p []byte, o secretsource.StoreOptions) error {
		calls = append(calls, storeCall{ref, string(p), o})
		for _, n := range failOn {
			if n == len(calls) {
				return errors.New("manager locked")
			}
		}
		return nil
	}
	return &calls
}

func TestPinSetSaveToGenerated(t *testing.T) {
	calls := manager(t)
	f := newFake()
	delete(f.info.Options, "clientPin")
	use(t, f, nil)
	out, e, err := run("pin", "set", "--save-to", "keychain:fido/key", "--generate", "12")
	if err != nil || len(*calls) != 1 || len((*calls)[0].pin) != 12 || f.setPIN != (*calls)[0].pin {
		t.Fatalf("%v %+v set=%q", err, *calls, f.setPIN)
	}
	if strings.Contains(out, f.setPIN) || strings.Contains(e, f.setPIN) || !strings.Contains(e, "stored in keychain:fido/key") {
		t.Errorf("nothing secret is printed: %q %q", out, e)
	}
	// Typed twice, saved, with --replace.
	f = newFake()
	delete(f.info.Options, "clientPin")
	use(t, f, nil)
	tm := &term{answers: []string{"s3cret", "s3cret"}}
	tm.install(t)
	*calls = nil
	if _, _, err := run("pin", "set", "--save-to", "secretservice:fido/key", "--replace"); err != nil || (*calls)[0].pin != "s3cret" || !(*calls)[0].o.Replace || f.setPIN != "s3cret" {
		t.Fatalf("%v %+v", err, *calls)
	}
}

// The store comes first: a failed store leaves the key untouched.
func TestPinSetStoreFailureLeavesTheKeyAlone(t *testing.T) {
	manager(t, 1)
	f := newFake()
	delete(f.info.Options, "clientPin")
	use(t, f, nil)
	_, _, err := run("pin", "set", "--save-to", "keychain:fido/key", "--generate", "12")
	if err == nil || !strings.Contains(err.Error(), "the key was not touched") || !strings.Contains(err.Error(), "manager locked") || f.setPIN != "" {
		t.Fatalf("%v set=%q", err, f.setPIN)
	}
}

func TestPinSetKeyFailureAfterStore(t *testing.T) {
	manager(t)
	f := newFake()
	delete(f.info.Options, "clientPin")
	f.setErr = errors.New("key said no")
	use(t, f, nil)
	_, _, err := run("pin", "set", "--save-to", "keychain:fido/key", "--generate", "12")
	if err == nil || !strings.Contains(err.Error(), "key said no") || !strings.Contains(err.Error(), "stays stored") {
		t.Fatalf("%v", err)
	}
	// Without --save-to the error is the key's alone.
	f = newFake()
	delete(f.info.Options, "clientPin")
	f.setErr = errors.New("key said no")
	use(t, f, nil)
	(&term{answers: []string{"abcd", "abcd"}}).install(t)
	if _, _, err := run("pin", "set"); err == nil || strings.Contains(err.Error(), "stored") {
		t.Errorf("%v", err)
	}
}

func TestPinGenerateRefusals(t *testing.T) {
	calls := manager(t)
	f := newFake()
	delete(f.info.Options, "clientPin")
	f.info.MinPINLength = 6
	use(t, f, nil)
	pf := secretFile(t, "1234", 0o600)
	for name, args := range map[string][]string{
		"no destination":            {"pin", "set", "--generate", "12"},
		"below the minimum":         {"pin", "set", "--save-to", "keychain:a/b", "--generate", "5"},
		"above 63":                  {"pin", "set", "--save-to", "keychain:a/b", "--generate", "64"},
		"zero":                      {"pin", "set", "--save-to", "keychain:a/b", "--generate", "0"},
		"with a file":               {"pin", "set", "--save-to", "keychain:a/b", "--generate", "12", "--pin-file", pf},
		"with a manager":            {"pin", "set", "--save-to", "keychain:a/b", "--generate", "12", "--pin-from", "keychain:c/d"},
		"change, with a file":       {"pin", "change", "--save-to", "keychain:a/b", "--generate", "12", "--new-pin-file", pf},
		"change, no destination":    {"pin", "change", "--generate", "12"},
		"change, below the minimum": {"pin", "change", "--save-to", "keychain:a/b", "--generate", "5"},
	} {
		if strings.HasPrefix(name, "change") {
			f.info.Options["clientPin"] = true
			(&term{answers: []string{"currentpin"}}).install(t)
		} else {
			delete(f.info.Options, "clientPin")
		}
		if _, _, err := run(args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if len(*calls) != 0 || f.setPIN != "" || f.newPIN != "" {
		t.Errorf("something was stored or set: %+v %q %q", *calls, f.setPIN, f.newPIN)
	}
	// A failing generator stops before the store.
	generatePIN = func(int) ([]byte, error) { return nil, errors.New("no entropy") }
	delete(f.info.Options, "clientPin")
	if _, _, err := run("pin", "set", "--save-to", "keychain:a/b", "--generate", "12"); err == nil || !strings.Contains(err.Error(), "no entropy") || len(*calls) != 0 {
		t.Errorf("%v", err)
	}
}

func TestPinChangeSaveTo(t *testing.T) {
	calls := manager(t)
	f := newFake()
	use(t, f, nil)
	cur := secretFile(t, "oldpin\n", 0o600)
	out, e, err := run("pin", "change", "--pin-file", cur, "--save-to", "keychain:fido/key", "--generate", "10")
	if err != nil || len(*calls) != 1 || f.curPIN != "oldpin" || f.newPIN != (*calls)[0].pin || len(f.newPIN) != 10 {
		t.Fatalf("%v %+v cur=%q new=%q", err, *calls, f.curPIN, f.newPIN)
	}
	if strings.Contains(out+e, f.newPIN) {
		t.Error("the new PIN was printed")
	}
}

func TestPinChangeFailures(t *testing.T) {
	cur := secretFile(t, "oldpin", 0o600)
	args := func(extra ...string) []string {
		return append([]string{"pin", "change", "--pin-file", cur, "--save-to", "keychain:fido/key", "--generate", "10"}, extra...)
	}
	// The store fails: the key is not touched.
	manager(t, 1)
	f := newFake()
	use(t, f, nil)
	if _, _, err := run(args()...); err == nil || !strings.Contains(err.Error(), "the key was not touched") || f.newPIN != "" {
		t.Errorf("store failure: %v new=%q", err, f.newPIN)
	}
	// The key refuses, no --replace: the entry was new and stays.
	calls := manager(t)
	f = newFake()
	f.changeErr = errors.New("wrong PIN")
	use(t, f, nil)
	if _, _, err := run(args()...); err == nil || !strings.Contains(err.Error(), "wrong PIN") || !strings.Contains(err.Error(), "stays stored") || len(*calls) != 1 {
		t.Errorf("no replace: %v %+v", err, *calls)
	}
	// With --replace the CURRENT PIN is put back (it may be the entry it was read from).
	calls = manager(t)
	f = newFake()
	f.changeErr = errors.New("wrong PIN")
	use(t, f, nil)
	_, _, err := run(args("--replace")...)
	if err == nil || !strings.Contains(err.Error(), "put back") || len(*calls) != 2 || (*calls)[1].pin != "oldpin" || !(*calls)[1].o.Replace {
		t.Errorf("replace: %v %+v", err, *calls)
	}
	// ...and when even that fails, say which PIN the key and the entry hold.
	calls = manager(t, 2)
	f = newFake()
	f.changeErr = errors.New("wrong PIN")
	use(t, f, nil)
	if _, _, err := run(args("--replace")...); err == nil || !strings.Contains(err.Error(), "still has the CURRENT PIN") || len(*calls) != 2 {
		t.Errorf("undo failure: %v", err)
	}
	// Without --save-to nothing changes in the error.
	manager(t)
	f = newFake()
	f.changeErr = errors.New("wrong PIN")
	use(t, f, nil)
	(&term{answers: []string{"newpin", "newpin"}}).install(t)
	if _, _, err := run("pin", "change", "--pin-file", cur); err == nil || err.Error() != "wrong PIN" {
		t.Errorf("%v", err)
	}
}
