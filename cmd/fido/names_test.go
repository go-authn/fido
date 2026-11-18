package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authn "github.com/go-authn/fido"
)

// withConfigDir points the alias table at a fresh directory.
func withConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := userConfigDir
	t.Cleanup(func() { userConfigDir = old })
	userConfigDir = func() (string, error) { return dir, nil }
	return dir
}

func TestTheAliasTableIsPrivateAndRoundTrips(t *testing.T) {
	dir := withConfigDir(t)
	m, err := loadAliases()
	if err != nil || len(m) != 0 {
		t.Fatalf("a missing table: %v %v", m, err)
	}
	want := map[string]string{"serial:123/aa": "desk key", "port:iokit:1/bb": "clé ✓"}
	if err := saveAliases(want); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fido", "names")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("table mode %v %v", st, err)
	}
	if st, _ := os.Stat(filepath.Dir(path)); st.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", st.Mode().Perm())
	}
	got, err := loadAliases()
	if err != nil || len(got) != 2 || got["serial:123/aa"] != "desk key" || got["port:iokit:1/bb"] != "clé ✓" {
		t.Fatalf("%v %v", got, err)
	}
	// Lines that are not entries (no tab, no key, a name that is not a name) are
	// skipped, not fatal.
	os.WriteFile(path, []byte("garbage\n\tnokey\nk\t\nk2\tgood\nk3\tbad\x1bname\n"), 0o600)
	if got, _ = loadAliases(); len(got) != 1 || got["k2"] != "good" {
		t.Errorf("%v", got)
	}
	// Errors: no config dir, a directory where the table should be, a file where
	// the directory should be.
	boom := errors.New("no home")
	userConfigDir = func() (string, error) { return "", boom }
	if _, err := loadAliases(); !errors.Is(err, boom) {
		t.Errorf("load: %v", err)
	}
	if err := saveAliases(nil); !errors.Is(err, boom) {
		t.Errorf("save: %v", err)
	}
	if _, err := aliasPath(); !errors.Is(err, boom) {
		t.Errorf("path: %v", err)
	}
	userConfigDir = func() (string, error) { return dir, nil }
	os.Remove(path)
	os.Mkdir(path, 0o700)
	if _, err := loadAliases(); err == nil {
		t.Error("a directory read as a table")
	}
	os.Remove(path)
	os.Remove(filepath.Dir(path))
	os.WriteFile(filepath.Dir(path), []byte("x"), 0o600)
	if err := saveAliases(map[string]string{"a": "b"}); err == nil {
		t.Error("saved under a file")
	}
	os.Remove(filepath.Dir(path))
	// The temporary file cannot be written: a directory in its place.
	os.MkdirAll(path+".tmp", 0o700)
	if err := saveAliases(map[string]string{"a": "b"}); err == nil {
		t.Error("saved over a directory")
	}
}

func TestAnAliasKeyUsesTheSerialWhenThereIsOne(t *testing.T) {
	a := [16]byte{0xab}
	if got := aliasKey(a, device{ID: "iokit:1", Serial: "S9"}); !strings.HasPrefix(got, "serial:S9/ab") {
		t.Errorf("%q", got)
	}
	if got := aliasKey(a, device{ID: "iokit:1"}); !strings.HasPrefix(got, "port:iokit:1/ab") {
		t.Errorf("%q", got)
	}
	for src, want := range map[nameSource]string{
		nameNone: "no name", nameOnKey: "stored on the key",
		nameAlias: "local alias", nameHidden: "no local alias is set",
	} {
		if !strings.Contains(src.String(), want) {
			t.Errorf("%d: %q", src, src.String())
		}
	}
	if quoted("") != "" || quoted("a") != ` "a"` {
		t.Error("quoted")
	}
	if !strings.Contains(aliasBinding(device{Serial: "x"}), "serial") || !strings.Contains(aliasBinding(device{}), "USB port") {
		t.Error("aliasBinding")
	}
}

func TestKeyNameFindsItOnTheKeyOrInTheAliasTable(t *testing.T) {
	ctx := context.Background()
	withConfigDir(t)
	f := newFake()
	f.dev = device{ID: "iokit:7"}
	// On the key.
	f.stored = "desk"
	if n, src, err := keyName(ctx, f); n != "desk" || src != nameOnKey || err != nil {
		t.Errorf("%q %v %v", n, src, err)
	}
	// None.
	f.stored = ""
	if n, src, err := keyName(ctx, f); n != "" || src != nameNone || err != nil {
		t.Errorf("%q %v %v", n, src, err)
	}
	// Refused, with and without an alias.
	f.readNameErr = authn.ErrNameRefused
	if _, src, err := keyName(ctx, f); src != nameHidden || err != nil {
		t.Errorf("hidden: %v %v", src, err)
	}
	if err := saveAliases(map[string]string{aliasKey(f.identity.AAGUID, f.dev): "the alias"}); err != nil {
		t.Fatal(err)
	}
	if n, src, err := keyName(ctx, f); n != "the alias" || src != nameAlias || err != nil {
		t.Errorf("alias: %q %v %v", n, src, err)
	}
	// Refused and the key will not say who it is, or the table is unreadable.
	f.identityErr = errors.New("boom")
	if _, src, _ := keyName(ctx, f); src != nameHidden {
		t.Errorf("identity failing: %v", src)
	}
	f.identityErr = nil
	userConfigDir = func() (string, error) { return "", errors.New("no home") }
	if _, src, _ := keyName(ctx, f); src != nameHidden {
		t.Errorf("table failing: %v", src)
	}
	// Any other failure is the caller's.
	f.readNameErr = errors.New("the key vanished")
	if _, _, err := keyName(ctx, f); err == nil {
		t.Error("another error was swallowed")
	}
}

func TestNameShow(t *testing.T) {
	withConfigDir(t)
	f := newFake()
	use(t, f, nil)
	f.stored = "desk"
	if out, _, err := run("name", "show"); err != nil || !strings.Contains(out, "name: desk (stored on the key)") {
		t.Errorf("%v %q", err, out)
	}
	f.stored = ""
	if out, _, _ := run("name", "show"); !strings.Contains(out, "name: none (no name)") {
		t.Errorf("%q", out)
	}
	f.refuses = true
	if out, _, _ := run("name", "show"); !strings.Contains(out, "no local alias is set") {
		t.Errorf("%q", out)
	}
	f.readNameErr = errors.New("boom")
	f.refuses = false
	if _, _, err := run("name", "show"); err == nil {
		t.Error("a read error")
	}
	use(t, nil, errors.New("no key"))
	if _, _, err := run("name", "show"); err == nil {
		t.Error("no key")
	}
	f2 := newFake()
	f2.stored = "x"
	f2.refuses = true
	saveAliases(map[string]string{aliasKey(f2.identity.AAGUID, f2.dev): "alias name"})
	use(t, f2, nil)
	if out, _, _ := run("name", "show"); !strings.Contains(out, "alias name (local alias") {
		t.Errorf("%q", out)
	}
}

func TestNameSet(t *testing.T) {
	withConfigDir(t)
	pf := secretFile(t, "1234", 0o600)
	f := newFake()
	use(t, f, nil)
	// A name that cannot be stored is refused before the key is opened.
	if _, _, err := run("name", "set", "a\nb", "--pin-file", pf); err == nil || f.writes != 0 {
		t.Errorf("a bad name: %v writes=%d", err, f.writes)
	}
	// Stored on the key and readable: said so, no alias.
	out, _, err := run("name", "set", "desk key", "--pin-file", pf)
	if err != nil || !strings.Contains(out, `Named "desk key" (stored on the key; read with no touch and no PIN)`) || f.tokenPIN != "1234" || f.setNames[0] != "desk key" {
		t.Fatalf("%v %q", err, out)
	}
	if m, _ := loadAliases(); len(m) != 0 {
		t.Errorf("an alias was written for a key that answers: %v", m)
	}
	// A key that will not show it: also kept in the alias table, and said so.
	g := newFake()
	g.refuses = true
	g.dev = device{ID: "iokit:7"}
	use(t, g, nil)
	out, _, err = run("name", "set", "bio", "--pin-file", pf)
	if err != nil || !strings.Contains(out, "does not answer a read of it without a PIN") || !strings.Contains(out, "USB port") {
		t.Fatalf("%v %q", err, out)
	}
	if m, _ := loadAliases(); m[aliasKey(g.identity.AAGUID, g.dev)] != "bio" {
		t.Errorf("alias table %v", m)
	}
	// Setting again on a key that now answers drops the alias.
	g.refuses = false
	if _, _, err = run("name", "set", "bio2", "--pin-file", pf); err != nil {
		t.Fatal(err)
	}
	if m, _ := loadAliases(); len(m) != 0 {
		t.Errorf("a stale alias stayed: %v", m)
	}
}

func TestNameSetRefusals(t *testing.T) {
	withConfigDir(t)
	pf := secretFile(t, "1234", 0o600)
	boom := errors.New("boom")
	args := []string{"name", "set", "x", "--pin-file", pf}
	for name, mut := range map[string]func(*fake){
		"no PIN":        func(f *fake) { delete(f.info.Options, "clientPin") },
		"forced change": func(f *fake) { f.info.ForcePINChange = true },
		"retries":       func(f *fake) { f.retriesErr = boom },
		"info":          func(f *fake) { f.infoErr = boom },
		"tokens":        func(f *fake) { f.nameTokensErr = boom },
		"set":           func(f *fake) { f.setNameErr = boom },
		"read back":     func(f *fake) { f.readNameErr = boom },
		"identity":      func(f *fake) { f.refuses = true; f.identityErr = boom },
	} {
		f := newFake()
		mut(f)
		use(t, f, nil)
		if _, _, err := run(args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !f.closed {
			t.Errorf("%s: the key was not released", name)
		}
	}
	// An unreadable PIN file; no key; a table that cannot be read or written.
	f := newFake()
	use(t, f, nil)
	if _, _, err := run("name", "set", "x", "--pin-file", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing PIN file")
	}
	use(t, nil, boom)
	if _, _, err := run(args...); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
	g := newFake()
	g.refuses = true
	use(t, g, nil)
	userConfigDir = func() (string, error) { return "", boom }
	if _, _, err := run(args...); err == nil {
		t.Error("a hidden name with no usable alias table")
	}
	dir := withConfigDir(t)
	os.WriteFile(filepath.Join(dir, "fido"), []byte("x"), 0o600)
	if _, _, err := run(args...); err == nil {
		t.Error("an alias table that cannot be written")
	}
	// A table that reads but cannot be written (its temporary file is a directory).
	dir3 := withConfigDir(t)
	os.MkdirAll(filepath.Join(dir3, "fido", "names.tmp"), 0o700)
	use(t, g, nil)
	if _, _, err := run(args...); err == nil {
		t.Error("an alias that could not be saved")
	}
	// A successful set whose stale-alias cleanup fails.
	dir4 := withConfigDir(t)
	os.WriteFile(filepath.Join(dir4, "fido"), []byte("x"), 0o600)
	h := newFake()
	use(t, h, nil)
	if _, _, err := run(args...); err == nil {
		t.Error("alias cleanup failing was ignored")
	}
}

func TestNameRemove(t *testing.T) {
	withConfigDir(t)
	pf := secretFile(t, "1234", 0o600)
	f := newFake()
	f.stored = "desk"
	f.dev = device{ID: "iokit:7"}
	saveAliases(map[string]string{aliasKey(f.identity.AAGUID, f.dev): "alias"})
	use(t, f, nil)
	out, _, err := run("name", "remove", "--pin-file", pf)
	if err != nil || !strings.Contains(out, "The name was removed") || f.removedNames != 1 || f.stored != "" {
		t.Fatalf("%v %q", err, out)
	}
	if m, _ := loadAliases(); len(m) != 0 {
		t.Errorf("the alias stayed: %v", m)
	}
	boom := errors.New("boom")
	f.removeNameErr = boom
	if _, _, err := run("name", "remove", "--pin-file", pf); !errors.Is(err, boom) {
		t.Errorf("remove: %v", err)
	}
	f.removeNameErr = nil
	f.identityErr = boom // the alias cleanup cannot tell which key this is
	if _, _, err := run("name", "remove", "--pin-file", pf); err == nil {
		t.Error("identity failing in the cleanup")
	}
	use(t, nil, boom)
	if _, _, err := run("name", "remove", "--pin-file", pf); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
}

func TestADeviceFlagAcceptsANameOrAnID(t *testing.T) {
	withConfigDir(t)
	a, b := newAnswerKey("Alpha", nil), newAnswerKey("Beta", nil)
	a.stored, b.stored = "desk", "travel"
	devs := []device{a.device("id:a"), b.device("id:b")}
	withDevices(t, devs, nil)
	oc := chooseByTouch
	t.Cleanup(func() { chooseByTouch = oc })
	chooseByTouch = func(context.Context, []device) (*authn.Selected, error) {
		t.Error("a touch was asked although --device named the key")
		return nil, errors.New("unreachable")
	}
	// By ID, exactly; by name, exactly; a key's name appears in the announcement.
	if _, e, err := run("--device", "id:b", "info"); err != nil && !strings.Contains(e, `Key: Beta at id:b "travel"`) {
		t.Errorf("by id: %v %q", err, e)
	}
	_, e, _ := run("--device", "desk", "info")
	if !strings.Contains(e, `Key: Alpha at id:a "desk"`) {
		t.Errorf("by name: %q", e)
	}
	// Neither an id nor a name; a prefix of a name is not a name.
	for _, bad := range []string{"id:", "des", "Desk"} {
		if _, _, err := run("--device", bad, "info"); err == nil || !strings.Contains(err.Error(), "no attached key has the id or name") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// A name on two keys: refused, naming both.
	b.stored = "desk"
	devs = []device{a.device("id:a"), b.device("id:b")}
	withDevices(t, devs, nil)
	_, _, err := run("--device", "desk", "pin", "set", "--pin-file", secretFile(t, "abcdef", 0o600))
	if err == nil || !strings.Contains(err.Error(), "is on 2 keys") || !strings.Contains(err.Error(), "id:a") || !strings.Contains(err.Error(), "id:b") {
		t.Errorf("two keys with one name: %v", err)
	}
	// A key that will not open is skipped, not matched.
	bad := device{ID: "id:c", open: func(context.Context) (*authn.Key, error) { return nil, errors.New("busy") }}
	withDevices(t, []device{bad, a.device("id:a")}, nil)
	if _, e, _ := run("--device", "desk", "info"); !strings.Contains(e, "Alpha at id:a") {
		t.Errorf("%q", e)
	}
}

func TestListShowsNames(t *testing.T) {
	withConfigDir(t)
	a, b, c, d := newAnswerKey("Alpha", nil), newAnswerKey("Beta", nil), newAnswerKey("Gamma", nil), newAnswerKey("Delta", nil)
	a.stored = "desk"
	b.refuse = true // has a name it will not show, and an alias
	b.aaguid = 0xbb
	c.refuse = true // hides it and has no alias
	// d has no name.
	db := b.device("id:b")
	saveAliases(map[string]string{aliasKey(authnAAGUID(0xbb), db): "travel"})
	failing := device{ID: "id:z", Name: "Zeta", open: func(context.Context) (*authn.Key, error) { return nil, errors.New("busy") }}
	withDevices(t, []device{a.device("id:a"), db, c.device("id:c"), d.device("id:d"), failing}, nil)
	out, _, err := run("list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NAME", "desk", "travel (alias)", "? (will not show it without a PIN)", "busy"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if got := nameCell("", nameNone, nil); got != "-" {
		t.Errorf("%q", got)
	}
	if got := nameCell("", nameNone, errors.New("fido: boom")); got != "? (boom)" {
		t.Errorf("%q", got)
	}
	// The name read failing for another reason is shown, not hidden.
	e := newAnswerKey("Eps", nil)
	e.readFail = true
	withDevices(t, []device{e.device("id:e")}, nil)
	if out, _, _ = run("list"); !strings.Contains(out, "? (") {
		t.Errorf("%s", out)
	}
}

func authnAAGUID(first byte) (a [16]byte) { a[0] = first; return a }
