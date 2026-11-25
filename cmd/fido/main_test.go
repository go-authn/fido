package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	authn "github.com/go-authn/fido"
)

// fake is a programmable key and enrollment interface in one.
type fake struct {
	info       authn.Info
	retries    authn.Retries
	uvRetries  int
	sensor     authn.SensorInfo
	enrollList []authn.Enrollment
	steps      []authn.EnrollStep

	// recorded
	setPIN, curPIN, newPIN, tokenPIN string
	// held is every PIN slice the key was handed, by reference: a test reads
	// it after the command to see that the slice was wiped.
	held             [][]byte
	proto            authn.PINProtocol
	perms            authn.Permissions
	timeout          time.Duration
	renamed, removed []byte
	renamedTo        string
	closed           bool
	writes           int // how many times a command asked to WRITE
	identity         authn.Identity
	dev              device
	identityErr      error
	// names: stored is what the key holds, refuses makes it hide it after
	// SetName (the silent read is refused), the errors are injected.
	stored                                                string
	refuses                                               bool
	setNames                                              []string
	removedNames                                          int
	readNameErr, setNameErr, removeNameErr, nameTokensErr error

	// makeCredential: the request seen, and what to answer.
	mcReq authn.MakeCredentialRequest
	mcFn  func(authn.MakeCredentialRequest) (*authn.Attestation, error)

	// injected errors
	ykInfo                                                          authn.YubiKeyInfo
	ykErr                                                           error
	infoErr, retriesErr, uvErr, setErr, changeErr, tokenErr, bioErr error
	sensorErr, enrollErr, listErr, renameErr, removeErr             error
}

func (f *fake) GetInfo(context.Context) (authn.Info, error)            { return f.info, f.infoErr }
func (f *fake) YubiKeyInfo(context.Context) (authn.YubiKeyInfo, error) { return f.ykInfo, f.ykErr }
func (f *fake) PINRetries(context.Context) (authn.Retries, error)      { return f.retries, f.retriesErr }
func (f *fake) UVRetries(context.Context) (int, error)                 { return f.uvRetries, f.uvErr }
func (f *fake) SetPINBytes(_ context.Context, p authn.PINProtocol, n []byte, _ uint) error {
	f.proto, f.setPIN = p, string(n)
	f.held = append(f.held, n)
	return f.setErr
}
func (f *fake) ChangePINBytes(_ context.Context, p authn.PINProtocol, c, n []byte, _ uint) error {
	f.proto, f.curPIN, f.newPIN = p, string(c), string(n)
	f.held = append(f.held, c, n)
	return f.changeErr
}
func (f *fake) PINTokenBytes(_ context.Context, pin []byte, p authn.PINProtocol, perms authn.Permissions, _ string) (authn.Token, error) {
	f.tokenPIN, f.proto, f.perms = string(pin), p, perms
	f.held = append(f.held, pin)
	return authn.Token{}, f.tokenErr
}
func (f *fake) Bio(authn.Info) (bioAPI, error) {
	if f.bioErr != nil {
		return nil, f.bioErr
	}
	return f, nil
}
func (f *fake) Identity(context.Context) (authn.Identity, error)     { return f.identity, f.identityErr }
func (f *fake) Close() error                                         { f.closed = true; return nil }
func (f *fake) Permissions() authn.Permissions                       { return authn.PermBioEnrollment }
func (f *fake) SensorInfo(context.Context) (authn.SensorInfo, error) { return f.sensor, f.sensorErr }
func (f *fake) Enroll(_ context.Context, _ authn.Token, t time.Duration, progress func(authn.EnrollStep)) ([]byte, error) {
	f.timeout = t
	for _, s := range f.steps {
		progress(s)
	}
	return []byte{0xab, 0xcd}, f.enrollErr
}
func (f *fake) Enumerate(context.Context, authn.Token) ([]authn.Enrollment, error) {
	return f.enrollList, f.listErr
}
func (f *fake) Rename(_ context.Context, _ authn.Token, id []byte, n string) error {
	f.renamed, f.renamedTo = id, n
	return f.renameErr
}
func (f *fake) Remove(_ context.Context, _ authn.Token, id []byte) error {
	f.removed = id
	return f.removeErr
}

func newFake() *fake {
	return &fake{
		info: authn.Info{
			Versions: []string{"FIDO_2_1"}, PINProtocols: []uint{2, 1},
			Options: map[string]bool{"clientPin": true, "bioEnroll": false},
		},
		retries: authn.Retries{PIN: 8}, uvRetries: 5,
		sensor: authn.SensorInfo{Touch: true, MaxSamples: 4, MaxNameLength: 16},
	}
}

// term scripts the terminal: each prompt gets the next answer.
type term struct {
	answers []string
	prompts []string
	err     error
}

func (tm *term) install(t *testing.T) {
	t.Helper()
	old := readTerminal
	t.Cleanup(func() { readTerminal = old })
	readTerminal = func(_ *cobra.Command, prompt string) ([]byte, error) {
		tm.prompts = append(tm.prompts, prompt)
		if tm.err != nil {
			return nil, tm.err
		}
		a := tm.answers[0]
		tm.answers = tm.answers[1:]
		return []byte(a), nil
	}
}

func use(t *testing.T, f *fake, openErr error) {
	t.Helper()
	old := openKey
	t.Cleanup(func() { openKey = old })
	openKey = func(cmd *cobra.Command, write bool) (keyAPI, error) {
		if openErr != nil {
			return nil, openErr
		}
		if write {
			f.writes++
		}
		return f, nil
	}
}

func run(args ...string) (stdout, stderr string, err error) {
	root := RootCmd()
	var o, e bytes.Buffer
	root.SetOut(&o)
	root.SetErr(&e)
	root.SetArgs(args)
	err = root.Execute()
	return o.String(), e.String(), err
}

func secretFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

var boom = errors.New("boom")

func TestPinSet(t *testing.T) {
	f := newFake()
	delete(f.info.Options, "clientPin")
	use(t, f, nil)
	tm := &term{answers: []string{"s3cret", "s3cret"}}
	tm.install(t)
	out, _, err := run("pin", "set")
	if err != nil || f.setPIN != "s3cret" || f.proto != authn.PINProtocolTwo || !strings.Contains(out, "PIN set") || !f.closed {
		t.Fatalf("%v %q %v %q", err, f.setPIN, f.proto, out)
	}
	if len(tm.prompts) != 2 || !strings.Contains(tm.prompts[1], "again") {
		t.Errorf("prompts %v: a new PIN is typed twice", tm.prompts)
	}
	// From a file, with protocol one only.
	f = newFake()
	delete(f.info.Options, "clientPin")
	f.info.PINProtocols = []uint{1}
	use(t, f, nil)
	if _, _, err = run("pin", "set", "--pin-file", secretFile(t, "filepin\n", 0o600)); err != nil || f.setPIN != "filepin" || f.proto != authn.PINProtocolOne {
		t.Fatalf("%v %q %v", err, f.setPIN, f.proto)
	}
}

func TestPinSetRefusals(t *testing.T) {
	tm := &term{answers: []string{"aaaa", "bbbb"}}
	tm.install(t)
	f := newFake()
	delete(f.info.Options, "clientPin")
	use(t, f, nil)
	if _, _, err := run("pin", "set"); err == nil || !strings.Contains(err.Error(), "differ") || f.setPIN != "" {
		t.Errorf("mismatch: %v", err)
	}
	tm.answers = []string{"aaaa"} // the second prompt finds no answer
	tm.err = nil
	tm2 := &term{err: boom}
	tm2.install(t)
	if _, _, err := run("pin", "set"); !errors.Is(err, boom) {
		t.Errorf("terminal error: %v", err)
	}
	// The second read failing.
	n := 0
	old := readTerminal
	readTerminal = func(*cobra.Command, string) ([]byte, error) {
		n++
		if n == 2 {
			return nil, boom
		}
		return []byte("aaaa"), nil
	}
	if _, _, err := run("pin", "set"); !errors.Is(err, boom) {
		t.Errorf("second read: %v", err)
	}
	readTerminal = old
	f.setErr = boom
	tm3 := &term{answers: []string{"aaaa", "aaaa"}}
	tm3.install(t)
	if _, _, err := run("pin", "set"); !errors.Is(err, boom) {
		t.Errorf("SetPIN error: %v", err)
	}
	f2 := newFake() // already has a PIN
	use(t, f2, nil)
	if _, _, err := run("pin", "set"); err == nil || !strings.Contains(err.Error(), "pin change") {
		t.Errorf("already set: %v", err)
	}
	f2.infoErr = boom
	if _, _, err := run("pin", "set"); !errors.Is(err, boom) {
		t.Errorf("info: %v", err)
	}
	use(t, nil, boom)
	if _, _, err := run("pin", "set"); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
}

func TestPinChange(t *testing.T) {
	f := newFake()
	use(t, f, nil)
	tm := &term{answers: []string{"old", "new1", "new1"}}
	tm.install(t)
	out, _, err := run("pin", "change")
	if err != nil || f.curPIN != "old" || f.newPIN != "new1" || !strings.Contains(out, "PIN changed") {
		t.Fatalf("%v %q %q %q", err, f.curPIN, f.newPIN, out)
	}
	cur, nw := secretFile(t, "cur", 0o600), secretFile(t, "nw", 0o600)
	if _, _, err = run("pin", "change", "--pin-file", cur, "--new-pin-file", nw); err != nil || f.curPIN != "cur" || f.newPIN != "nw" {
		t.Fatalf("files: %v %q %q", err, f.curPIN, f.newPIN)
	}
	// Few tries left: a warning, not a refusal.
	f.retries.PIN = 2
	if _, e, err := run("pin", "change", "--pin-file", cur, "--new-pin-file", nw); err != nil || !strings.Contains(e, "2 PIN tries left") {
		t.Errorf("warning: %v %q", err, e)
	}
}

func TestPinChangeRefusals(t *testing.T) {
	cur, nw := secretFile(t, "cur", 0o600), secretFile(t, "nw", 0o600)
	args := []string{"pin", "change", "--pin-file", cur, "--new-pin-file", nw}
	f := newFake()
	use(t, f, nil)
	f.retries.PowerCycle = true
	if _, _, err := run(args...); err == nil || !strings.Contains(err.Error(), "unplugged") {
		t.Errorf("power cycle: %v", err)
	}
	f.retries = authn.Retries{}
	if _, _, err := run(args...); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("blocked: %v", err)
	}
	f.retries = authn.Retries{PIN: 8}
	f.retriesErr = boom
	if _, _, err := run(args...); !errors.Is(err, boom) {
		t.Errorf("retries: %v", err)
	}
	f.retriesErr = nil
	f.changeErr = boom
	if _, _, err := run(args...); !errors.Is(err, boom) {
		t.Errorf("change: %v", err)
	}
	// A current-PIN read error, and a new-PIN read error.
	if _, _, err := run("pin", "change", "--pin-file", filepath.Join(t.TempDir(), "missing"), "--new-pin-file", nw); err == nil {
		t.Error("missing current file")
	}
	if _, _, err := run("pin", "change", "--pin-file", cur, "--new-pin-file", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing new file")
	}
	delete(f.info.Options, "clientPin")
	if _, _, err := run(args...); err == nil || !strings.Contains(err.Error(), "pin set") {
		t.Errorf("no PIN: %v", err)
	}
	f.infoErr = boom
	if _, _, err := run(args...); !errors.Is(err, boom) {
		t.Errorf("info: %v", err)
	}
	use(t, nil, boom)
	if _, _, err := run(args...); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
}

func TestFingerprintAdd(t *testing.T) {
	f := newFake()
	f.steps = []authn.EnrollStep{
		{Status: authn.SampleGood, Remaining: 2},
		{Status: authn.SampleTooFast, Remaining: 2},
		{Status: authn.SampleGood, Remaining: 0},
	}
	use(t, f, nil)
	pf := secretFile(t, "1234", 0o600)
	out, _, err := run("fingerprint", "add", "--name", "left index", "--timeout", "5s", "--pin-file", pf)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"about 4 good touches", "Touch the sensor again: 2 samples left", "Not counted: moved too fast", "Done", "Enrolled fingerprint abcd", `Named it "left index"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if f.tokenPIN != "1234" || f.perms != authn.PermBioEnrollment || f.timeout != 5*time.Second || f.renamedTo != "left index" || !f.closed {
		t.Errorf("recorded %+v", f)
	}
	// Without a name: no rename.
	f.renamedTo = ""
	if _, _, err = run("fp", "add", "--pin-file", pf); err != nil || f.renamedTo != "" {
		t.Errorf("unnamed: %v %q", err, f.renamedTo)
	}
}

func TestFingerprintAddRefusals(t *testing.T) {
	pf := secretFile(t, "1234", 0o600)
	add := []string{"fingerprint", "add", "--pin-file", pf}
	f := newFake()
	use(t, f, nil)
	f.tokenErr = boom
	if _, _, err := run(add...); !errors.Is(err, boom) {
		t.Errorf("session: %v", err)
	}
	f.tokenErr = nil
	f.sensorErr = boom
	if _, _, err := run(add...); !errors.Is(err, boom) {
		t.Errorf("sensor: %v", err)
	}
	f.sensorErr = nil
	if _, _, err := run(append(add, "--name", strings.Repeat("n", 17))...); err == nil || !strings.Contains(err.Error(), "at most 16") {
		t.Errorf("long name: %v", err)
	}
	f.enrollErr = boom
	if _, _, err := run(add...); !errors.Is(err, boom) {
		t.Errorf("enroll: %v", err)
	}
	f.enrollErr, f.renameErr = nil, boom
	if _, _, err := run(append(add, "--name", "x")...); err == nil || !strings.Contains(err.Error(), "could not name it") || !strings.Contains(err.Error(), "abcd") {
		t.Errorf("rename: %v", err)
	}
}

func TestSessionRefusals(t *testing.T) {
	pf := secretFile(t, "1234", 0o600)
	list := []string{"fingerprint", "list", "--pin-file", pf}
	for name, c := range map[string]struct {
		mut  func(*fake)
		want string
	}{
		"info":          {func(f *fake) { f.infoErr = boom }, "boom"},
		"no bio":        {func(f *fake) { f.bioErr = boom }, "boom"},
		"no PIN":        {func(f *fake) { delete(f.info.Options, "clientPin") }, "pin set"},
		"forced change": {func(f *fake) { f.info.ForcePINChange = true }, "pin change"},
		"retries":       {func(f *fake) { f.retriesErr = boom }, "boom"},
		"token":         {func(f *fake) { f.tokenErr = boom }, "boom"},
	} {
		f := newFake()
		c.mut(f)
		use(t, f, nil)
		if _, _, err := run(list...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if !f.closed {
			t.Errorf("%s: the key was not released", name)
		}
	}
	use(t, nil, boom)
	if _, _, err := run(list...); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
	use(t, newFake(), nil)
	if _, _, err := run("fingerprint", "list", "--pin-file", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing PIN file")
	}
}

func TestFingerprintListRenameRemove(t *testing.T) {
	pf := secretFile(t, "1234", 0o600)
	f := newFake()
	f.enrollList = []authn.Enrollment{{ID: []byte{1, 2}, Name: "thumb"}, {ID: []byte{3}}}
	use(t, f, nil)
	out, _, err := run("fingerprint", "list", "--pin-file", pf)
	if err != nil || !strings.Contains(out, "0102  thumb") || !strings.Contains(out, "03  (no name)") {
		t.Fatalf("%v\n%s", err, out)
	}
	f.enrollList = nil
	if out, _, _ = run("fingerprint", "list", "--pin-file", pf); !strings.Contains(out, "No fingerprint") {
		t.Errorf("empty: %q", out)
	}
	f.listErr = boom
	if _, _, err = run("fingerprint", "list", "--pin-file", pf); !errors.Is(err, boom) {
		t.Errorf("list: %v", err)
	}

	if _, _, err = run("fingerprint", "rename", "0102", "ring", "--pin-file", pf); err != nil || string(f.renamed) != "\x01\x02" || f.renamedTo != "ring" {
		t.Errorf("rename: %v %x %q", err, f.renamed, f.renamedTo)
	}
	if _, _, err = run("fingerprint", "remove", "03", "--pin-file", pf); err != nil || string(f.removed) != "\x03" {
		t.Errorf("remove: %v %x", err, f.removed)
	}
	for _, args := range [][]string{{"rename", "zz", "x"}, {"rename", "", "x"}, {"remove", "zz"}, {"remove", ""}} {
		if _, _, err = run(append([]string{"fingerprint"}, append(args, "--pin-file", pf)...)...); err == nil || !strings.Contains(err.Error(), "not a fingerprint id") {
			t.Errorf("%v: %v", args, err)
		}
	}
	// Session failures before the call (a key that is not there).
	use(t, nil, boom)
	for _, args := range [][]string{{"rename", "01", "x"}, {"remove", "01"}} {
		if _, _, err = run(append([]string{"fingerprint"}, append(args, "--pin-file", pf)...)...); !errors.Is(err, boom) {
			t.Errorf("%v: %v", args, err)
		}
	}
	f.renameErr, f.removeErr = boom, boom
	use(t, f, nil)
	for _, args := range [][]string{{"rename", "01", "x"}, {"remove", "01"}} {
		if _, _, err = run(append([]string{"fingerprint"}, append(args, "--pin-file", pf)...)...); !errors.Is(err, boom) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestInfo(t *testing.T) {
	f := newFake()
	use(t, f, nil)
	out, _, err := run("info")
	for _, want := range []string{"PIN:            set (minimum 4 characters)", "PIN tries:      8 left", "touch sensor, 4 good samples", "none enrolled", "fingerprint tries: 5 left"} {
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("lacks %q (%v):\n%s", want, err, out)
		}
	}
	// Some enrolled, a swipe sensor, forced change, power cycle, stated minimum.
	f.info.Options["bioEnroll"] = true
	f.info.MinPINLength, f.info.ForcePINChange = 6, true
	f.sensor.Touch = false
	f.retries.PowerCycle = true
	f.uvErr = boom
	out, _, _ = run("info")
	for _, want := range []string{"minimum 6", "unplug the key", "must be changed", "swipe sensor", "some enrolled"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fingerprint tries") {
		t.Error("tries printed though the key would not say")
	}
	// No PIN, no bio.
	g := newFake()
	delete(g.info.Options, "clientPin")
	g.bioErr = boom
	use(t, g, nil)
	out, _, err = run("info")
	if err != nil || !strings.Contains(out, "not set") || !strings.Contains(out, "no enrollment on this key") {
		t.Errorf("%v\n%s", err, out)
	}
	// A retries failure is not fatal; a sensor failure is.
	g.retriesErr, g.bioErr = boom, nil
	g.info.Options["clientPin"] = true
	g.sensorErr = boom
	if _, _, err = run("info"); !errors.Is(err, boom) {
		t.Errorf("sensor: %v", err)
	}
	g.infoErr = boom
	if _, _, err = run("info"); !errors.Is(err, boom) {
		t.Errorf("info: %v", err)
	}
	use(t, nil, boom)
	if _, _, err = run("info"); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
}

func TestSecretFilesAreRefusedUnlessPrivate(t *testing.T) {
	if _, err := readSecretFile(secretFile(t, "x", 0o644)); err == nil || !strings.Contains(err.Error(), "must not be readable") {
		t.Errorf("0644: %v", err)
	}
	if _, err := readSecretFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	if _, err := readSecretFile(secretFile(t, strings.Repeat("a", maxSecretFile+1), 0o600)); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("long: %v", err)
	}
	if _, err := readSecretFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing")
	}
	for in, want := range map[string]string{"pin\r\n": "pin", "pin\n": "pin", "pin": "pin", "\n": "", "": ""} {
		if b, err := readSecretFile(secretFile(t, in, 0o600)); err != nil || string(b) != want {
			t.Errorf("%q -> %q %v", in, b, err)
		}
	}
}

func TestTheTerminalIsNeededWithoutAFile(t *testing.T) {
	old := isTerminal
	t.Cleanup(func() { isTerminal = old })
	isTerminal = func(int) bool { return false }
	if _, err := readTerminal(&cobra.Command{}, "PIN: "); err == nil || !strings.Contains(err.Error(), "--pin-file") {
		t.Errorf("no terminal: %v", err)
	}
	isTerminal = func(int) bool { return true }
	oldRead := readPassword
	t.Cleanup(func() { readPassword = oldRead })
	readPassword = func(int) ([]byte, error) { return []byte("typed"), nil }
	cmd := &cobra.Command{}
	var e bytes.Buffer
	cmd.SetErr(&e)
	if b, err := readTerminal(cmd, "PIN: "); err != nil || string(b) != "typed" || !strings.Contains(e.String(), "PIN: ") {
		t.Errorf("%q %v %q", b, err, e.String())
	}
}

// handshakeTransport answers the CTAPHID INIT handshake of authn.Open.
type handshakeTransport struct{ reply []byte }

func (h *handshakeTransport) Send(r []byte) error {
	// The INIT request: channel (4), command, length (2), then the 8-byte nonce.
	data := append(append(append([]byte{}, r[7:15]...), 0x01, 0x02, 0x03, 0x04), 2, 5, 7, 4, 0x04)
	pk, err := authn.Split(authn.BroadcastChannel, authn.CmdInit, data)
	if err != nil {
		return err
	}
	h.reply = pk[0]
	return nil
}
func (h *handshakeTransport) Receive(context.Context) ([]byte, error) { return h.reply, nil }
func (h *handshakeTransport) Name() string                            { return "handshake" }
func (h *handshakeTransport) Close() error                            { return nil }

func handshakeKey(t *testing.T) (*authn.Key, error) {
	t.Helper()
	return authn.Open(context.Background(), &handshakeTransport{})
}

func TestTheRealKeyAdapterHandsOutTheEnrollmentInterface(t *testing.T) {
	k, err := handshakeKey(t)
	if err != nil {
		t.Fatal(err)
	}
	r := realKey{k, device{}}
	if _, err := r.Bio(authn.Info{}); err == nil {
		t.Error("a key without bio enrollment got an interface")
	}
	b, err := r.Bio(authn.Info{Options: map[string]bool{"bioEnroll": false}})
	if err != nil || b.Permissions() != authn.PermBioEnrollment {
		t.Errorf("%v %v", b, err)
	}
}

func TestMainReportsAnError(t *testing.T) {
	saved, args := osExit, os.Args
	defer func() { osExit, os.Args = saved, args }()
	code := 0
	osExit = func(c int) { code = c }
	os.Args = []string{"fido", "nonsense"}
	main()
	if code != 1 {
		t.Errorf("exit code %d", code)
	}
	code = 0
	use(t, nil, boom)
	os.Args = []string{"fido", "info"}
	main()
	if code != 1 {
		t.Errorf("exit code %d", code)
	}
}

func TestProtocolChoice(t *testing.T) {
	if protocolOf(authn.Info{PINProtocols: []uint{1}}) != authn.PINProtocolOne || protocolOf(authn.Info{PINProtocols: []uint{1, 2}}) != authn.PINProtocolTwo {
		t.Error("protocol two is preferred where offered")
	}
	if ctxOf(&cobra.Command{}) == nil {
		t.Error("no context")
	}
}
