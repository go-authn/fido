package main

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	authn "github.com/go-authn/fido"
	linuxfido "github.com/go-gnulinux/fido"
	macfido "github.com/go-macos/fido"
)

// answerKey is a key that answers the handshake, getInfo and
// authenticatorSelection at once (so a touch is "instant").
type answerKey struct {
	name   string
	opts   map[string]bool
	aaguid byte
	mu     sync.Mutex
	inbox  chan []byte
	reasm  map[uint32]*authn.Reassembler
}

func newAnswerKey(name string, opts map[string]bool) *answerKey {
	return &answerKey{name: name, opts: opts, inbox: make(chan []byte, 32)}
}

func (a *answerKey) Name() string { return a.name }
func (a *answerKey) Close() error { return nil }
func (a *answerKey) Receive(ctx context.Context) ([]byte, error) {
	select {
	case r := <-a.inbox:
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (a *answerKey) say(ch uint32, cmd byte, data []byte) {
	p, _ := authn.Split(ch, cmd, data)
	for _, r := range p {
		a.inbox <- r
	}
}
func (a *answerKey) Send(report []byte) error {
	ch := binary.BigEndian.Uint32(report[0:4])
	a.mu.Lock()
	if a.reasm == nil {
		a.reasm = map[uint32]*authn.Reassembler{}
	}
	r, ok := a.reasm[ch]
	if !ok {
		r = authn.NewReassembler(ch)
		a.reasm[ch] = r
	}
	msg, done, err := r.Feed(report)
	a.mu.Unlock()
	if err != nil || !done {
		return nil
	}
	const own = 0x0A0B0C0D
	switch msg.Cmd {
	case authn.CmdInit:
		p := make([]byte, 17)
		copy(p, msg.Data[:8])
		binary.BigEndian.PutUint32(p[8:12], own)
		p[12], p[13], p[14], p[15] = 2, 5, 7, 4
		p[16] = byte(authn.CapCBOR)
		a.say(authn.BroadcastChannel, authn.CmdInit, p)
	case authn.CmdCBOR:
		switch msg.Data[0] {
		case authn.CmdGetInfo:
			aaguid := make([]byte, 16)
			aaguid[0] = a.aaguid
			b, _ := cbor.Marshal(map[uint64]any{1: []string{"FIDO_2_1"}, 3: aaguid, 4: a.opts})
			a.say(own, authn.CmdCBOR, append([]byte{0}, b...))
		case authn.CmdSelection:
			a.say(own, authn.CmdCBOR, []byte{0})
		default:
			a.say(own, authn.CmdCBOR, []byte{0x01}) // a command this fake does not know
		}
	}
	return nil
}

func (a *answerKey) device(id string) device {
	return device{ID: id, Label: a.name + " at " + id, Name: a.name, open: func(ctx context.Context) (*authn.Key, error) {
		return authn.Open(ctx, a)
	}}
}

// runCLI is the same helper main_test.go calls run.
func runCLI(args ...string) (string, string, error) { return run(args...) }

func withDevices(t *testing.T, devs []device, err error) {
	t.Helper()
	old := listDevices
	t.Cleanup(func() { listDevices = old })
	listDevices = func() ([]device, error) { return devs, err }
}

func TestDevicesAreListedPerPlatformInAStableOrder(t *testing.T) {
	ol, om, olo, oOM, oOL, og := listDevices, listMac, listLinux, openMacDevice, openLinuxDevice, goos
	t.Cleanup(func() {
		listDevices, listMac, listLinux, openMacDevice, openLinuxDevice, goos = ol, om, olo, oOM, oOL, og
	})
	opened := ""
	k := newAnswerKey("K", map[string]bool{})
	listMac = func() ([]macfido.Device, error) {
		return []macfido.Device{{Path: "iokit:2", Name: "B", Serial: "7"}, {Path: "iokit:1", Name: "A"}}, nil
	}
	openMacDevice = func(d macfido.Device) (authn.Transport, error) { opened = d.Path; return k, nil }
	listLinux = func() ([]linuxfido.Device, error) {
		return []linuxfido.Device{{Path: "/dev/hidraw1", Phys: "usb-0000:00:14.0-3/input0", Name: "Y"}, {Path: "/dev/hidraw0", Name: "X"}}, nil
	}
	openLinuxDevice = func(d linuxfido.Device) (authn.Transport, error) { opened = d.Path; return k, nil }

	goos = "darwin"
	ds, err := listDevices()
	if err != nil || len(ds) != 2 || ds[0].ID != "iokit:1" || ds[1].ID != "iokit:2" || ds[1].Serial != "7" || ds[1].Name != "B" {
		t.Fatalf("%+v %v", ds, err)
	}
	key, err := ds[1].open(context.Background())
	if err != nil || opened != "iokit:2" {
		t.Fatalf("opened %q %v", opened, err)
	}
	key.Close()

	goos = "linux"
	ds, err = listDevices()
	// The port when there is one, the node otherwise.
	if err != nil || len(ds) != 2 || ds[0].ID != "/dev/hidraw0" || ds[1].ID != "usb-0000:00:14.0-3/input0" {
		t.Fatalf("%+v %v", ds, err)
	}
	if key, err = ds[1].open(context.Background()); err != nil || opened != "/dev/hidraw1" {
		t.Fatalf("opened %q %v", opened, err)
	}
	key.Close()

	boom := errors.New("boom")
	openMacDevice = func(macfido.Device) (authn.Transport, error) { return nil, boom }
	openLinuxDevice = func(linuxfido.Device) (authn.Transport, error) { return nil, boom }
	if _, err := ds[0].open(context.Background()); !errors.Is(err, boom) {
		t.Errorf("linux open: %v", err)
	}
	goos = "darwin"
	ds, _ = listDevices()
	if _, err := ds[0].open(context.Background()); !errors.Is(err, boom) {
		t.Errorf("mac open: %v", err)
	}
	listMac = func() ([]macfido.Device, error) { return nil, boom }
	listLinux = func() ([]linuxfido.Device, error) { return nil, boom }
	for _, os := range []string{"darwin", "linux"} {
		goos = os
		if _, err := listDevices(); !errors.Is(err, boom) {
			t.Errorf("%s: %v", os, err)
		}
	}
	goos = "windows"
	if _, err := listDevices(); err == nil || !strings.Contains(err.Error(), "Windows refuses raw HID") {
		t.Errorf("windows: %v", err)
	}
}

func TestADeviceIsMatchedByItsExactID(t *testing.T) {
	devs := []device{{ID: "a:1"}, {ID: "a:2"}}
	if d, err := findDevice(devs, "a:2"); err != nil || d.ID != "a:2" {
		t.Fatalf("%v %v", d, err)
	}
	// A prefix or a position could name another key after a replug.
	for _, bad := range []string{"a:", "1", "A:2"} {
		if _, err := findDevice(devs, bad); err == nil || !strings.Contains(err.Error(), "a:1, a:2") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestOpenKeyWithoutAChoice(t *testing.T) {
	a, b := newAnswerKey("Alpha", nil), newAnswerKey("Beta", nil)
	boom := errors.New("boom")
	run := runCLI

	withDevices(t, nil, nil)
	if _, _, err := run("info"); !errors.Is(err, errNoKey) {
		t.Errorf("none: %v", err)
	}
	withDevices(t, nil, boom)
	if _, _, err := run("info"); !errors.Is(err, boom) {
		t.Errorf("list: %v", err)
	}

	// One key: used, and named BEFORE anything is done to it.
	withDevices(t, []device{a.device("id:a")}, nil)
	_, e, err := run("pin", "set", "--pin-file", secretFile(t, "abcdef", 0o600))
	if !strings.Contains(e, "This key will be changed: Alpha at id:a") {
		t.Errorf("a write was not announced: %v %q", err, e)
	}
	if _, e, _ = run("info"); !strings.Contains(e, "Key: Alpha at id:a") || strings.Contains(e, "will be changed") {
		t.Errorf("a read: %q", e)
	}

	// --device picks the named one, whatever the order.
	withDevices(t, []device{a.device("id:a"), b.device("id:b")}, nil)
	oc := chooseByTouch
	t.Cleanup(func() { chooseByTouch = oc })
	chooseByTouch = func(context.Context, []device) (*authn.Selected, error) {
		t.Error("a touch was asked although --device named the key")
		return nil, errors.New("unreachable")
	}
	if _, e, _ = run("--device", "id:b", "info"); !strings.Contains(e, "Key: Beta at id:b") {
		t.Errorf("--device: %q", e)
	}
	if _, _, err = run("--device", "id:zz", "info"); err == nil || !strings.Contains(err.Error(), "no attached key has the id") {
		t.Errorf("unknown: %v", err)
	}
	// The named key failing to open.
	bad := device{ID: "id:c", open: func(context.Context) (*authn.Key, error) { return nil, boom }}
	withDevices(t, []device{bad}, nil)
	if _, _, err = run("info"); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
}

func TestSeveralKeysAndNoDeviceMeansTouchToChoose(t *testing.T) {
	a, b := newAnswerKey("Alpha", map[string]bool{"clientPin": true}), newAnswerKey("Beta", map[string]bool{})
	withDevices(t, []device{a.device("id:a"), b.device("id:b")}, nil)
	oc, ot := chooseByTouch, selectTimeout
	t.Cleanup(func() { chooseByTouch, selectTimeout = oc, ot })
	chooseByTouch = oc // the real Select, over answering keys

	// A read-only command: the touched key is used, and every key was listed.
	out, e, err := runCLI("info")
	if err != nil {
		t.Fatalf("%v %q", err, e)
	}
	for _, want := range []string{"2 security keys are attached", "Alpha at id:a", "Beta at id:b", "Touch the key to use", "Key: "} {
		if !strings.Contains(e, want) {
			t.Errorf("stderr lacks %q:\n%s", want, e)
		}
	}
	if !strings.Contains(out, "aaguid") {
		t.Errorf("info did not run: %q", out)
	}

	// Select failing (nothing touched): nothing is changed.
	selectTimeout = time.Second
	chooseByTouch = func(ctx context.Context, _ []device) (*authn.Selected, error) {
		return nil, &authn.SelectError{Cause: context.DeadlineExceeded}
	}
	f := newFake()
	delete(f.info.Options, "clientPin")
	_, _, err = runCLI("pin", "set", "--pin-file", secretFile(t, "abcdef", 0o600))
	var se *authn.SelectError
	if !errors.As(err, &se) {
		t.Errorf("nothing touched: %v", err)
	}

	// Two keys touched at the same instant: a write refuses, a read warns.
	chooseByTouch = func(ctx context.Context, devs []device) (*authn.Selected, error) {
		k, err := devs[0].open(ctx)
		if err != nil {
			return nil, err
		}
		return &authn.Selected{Index: 0, Label: devs[0].Label, Key: k, AlsoTouched: []string{devs[1].Label}}, nil
	}
	_, _, err = runCLI("pin", "set", "--pin-file", secretFile(t, "abcdef", 0o600))
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), "touched at the same time") {
		t.Errorf("write on an ambiguous touch: %v", err)
	}
	_, e, err = runCLI("info")
	if err != nil || !strings.Contains(e, "Warning: Alpha at id:a and Beta at id:b were touched at the same time; using Alpha at id:a") {
		t.Errorf("read on an ambiguous touch: %v %q", err, e)
	}
}

func TestListShowsEveryKeyWithoutTouching(t *testing.T) {
	a := newAnswerKey("Alpha", map[string]bool{"clientPin": true, "bioEnroll": true})
	a.aaguid = 0xAB
	b := newAnswerKey("Beta", map[string]bool{"clientPin": false})
	c := newAnswerKey("Gamma", map[string]bool{})
	boom := errors.New("fido: busy\nsecond line")
	bad := device{ID: "id:d", Name: "Delta", open: func(context.Context) (*authn.Key, error) { return nil, boom }}
	// A key whose getInfo is refused after opening.
	refusing := device{ID: "id:e", Name: "Eps", open: func(ctx context.Context) (*authn.Key, error) {
		return authn.Open(ctx, &failInfo{newAnswerKey("Eps", nil)})
	}}
	da := a.device("id:a")
	da.Serial = "S1"
	withDevices(t, []device{da, b.device("id:b"), c.device("id:c"), bad, refusing}, nil)
	oc := chooseByTouch
	t.Cleanup(func() { chooseByTouch = oc })
	chooseByTouch = func(context.Context, []device) (*authn.Selected, error) {
		t.Error("list asked for a touch")
		return nil, errors.New("unreachable")
	}
	out, _, err := runCLI("list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ID", "id:a", "Alpha", "S1", "ab000000000000000000000000000000", "set", "enrolled", "not set", "no sensor", "none", "busy second line"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "\n") != 6 {
		t.Errorf("one line per key and a header:\n%s", out)
	}
	if !strings.Contains(out, "-") {
		t.Errorf("a missing serial should print a dash:\n%s", out)
	}

	withDevices(t, nil, nil)
	if _, _, err = runCLI("list"); !errors.Is(err, errNoKey) {
		t.Errorf("none: %v", err)
	}
	withDevices(t, nil, errors.New("boom"))
	if _, _, err = runCLI("list"); err == nil {
		t.Error("a listing error was swallowed")
	}
}

// failInfo answers the handshake but refuses getInfo.
type failInfo struct{ *answerKey }

func (f *failInfo) Send(report []byte) error {
	ch := binary.BigEndian.Uint32(report[0:4])
	if ch != authn.BroadcastChannel {
		const own = 0x0A0B0C0D
		f.say(own, authn.CmdCBOR, []byte{0x01})
		return nil
	}
	return f.answerKey.Send(report)
}

func TestWordsForPINAndFingerprints(t *testing.T) {
	for id, want := range map[string][2]string{
		"set":    {pinWord(authn.Identity{PINSet: true, PINCapable: true}), "set"},
		"forced": {pinWord(authn.Identity{PINSet: true, ForcePINChange: true}), "set (change required)"},
		"unset":  {pinWord(authn.Identity{PINCapable: true}), "not set"},
		"none":   {pinWord(authn.Identity{}), "none"},
		"fp":     {fingerprintWord(authn.Identity{FingerprintsEnrolled: true, FingerprintCapable: true}), "enrolled"},
		"fpnone": {fingerprintWord(authn.Identity{FingerprintCapable: true}), "none enrolled"},
		"nofp":   {fingerprintWord(authn.Identity{}), "no sensor"},
	} {
		if want[0] != want[1] {
			t.Errorf("%s: %q, want %q", id, want[0], want[1])
		}
	}
}

func TestTheOptionsLineIsOnlyTheOptions(t *testing.T) {
	info := authn.Info{Versions: []string{"FIDO_2_1"}, Options: map[string]bool{"uv": false, "clientPin": true, "bioEnroll": true}}
	if got := optionsLine(info); got != "bioEnroll, clientPin, uv=false" {
		t.Errorf("%q", got)
	}
	if got := optionsLine(authn.Info{}); got != "none declared" {
		t.Errorf("%q", got)
	}
}

func TestAnErrorIsPrefixedOnce(t *testing.T) {
	for in, want := range map[string]string{
		"fido: no security key is attached": "fido: no security key is attached",
		"no security key is attached":       "fido: no security key is attached",
	} {
		if got := errorLine(errors.New(in)); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
}
