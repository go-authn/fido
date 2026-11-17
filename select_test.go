// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// selKey is a key a person can touch: it answers the handshake and getInfo at
// once, and a touch request waits until touch is closed (the person touched
// THIS key) or CTAPHID_CANCEL arrives (it answers CTAP2_ERR_KEEPALIVE_CANCEL,
// 0x2D, as a real key does). It is safe for concurrent use: Select drives
// every key from its own goroutine.
type selKey struct {
	name     string
	versions []string
	options  map[string]bool
	// touchStatus is what the key answers a touch with (0 for authenticatorSelection).
	touchStatus byte
	touch       chan struct{}
	failSend    atomic.Bool // the key is unplugged: writes fail

	inbox     chan []byte
	cancelled chan struct{}
	cancelOne sync.Once
	closed    atomic.Int32
	mu        sync.Mutex
	asked     []byte // CBOR commands received
	reasm     map[uint32]*Reassembler
}

func newSelKey(name string, versions ...string) *selKey {
	if len(versions) == 0 {
		versions = []string{"FIDO_2_0", "FIDO_2_1"}
	}
	return &selKey{
		name: name, versions: versions, options: map[string]bool{"clientPin": true},
		touch: make(chan struct{}), inbox: make(chan []byte, 64), cancelled: make(chan struct{}),
	}
}

func (s *selKey) Name() string { return s.name }
func (s *selKey) Close() error { s.closed.Add(1); return nil }

func (s *selKey) Receive(ctx context.Context) ([]byte, error) {
	select {
	case r := <-s.inbox:
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *selKey) say(ch uint32, cmd byte, data []byte) {
	p, _ := Split(ch, cmd, data)
	for _, r := range p {
		s.inbox <- r
	}
}

func (s *selKey) Send(report []byte) error {
	if s.failSend.Load() {
		return errors.New("the key was unplugged")
	}
	ch := binary.BigEndian.Uint32(report[0:4])
	s.mu.Lock()
	if s.reasm == nil {
		s.reasm = map[uint32]*Reassembler{}
	}
	r, ok := s.reasm[ch]
	if !ok {
		r = NewReassembler(ch)
		s.reasm[ch] = r
	}
	msg, done, err := r.Feed(report)
	s.mu.Unlock()
	if err != nil || !done {
		return nil // a request spans several reports: wait for the rest
	}
	const own = 0x0A0B0C0D
	switch msg.Cmd {
	case CmdInit:
		payload := make([]byte, 17)
		copy(payload, msg.Data[:8])
		binary.BigEndian.PutUint32(payload[8:12], own)
		payload[12], payload[13], payload[14], payload[15] = 2, 5, 7, 4
		payload[16] = byte(CapCBOR)
		s.say(BroadcastChannel, CmdInit, payload)
	case CmdCancel:
		s.cancelOne.Do(func() { close(s.cancelled) })
	case CmdCBOR:
		s.mu.Lock()
		s.asked = append(s.asked, msg.Data[0])
		s.mu.Unlock()
		go s.cbor(msg.Data[0])
	}
	return nil
}

func (s *selKey) cbor(cmd byte) {
	const own = 0x0A0B0C0D
	switch cmd {
	case CmdGetInfo:
		b, _ := ctap2.Marshal(map[uint64]any{infoVersions: s.versions, infoOptions: s.options})
		s.say(own, CmdCBOR, append([]byte{0}, b...))
	case CmdSelection, CmdMakeCredential:
		select {
		case <-s.touch:
			s.say(own, CmdCBOR, []byte{s.touchStatus})
		case <-s.cancelled:
			s.say(own, CmdCBOR, []byte{0x2D})
		}
	}
}

func (s *selKey) askedCommands() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}

func (s *selKey) candidate() Candidate {
	return Candidate{Label: s.name, Open: func(ctx context.Context) (*Key, error) { return Open(ctx, s) }}
}

func timeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), d)
	t.Cleanup(stop)
	return ctx
}

func TestTheTouchedKeyWinsAndTheOthersAreCancelledAndClosed(t *testing.T) {
	a, b, c := newSelKey("A"), newSelKey("B"), newSelKey("C")
	go func() { time.Sleep(50 * time.Millisecond); close(b.touch) }()
	sel, err := Select(timeout(t, 5*time.Second), []Candidate{a.candidate(), b.candidate(), c.candidate()})
	if err != nil {
		t.Fatal(err)
	}
	defer sel.Key.Close()
	if sel.Index != 1 || sel.Label != "B" || len(sel.AlsoTouched) != 0 || len(sel.Failures) != 0 {
		t.Fatalf("%+v", sel)
	}
	if sel.Key.Name() != "B" || sel.Info.Versions[1] != "FIDO_2_1" {
		t.Errorf("the key or its info: %v %+v", sel.Key.Name(), sel.Info)
	}
	for _, k := range []*selKey{a, c} {
		select {
		case <-k.cancelled:
		case <-time.After(2 * time.Second):
			t.Errorf("%s was not sent CTAPHID_CANCEL", k.name)
		}
		if k.closed.Load() != 1 {
			t.Errorf("%s closed %d times", k.name, k.closed.Load())
		}
	}
	if b.closed.Load() != 0 {
		t.Error("the chosen key was closed")
	}
	// authenticatorSelection was the request, and nothing that makes anything.
	if got := b.askedCommands(); !slices.Equal(got, []byte{CmdGetInfo, CmdSelection}) {
		t.Errorf("asked %v", got)
	}
}

func TestEachKeyIsTheWinnerWhenItIsTheOneTouched(t *testing.T) {
	// The wrong one touched is the whole point: the answer follows the finger,
	// not the order of the list.
	for want := range 3 {
		ks := []*selKey{newSelKey("A"), newSelKey("B"), newSelKey("C")}
		close(ks[want].touch)
		sel, err := Select(timeout(t, 5*time.Second), []Candidate{ks[0].candidate(), ks[1].candidate(), ks[2].candidate()})
		if err != nil || sel.Index != want {
			t.Fatalf("touched %d: %v %+v", want, err, sel)
		}
		sel.Key.Close()
	}
}

func TestTwoKeysTouchedTogetherIsReported(t *testing.T) {
	a, b := newSelKey("A"), newSelKey("B")
	close(a.touch)
	close(b.touch)
	sel, err := Select(timeout(t, 5*time.Second), []Candidate{a.candidate(), b.candidate()})
	if err != nil {
		t.Fatal(err)
	}
	defer sel.Key.Close()
	// Whether the second was touched before it could be cancelled depends on
	// timing; when it was, it is named, never silently dropped.
	if len(sel.AlsoTouched) > 1 || (len(sel.AlsoTouched) == 1 && sel.AlsoTouched[0] == sel.Label) {
		t.Errorf("%+v", sel)
	}
}

// settle is driven with the outcomes written out, in arrival order, so the
// cases that depend on timing in a real run are checked deterministically.
func TestSettleWithOutcomesWrittenOut(t *testing.T) {
	a, b, c, d := newSelKey("A"), newSelKey("B"), newSelKey("C"), newSelKey("D")
	open := func(s *selKey) *Key {
		k, err := Open(timeout(t, time.Second), s)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	boom := errors.New("boom")
	cands := []Candidate{a.candidate(), b.candidate(), c.candidate(), d.candidate()}
	kb, kc, kd := open(b), open(c), open(d)
	sel, err := settle(cands, []outcome{
		{i: 3, err: boom},
		{i: 1, key: kb, touched: true}, // first touched: the winner
		{i: 2, key: kc, touched: true}, // touched too, before it could be cancelled
		{i: 0},                         // cancelled: no key, no error
		{i: 3, key: kd},                // a key not touched is closed
	}, nil)
	if err != nil || sel.Index != 1 || sel.Key != kb || !slices.Equal(sel.AlsoTouched, []string{"C"}) ||
		len(sel.Failures) != 1 || sel.Failures[0].Index != 3 {
		t.Fatalf("%v %+v", err, sel)
	}
	if c.closed.Load() != 1 || d.closed.Load() != 1 || b.closed.Load() != 0 {
		t.Errorf("closed: b=%d c=%d d=%d", b.closed.Load(), c.closed.Load(), d.closed.Load())
	}
	// No winner: the failures, in list order, and the context's error.
	_, err = settle(cands, []outcome{{i: 2, err: boom}, {i: 0, err: boom}}, context.DeadlineExceeded)
	var se *SelectError
	if !errors.As(err, &se) || se.Failures[0].Index != 0 || se.Cause != context.DeadlineExceeded {
		t.Errorf("%v", err)
	}
}

func TestNothingTouchedIsATimeoutNotAnotherKey(t *testing.T) {
	a, b := newSelKey("A"), newSelKey("B")
	_, err := Select(timeout(t, 200*time.Millisecond), []Candidate{a.candidate(), b.candidate()})
	var se *SelectError
	if !errors.As(err, &se) || !errors.Is(err, context.DeadlineExceeded) || len(se.Failures) != 0 {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "no key was touched") {
		t.Errorf("%q", err)
	}
	for _, k := range []*selKey{a, b} {
		if k.closed.Load() != 1 {
			t.Errorf("%s not released", k.name)
		}
	}
}

func TestAKeyThatCannotBeAskedIsReportedBesideTheWinner(t *testing.T) {
	boom := errors.New("would not open")
	a, b, c := newSelKey("A"), newSelKey("B"), newSelKey("C")
	c.versions = []string{"FIDO_2_0"}
	c.options = map[string]bool{} // no PIN capability: cannot be chosen without making a credential
	go func() { time.Sleep(300 * time.Millisecond); close(b.touch) }()
	cands := []Candidate{
		{Label: "A", Open: func(context.Context) (*Key, error) { return nil, boom }},
		b.candidate(), c.candidate(),
	}
	_ = a
	sel, err := Select(timeout(t, 5*time.Second), cands)
	if err != nil {
		t.Fatal(err)
	}
	defer sel.Key.Close()
	if sel.Index != 1 || len(sel.Failures) != 2 || sel.Failures[0].Index != 0 || !errors.Is(sel.Failures[0], boom) ||
		!strings.Contains(sel.Failures[1].Err.Error(), "cannot be chosen by touch") {
		t.Errorf("%+v", sel.Failures)
	}
}

func TestAKeyUnpluggedWhileWaitingDoesNotStopTheOthers(t *testing.T) {
	a, b := newSelKey("A"), newSelKey("B")
	go func() {
		time.Sleep(30 * time.Millisecond)
		a.failSend.Store(true) // unplugged: even the cancel cannot be sent
		time.Sleep(30 * time.Millisecond)
		close(b.touch)
	}()
	sel, err := Select(timeout(t, 5*time.Second), []Candidate{a.candidate(), b.candidate()})
	if err != nil || sel.Label != "B" {
		t.Fatalf("%v %+v", err, sel)
	}
	sel.Key.Close()
}

func TestEveryKeyFailingIsListedPerKey(t *testing.T) {
	x, y := errors.New("x"), errors.New("y")
	a := newSelKey("A")
	a.options["clientPin"] = true
	_, err := Select(timeout(t, 5*time.Second), []Candidate{
		{Label: "X", Open: func(context.Context) (*Key, error) { return nil, x }},
		{Label: "Y", Open: func(context.Context) (*Key, error) { return nil, y }},
	})
	var se *SelectError
	if !errors.As(err, &se) || se.Cause != nil || len(se.Failures) != 2 || !errors.Is(err, x) || !errors.Is(err, y) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "X: x; Y: y") || !strings.HasPrefix(err.Error(), "fido: no key was chosen") {
		t.Errorf("%q", err)
	}
	if (&SelectError{}).Error() != "fido: no key was chosen" {
		t.Error("an empty error")
	}
	if _, err := Select(context.Background(), nil); !errors.Is(err, ErrNoCandidates) {
		t.Errorf("none: %v", err)
	}
	var ce error = CandidateError{Index: 1, Label: "L", Err: x}
	if ce.Error() != "L: x" || !errors.Is(ce, x) {
		t.Errorf("%v", ce)
	}
}

func TestAnExplicitRefusalAndAnInfoFailureAreFailuresOfThatKey(t *testing.T) {
	a := newSelKey("A")
	a.touchStatus = 0x27 // CTAP2_ERR_OPERATION_DENIED
	close(a.touch)
	good := newSelKey("B")
	// B is touched after the others have had time to answer, so their failures
	// are in before the winner cancels the rest.
	go func() { time.Sleep(300 * time.Millisecond); close(good.touch) }()
	// A key whose getInfo fails: its channel works, but it answers nothing sane.
	bad := newSelKey("C")
	bad.versions = nil // parseInfo refuses an authenticator with no version
	bad.options = nil
	sel, err := Select(timeout(t, 5*time.Second), []Candidate{a.candidate(), bad.candidate(), good.candidate()})
	if err != nil || sel.Label != "B" {
		t.Fatalf("%v %+v", err, sel)
	}
	sel.Key.Close()
	var denied, info bool
	for _, f := range sel.Failures {
		var se *StatusError
		denied = denied || (errors.As(f, &se) && se.Status == StatusOperationDenied)
		info = info || strings.Contains(f.Err.Error(), "version")
	}
	if !denied || !info {
		t.Errorf("failures %+v", sel.Failures)
	}
}

func TestAFidoTwoZeroKeyIsAskedByTheMakeCredentialProbe(t *testing.T) {
	for name, status := range map[string]byte{"pin auth invalid": 0x33, "pin invalid": 0x31, "pin not set": 0x35, "it made one": 0x00} {
		k := newSelKey("old", "FIDO_2_0")
		k.touchStatus = status
		close(k.touch)
		sel, err := Select(timeout(t, 5*time.Second), []Candidate{k.candidate()})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sel.Key.Close()
		if got := k.askedCommands(); !slices.Equal(got, []byte{CmdGetInfo, CmdMakeCredential}) {
			t.Errorf("%s: asked %v", name, got)
		}
	}
	// A status that is not a touch is the key's failure.
	k := newSelKey("old", "FIDO_2_0")
	k.touchStatus = 0x01
	close(k.touch)
	if _, err := Select(timeout(t, 5*time.Second), []Candidate{k.candidate()}); err == nil {
		t.Error("an unrelated refusal counted as a touch")
	}
}

func TestTheProbeSendsAnEmptyPinUvAuthParam(t *testing.T) {
	// Byte level: the makeCredential carries pinUvAuthParam (0x08) as an empty
	// byte string and the protocol (0x09), and nothing that could succeed.
	var got map[uint64]cbor.RawMessage
	k := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd == CmdGetInfo {
			b, _ := ctap2.Marshal(map[uint64]any{infoVersions: []string{"FIDO_2_0"}, infoOptions: map[string]bool{"clientPin": true}})
			return append([]byte{0}, b...)
		}
		_ = cbor.Unmarshal(params, &got)
		return []byte{0x33}
	})
	info, _ := k.GetInfo(context.Background())
	if touched, err := waitForTouch(context.Background(), k, info); !touched || err != nil {
		t.Fatalf("%v %v", touched, err)
	}
	var p []byte
	var proto int
	if cbor.Unmarshal(got[8], &p) != nil || len(p) != 0 || cbor.Unmarshal(got[9], &proto) != nil || proto != 1 {
		t.Errorf("pinUvAuthParam %x protocol %x", got[8], got[9])
	}
	if _, has := got[7]; has {
		t.Error("options were sent")
	}
}

func TestCancelNamesTheKeyThatCouldNotBeReached(t *testing.T) {
	a := newSelKey("A")
	k, err := Open(timeout(t, time.Second), a)
	if err != nil {
		t.Fatal(err)
	}
	a.failSend.Store(true)
	if err := k.Cancel(); err == nil || !strings.Contains(err.Error(), "cannot cancel on A") {
		t.Errorf("%v", err)
	}
}

func TestIdentityNeedsNoTouch(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(cmd byte, _ []byte) []byte {
		if cmd != CmdGetInfo {
			t.Errorf("asked %#02x", cmd)
		}
		b, _ := ctap2.Marshal(map[uint64]any{
			infoVersions: []string{"FIDO_2_1"}, infoAAGUID: make([]byte, 16),
			infoOptions: map[string]bool{"clientPin": true, "bioEnroll": true}, infoForcePIN: true,
		})
		return append([]byte{0}, b...)
	})
	id, err := k.Identity(context.Background())
	if err != nil || !id.PINSet || !id.PINCapable || !id.FingerprintCapable || !id.FingerprintsEnrolled || !id.ForcePINChange {
		t.Fatalf("%+v %v", id, err)
	}
	if s := id.String(); !strings.Contains(s, "PIN set") || !strings.Contains(s, "fingerprints enrolled") || !strings.Contains(s, "Test Key") {
		t.Errorf("%q", s)
	}
	for in, want := range map[string][2]string{
		"none":  {"no PIN capability", "no fingerprint sensor"},
		"nopin": {"no PIN yet", "no fingerprint enrolled"},
	} {
		info := Info{Versions: []string{"x"}}
		if in == "nopin" {
			info.Options = map[string]bool{"clientPin": false, "bioEnroll": false}
		}
		if s := identityOf("K", info).String(); !strings.Contains(s, want[0]) || !strings.Contains(s, want[1]) {
			t.Errorf("%s: %q", in, s)
		}
	}
	bad := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0x01} })
	if _, err := bad.Identity(context.Background()); err == nil {
		t.Error("a refused getInfo gave an identity")
	}
}
