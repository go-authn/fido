// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// bioKey is a virtual key with bio enrollment, its Bio handle and a token.
func bioKey(t *testing.T, option string) (*virtualAuthenticator, *Key, *Bio, Token) {
	t.Helper()
	v := newVirtualAuthenticator(t, "1234").withBio(option)
	k := virtualKey(t, v)
	info, err := k.GetInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.Bio(info)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := k.PINToken(context.Background(), "1234", PINProtocolTwo, b.Permissions(), "")
	if err != nil {
		t.Fatal(err)
	}
	return v, k, b, tok
}

func TestBioModeFollowsTheOptions(t *testing.T) {
	for name, c := range map[string]struct {
		opts map[string]bool
		want BioMode
	}{
		"none":                 {map[string]bool{"rk": true}, BioUnsupported},
		"bioEnroll true":       {map[string]bool{"bioEnroll": true}, BioFinal},
		"bioEnroll false":      {map[string]bool{"bioEnroll": false}, BioFinal},
		"preview only":         {map[string]bool{"userVerificationMgmtPreview": false}, BioPreview},
		"both: the final wins": {map[string]bool{"bioEnroll": false, "userVerificationMgmtPreview": true}, BioFinal},
	} {
		if got := (Info{Options: c.opts}).BioMode(); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	info, _ := k.GetInfo(context.Background())
	if _, err := k.Bio(info); err == nil || !strings.Contains(err.Error(), "does not declare bio enrollment") {
		t.Errorf("a key without it: %v", err)
	}
}

func TestEnrollingAFingerprintEndToEnd(t *testing.T) {
	ctx := context.Background()
	v, _, b, tok := bioKey(t, "bioEnroll")
	if b.Permissions() != PermBioEnrollment {
		t.Fatalf("permissions %v", b.Permissions())
	}
	si, err := b.SensorInfo(ctx)
	if err != nil || !si.Touch || si.MaxSamples != 4 || si.MaxNameLength != 16 {
		t.Fatalf("sensor %+v %v", si, err)
	}
	if _, has := v.bio.lastReq[bioAuthParam]; has {
		t.Error("getFingerprintSensorInfo carried a pinUvAuthParam")
	}

	// One bad sample in the middle: it does not count.
	v.bio.script = []SampleStatus{SampleGood, SampleTooFast, SampleGood, SampleGood, SampleGood}
	var steps []EnrollStep
	id, err := b.Enroll(ctx, tok, 750*time.Millisecond, func(s EnrollStep) { steps = append(steps, s) })
	if err != nil || len(id) != 8 {
		t.Fatalf("enroll: %x %v", id, err)
	}
	var got []string
	for _, s := range steps {
		got = append(got, s.Status.String())
		if string(s.TemplateID) != string(id) {
			t.Errorf("step names template %x, not %x", s.TemplateID, id)
		}
	}
	remaining := []int{3, 3, 2, 1, 0}
	for i, s := range steps {
		if s.Remaining != remaining[i] {
			t.Errorf("step %d: %d remaining, want %d (%v)", i, s.Remaining, remaining[i], got)
		}
	}
	if len(steps) != 5 || steps[1].Status != SampleTooFast {
		t.Errorf("steps %v", got)
	}
	// The per-sample timeout travelled in subCommandParams, in milliseconds.
	if v.bio.lastTimeout != 750 {
		t.Errorf("timeout on the wire: %d", v.bio.lastTimeout)
	}

	list, err := b.Enumerate(ctx, tok)
	if err != nil || len(list) != 1 || string(list[0].ID) != string(id) || list[0].Name != "" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := b.Rename(ctx, tok, id, "right index"); err != nil {
		t.Fatal(err)
	}
	if list, _ = b.Enumerate(ctx, tok); list[0].Name != "right index" {
		t.Errorf("name %q", list[0].Name)
	}
	if err := b.Remove(ctx, tok, id); err != nil {
		t.Fatal(err)
	}
	if list, err = b.Enumerate(ctx, tok); err != nil || len(list) != 0 {
		t.Errorf("after removal: %+v %v (none enrolled is an empty list, not an error)", list, err)
	}
}

func TestBeginWithoutATimeoutSendsNoParameters(t *testing.T) {
	v, _, b, tok := bioKey(t, "bioEnroll")
	if _, err := b.EnrollBegin(context.Background(), tok, 0); err != nil {
		t.Fatal(err)
	}
	if _, has := v.bio.lastReq[bioParams]; has {
		t.Error("an empty subCommandParams was sent")
	}
	// Enroll with no progress function is allowed.
	if _, err := b.Enroll(context.Background(), tok, 0, nil); err != nil {
		t.Fatal(err)
	}
}

func TestThePreviewCommandUsesTheLegacyToken(t *testing.T) {
	ctx := context.Background()
	v, _, b, tok := bioKey(t, "userVerificationMgmtPreview")
	if b.Permissions() != 0 {
		t.Fatalf("permissions %v", b.Permissions())
	}
	if _, err := b.Enroll(ctx, tok, 0, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(v.asked, "bio/0x40") || slices.Contains(v.asked, "bio/0x09") {
		t.Errorf("asked %v", v.asked)
	}
	if _, err := b.Enumerate(ctx, Token{}); err == nil || !strings.Contains(err.Error(), "from getPinToken") {
		t.Errorf("no token: %v", err)
	}
	// The final command is refused by a preview-only key.
	k := virtualKey(t, v)
	fin := &Bio{k: k, cmd: CmdBioEnrollment, perm: PermBioEnrollment}
	if _, err := fin.SensorInfo(ctx); err == nil {
		t.Error("a preview key answered the final command")
	}
}

func TestBioRefusals(t *testing.T) {
	ctx := context.Background()
	var se *StatusError
	v, k, b, tok := bioKey(t, "bioEnroll")
	// A token without the be permission.
	weak, err := k.PINToken(ctx, "1234", PINProtocolTwo, PermGetAssertion, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.EnrollBegin(ctx, weak, 0); !errors.As(err, &se) || se.Status != StatusPINAuthInvalid {
		t.Errorf("weak token: %v", err)
	}
	if _, err := b.Enumerate(ctx, weak); !errors.As(err, &se) {
		t.Errorf("weak token enumerate: %v", err)
	}
	// No token at all.
	if _, err := b.EnrollBegin(ctx, Token{}, 0); err == nil || !strings.Contains(err.Error(), "bio-enrollment permission") {
		t.Errorf("empty token: %v", err)
	}
	// (The virtual key holds one token at a time: ask for the real one again.)
	if tok, err = k.PINToken(ctx, "1234", PINProtocolTwo, PermBioEnrollment, ""); err != nil {
		t.Fatal(err)
	}
	// A full database.
	v.bio.capacity = 0
	if _, err := b.EnrollBegin(ctx, tok, 0); !errors.As(err, &se) || se.Status != 0x17 {
		t.Errorf("full: %v", err)
	}
	v.bio.capacity = 5
	// Next sample of an enrollment that is not under way.
	if _, err := b.EnrollNext(ctx, tok, []byte("nope"), 0); !errors.As(err, &se) || se.Status != StatusInvalidOption {
		t.Errorf("next: %v", err)
	}
	// Rename and remove what is not there; a name beyond the limit.
	if err := b.Rename(ctx, tok, []byte("nope"), "x"); !errors.As(err, &se) || se.Status != StatusInvalidOption {
		t.Errorf("rename unknown: %v", err)
	}
	if err := b.Remove(ctx, tok, []byte("nope")); !errors.As(err, &se) || se.Status != StatusInvalidOption {
		t.Errorf("remove unknown: %v", err)
	}
	id, _ := b.Enroll(ctx, tok, 0, nil)
	if err := b.Rename(ctx, tok, id, strings.Repeat("n", 17)); !errors.As(err, &se) || se.Status != 0x03 {
		t.Errorf("long name: %v", err)
	}
	// Enumerate propagates an error that is not "none".
	v.token = nil
	if _, err := b.Enumerate(ctx, tok); !errors.As(err, &se) || se.Status != StatusPINAuthInvalid {
		t.Errorf("enumerate: %v", err)
	}
	// A request the key cannot parse is not sent.
	if _, err := b.call(ctx, nil, subEnumerate, map[int]any{bpName: make(chan int)}); err == nil || !strings.Contains(err.Error(), "cannot encode") {
		t.Errorf("unencodable: %v", err)
	}
	// An unknown subcommand and a wrong modality, as an authenticator answers.
	if _, err := b.call(ctx, nil, 0x42, nil); !errors.As(err, &se) || se.Status != 0x3e {
		t.Errorf("unknown subcommand: %v", err)
	}
	if _, err := k.cborCall(ctx, CmdBioEnrollment, map[int]any{bioModality: 9, bioSub: subSensorInfo}); !errors.As(err, &se) {
		t.Errorf("modality: %v", err)
	}
	// An authenticated subcommand without a pinUvAuthParam.
	if _, err := b.call(ctx, nil, subEnumerate, nil); !errors.As(err, &se) || se.Status != 0x36 {
		t.Errorf("no param: %v", err)
	}
	// A sensor-info request WITH one is refused by the virtual key (as 6.7.3
	// lists no pinUvAuthParam).
	if _, err := k.cborCall(ctx, CmdBioEnrollment, map[int]any{bioModality: 1, bioSub: subSensorInfo, bioAuthParam: []byte{1}}); !errors.As(err, &se) {
		t.Errorf("param on sensor info: %v", err)
	}
}

func TestEnrollCancelsWhatItCannotFinish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, _, b, tok := bioKey(t, "bioEnroll")
	// The context ends after the first sample.
	_, err := b.Enroll(ctx, tok, 0, func(EnrollStep) { cancel() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if v.bio.enrolling != nil || len(v.bio.templates) != 0 {
		t.Error("an enrollment was left half-made")
	}
	if !slices.Contains(v.asked, "bio/0x09") || v.bio.lastSub != subEnrollCancel {
		t.Errorf("no cancel was sent: last subcommand %d", v.bio.lastSub)
	}

	// A call failing midway (the token vanishes).
	v, _, b, tok = bioKey(t, "bioEnroll")
	_, err = b.Enroll(context.Background(), tok, 0, func(EnrollStep) { v.token = nil })
	var se *StatusError
	if !errors.As(err, &se) || v.bio.enrolling != nil || v.bio.lastSub != subEnrollCancel {
		t.Errorf("mid-way failure: %v enrolling=%v last=%d", err, v.bio.enrolling, v.bio.lastSub)
	}

	// A key that never says it is done.
	v, _, b, tok = bioKey(t, "bioEnroll")
	v.bio.script = make([]SampleStatus, 1000)
	for i := range v.bio.script {
		v.bio.script[i] = SampleTooFast
	}
	if _, err = b.Enroll(context.Background(), tok, 0, nil); err == nil || !strings.Contains(err.Error(), "256 rounds") {
		t.Errorf("unbounded: %v", err)
	}
	if v.bio.enrolling != nil {
		t.Error("the endless enrollment was not cancelled")
	}
	// Begin failing leaves nothing to cancel.
	v.bio.capacity = 0
	if _, err = b.Enroll(context.Background(), tok, 0, nil); err == nil {
		t.Error("enroll on a full key")
	}
}

func TestBioNeedsACTAP2Key(t *testing.T) {
	k := ctap2Key(t, CapWink, func(byte, []byte) []byte { t.Error("asked"); return []byte{0} })
	b := &Bio{k: k, cmd: CmdBioEnrollment}
	if _, err := b.SensorInfo(context.Background()); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("%v", err)
	}
}

func TestSampleStatusesSayWhatToDo(t *testing.T) {
	for s := range sampleNames {
		if strings.HasPrefix(s.String(), "sample status") {
			t.Errorf("%d has no name", s)
		}
	}
	if got := SampleStatus(0x0C).String(); got != "sample status 0x0c" {
		t.Errorf("unused value: %q", got)
	}
}

func cborOf(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBioRepliesThatAreNotWhatTheyClaim(t *testing.T) {
	notMap := cborOf(t, "x")
	for name, f := range map[string]func([]byte) error{
		"sensor":  func(b []byte) error { _, err := parseSensorInfo(b); return err },
		"begin":   func(b []byte) error { _, err := parseEnrollStep(b, true); return err },
		"next":    func(b []byte) error { _, err := parseEnrollStep(b, false); return err },
		"listing": func(b []byte) error { _, err := parseEnrollments(b); return err },
	} {
		if f(notMap) == nil || f(nil) == nil {
			t.Errorf("%s: a non-map was accepted", name)
		}
	}
	sensor := func(m map[uint64]any) error { _, err := parseSensorInfo(cborOf(t, m)); return err }
	for name, m := range map[string]map[uint64]any{
		"no kind":       {brMaxSamples: 4},
		"kind 3":        {brKind: 3, brMaxSamples: 4},
		"no samples":    {brKind: 1},
		"name wrong":    {brKind: 1, brMaxSamples: 4, brMaxName: "x"},
		"negative":      {brKind: 1, brMaxSamples: -4},
		"negative name": {brKind: 1, brMaxSamples: 4, brMaxName: -1},
	} {
		if sensor(m) == nil {
			t.Errorf("sensor %s accepted", name)
		}
	}
	if err := sensor(map[uint64]any{brKind: 2, brMaxSamples: 6}); err != nil {
		t.Errorf("a swipe sensor without a name limit: %v", err)
	}
	step := func(m map[uint64]any, id bool) error { _, err := parseEnrollStep(cborOf(t, m), id); return err }
	for name, c := range map[string]struct {
		m  map[uint64]any
		id bool
	}{
		"begin without id":   {map[uint64]any{brLastStatus: 0, brRemaining: 3}, true},
		"begin empty id":     {map[uint64]any{brTemplateID: []byte{}, brLastStatus: 0, brRemaining: 3}, true},
		"no status":          {map[uint64]any{brRemaining: 3}, false},
		"no remaining":       {map[uint64]any{brLastStatus: 0}, false},
		"negative remaining": {map[uint64]any{brLastStatus: 0, brRemaining: -1}, false},
	} {
		if step(c.m, c.id) == nil {
			t.Errorf("step %s accepted", name)
		}
	}
	list := func(m map[uint64]any) error { _, err := parseEnrollments(cborOf(t, m)); return err }
	for name, m := range map[string]map[uint64]any{
		"no list":      {},
		"list is text": {brTemplateInfos: "x"},
		"no id":        {brTemplateInfos: []map[uint64]any{{bpName: "a"}}},
		"name is int":  {brTemplateInfos: []map[uint64]any{{bpTemplateID: []byte{1}, bpName: 7}}},
	} {
		if list(m) == nil {
			t.Errorf("list %s accepted", name)
		}
	}
	if err := list(map[uint64]any{brTemplateInfos: []map[uint64]any{}}); err != nil {
		t.Errorf("an empty list: %v", err)
	}
}
