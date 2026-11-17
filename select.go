// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// CmdSelection is authenticatorSelection (CTAP 2.1 6.9): the authenticator
// asks for user presence and answers CTAP2_OK when it gets it. It exists for
// exactly this, a platform choosing among several authenticators.
const CmdSelection byte = 0x0B

// ErrNoCandidates is returned by [Select] when it is given nothing to choose
// from.
var ErrNoCandidates = errors.New("fido: no security key to choose from")

// Candidate is a key that may be chosen: how to open it and what to call it.
//
// Open is a function rather than a device so that this package stays free of
// every operating system: go-macos/fido and go-gnulinux/fido list their keys
// and a caller turns each one into a Candidate with a closure over its
// OpenDevice.
type Candidate struct {
	// Label is how the key is named to a person, in messages.
	Label string
	// Open opens the key and does the CTAPHID handshake (see [Open]).
	Open func(context.Context) (*Key, error)
}

// CandidateError is one key's failure during [Select].
type CandidateError struct {
	// Index is the position in the list given to Select.
	Index int
	Label string
	Err   error
}

func (e CandidateError) Error() string { return fmt.Sprintf("%s: %v", e.Label, e.Err) }
func (e CandidateError) Unwrap() error { return e.Err }

// SelectError is what [Select] returns when no key was chosen. Every key's own
// failure is listed: none is swallowed, so "nothing was touched in time" can be
// told from "one key would not open".
type SelectError struct {
	// Cause is the context's error when the wait ran out or was cancelled, nil
	// when every key failed on its own.
	Cause    error
	Failures []CandidateError
}

func (e *SelectError) Error() string {
	var parts []string
	for _, f := range e.Failures {
		parts = append(parts, f.Error())
	}
	head := "fido: no key was chosen"
	if e.Cause != nil {
		head = fmt.Sprintf("fido: no key was touched (%v)", e.Cause)
	}
	if len(parts) == 0 {
		return head
	}
	return head + ": " + strings.Join(parts, "; ")
}

// Unwrap exposes the cause and every key's error to errors.Is and errors.As.
func (e *SelectError) Unwrap() []error {
	var out []error
	if e.Cause != nil {
		out = append(out, e.Cause)
	}
	for _, f := range e.Failures {
		out = append(out, f)
	}
	return out
}

// Selected is the key a person chose by touching it.
type Selected struct {
	// Index is its position in the list given to [Select].
	Index int
	Label string
	// Key is open and ready. The caller closes it; every other key was
	// cancelled and closed.
	Key  *Key
	Info Info
	// AlsoTouched lists the labels of OTHER keys that were touched in the same
	// instant, before they could be cancelled. When it is not empty the choice
	// is ambiguous, and a caller about to change something must not proceed on
	// it.
	AlsoTouched []string
	// Failures are the keys that could not be asked at all (unplugged while
	// waiting, would not open), reported alongside the winner.
	Failures []CandidateError
}

// Cancel sends CTAPHID_CANCEL (CTAP 2.1 11.2.9.1.6): the key abandons whatever
// it is waiting for, answering the pending request with
// CTAP2_ERR_KEEPALIVE_CANCEL. It sends only; the answer, if anyone waits for
// one, arrives through the request that was pending.
func (k *Key) Cancel() error {
	packets, _ := Split(k.channel, CmdCancel, nil) // an empty message always splits
	for _, p := range packets {
		if err := k.t.Send(p); err != nil {
			return fmt.Errorf("fido: cannot cancel on %s: %w", k.t.Name(), err)
		}
	}
	return nil
}

// touchStatuses are the answers of the makeCredential probe that mean "the key
// was touched": it checks user presence BEFORE it checks the (deliberately
// empty) pinUvAuthParam, so these are what a touched key says.
var touchStatuses = []Status{StatusPINAuthInvalid, StatusPINInvalid, 0x35}

type outcome struct {
	i       int
	key     *Key
	info    Info
	touched bool
	err     error
}

// Select asks every candidate for a touch at once and returns the first one
// touched. The others are sent CTAPHID_CANCEL and closed before Select returns.
//
// Each key is opened and asked, in parallel, to wait for the person:
// authenticatorSelection (CTAP 2.1 6.9) when it speaks FIDO_2_1, and otherwise,
// as libfido2's touch.c does for 2.0 keys, a makeCredential whose
// pinUvAuthParam is empty. A key with neither (a 2.0 key with no PIN set up)
// cannot be selected without making a credential on it, so it is reported as
// an error rather than asked.
//
// The wait is bounded by ctx: give it a timeout. A person who explicitly
// refuses on one key (CTAP2_ERR_OPERATION_DENIED) makes that key an error, as
// 6.9 says not to ask it again.
func Select(ctx context.Context, cands []Candidate) (*Selected, error) {
	if len(cands) == 0 {
		return nil, ErrNoCandidates
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan outcome, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- askToTouch(ctx, i, c)
		}()
	}

	// Outcomes in the order they arrive: the first touched key is the winner,
	// and the others are told at once so a key still waiting stops blinking.
	outs := make([]outcome, 0, len(cands))
	for range cands {
		o := <-results
		outs = append(outs, o)
		if o.err == nil && o.touched {
			cancel()
		}
	}
	wg.Wait()
	return settle(cands, outs, ctx.Err())
}

// settle turns the outcomes, in arrival order, into the answer. It is separate
// from Select so the cases that depend on timing (two keys touched together,
// a failure beside a winner) are tested with the outcomes written out.
func settle(cands []Candidate, outs []outcome, ctxErr error) (*Selected, error) {
	var winner *outcome
	var failures []CandidateError
	var also []string
	for _, o := range outs {
		switch {
		case o.err != nil:
			failures = append(failures, CandidateError{Index: o.i, Label: cands[o.i].Label, Err: o.err})
		case o.touched && winner == nil:
			w := o
			winner = &w
		default:
			if o.touched {
				also = append(also, cands[o.i].Label)
			}
			if o.key != nil {
				o.key.Close()
			}
		}
	}
	slices.SortFunc(failures, func(a, b CandidateError) int { return a.Index - b.Index })
	if winner == nil {
		return nil, &SelectError{Failures: failures, Cause: ctxErr}
	}
	return &Selected{
		Index: winner.i, Label: cands[winner.i].Label, Key: winner.key, Info: winner.info,
		AlsoTouched: also, Failures: failures,
	}, nil
}

// askToTouch opens one key and waits for its person. A key that is not
// touched is cancelled and closed here; a touched one is returned open.
func askToTouch(ctx context.Context, i int, c Candidate) (o outcome) {
	o.i = i
	k, err := c.Open(ctx)
	if err != nil {
		o.err = err
		return o
	}
	defer func() {
		// Anything but a touched key is released, cancelling what it waits for.
		if o.key == nil {
			_ = k.Cancel()
			k.Close()
		}
	}()
	info, err := k.GetInfo(ctx)
	touched := false
	if err == nil {
		touched, err = waitForTouch(ctx, k, info)
	}
	switch {
	case err != nil && ctx.Err() != nil && isCancellation(ctx, err):
		// Cancelled because another key won, or the wait ran out: not a failure
		// of this key. (A real answer from the key, such as a refusal, still is.)
		return o
	case err != nil:
		o.err = err
		return o
	}
	o.key, o.info, o.touched = k, info, touched
	return o
}

// isCancellation reports whether err is only the effect of ctx ending: the wait
// itself was abandoned, or the key answered CTAP2_ERR_KEEPALIVE_CANCEL (0x2D)
// to the CTAPHID_CANCEL.
func isCancellation(ctx context.Context, err error) bool {
	var se *StatusError
	return errors.Is(err, ctx.Err()) || (errors.As(err, &se) && se.Status == 0x2D)
}

// waitForTouch sends the touch request and waits for its answer.
func waitForTouch(ctx context.Context, k *Key, info Info) (bool, error) {
	if slices.Contains(info.Versions, "FIDO_2_1") {
		if _, err := k.CBOR(ctx, CmdSelection, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	if _, hasPIN := info.Options["clientPin"]; !hasPIN {
		return false, fmt.Errorf("fido: %s speaks neither authenticatorSelection nor takes a PIN, so it cannot be chosen by touch without making a credential on it", k.Name())
	}
	// makeCredential, with dummy parameters and an EMPTY pinUvAuthParam (key
	// 0x08) under protocol 1 (key 0x09): the key waits for user presence and
	// then refuses the empty parameter. Which status it refuses with is not
	// the point; that it got as far as checking is.
	_, err := k.cborCall(ctx, CmdMakeCredential, map[int]any{
		1: make([]byte, 32),
		2: map[string]any{"id": "selection.invalid", "name": "selection"},
		3: map[string]any{"id": []byte{1}, "name": "selection"},
		4: []map[string]any{{"alg": -7, "type": "public-key"}},
		8: []byte{},
		9: int(PINProtocolOne),
	})
	if err == nil {
		return true, nil // it made a credential after all; it was touched
	}
	var se *StatusError
	if errors.As(err, &se) && slices.Contains(touchStatuses, se.Status) {
		return true, nil
	}
	return false, err
}

// Identity is what a key says about itself without being touched, to tell
// several apart on a screen.
type Identity struct {
	// Name is what the transport calls the key.
	Name string
	// AAGUID identifies the MODEL, not the individual key.
	AAGUID   [16]byte
	Versions []string
	// PINSet is true when a PIN is set; PINCapable when the key has one to set.
	PINSet, PINCapable bool
	// ForcePINChange is true when the PIN must be changed before use.
	ForcePINChange bool
	// FingerprintCapable is true for a key that declares bio enrollment;
	// FingerprintsEnrolled is true when at least one fingerprint is enrolled
	// (the bioEnroll option's value, CTAP 2.1 6.4).
	FingerprintCapable, FingerprintsEnrolled bool
}

// String renders the identity on one line.
func (i Identity) String() string {
	pin := "no PIN capability"
	switch {
	case i.PINSet:
		pin = "PIN set"
	case i.PINCapable:
		pin = "no PIN yet"
	}
	fp := "no fingerprint sensor"
	switch {
	case i.FingerprintsEnrolled:
		fp = "fingerprints enrolled"
	case i.FingerprintCapable:
		fp = "no fingerprint enrolled"
	}
	return fmt.Sprintf("%s, aaguid %x, %s, %s", i.Name, i.AAGUID, pin, fp)
}

// Identity reads the key's description with getInfo. It needs no touch and no
// PIN.
func (k *Key) Identity(ctx context.Context) (Identity, error) {
	info, err := k.GetInfo(ctx)
	if err != nil {
		return Identity{}, err
	}
	return identityOf(k.Name(), info), nil
}

func identityOf(name string, info Info) Identity {
	_, capable := info.Options["clientPin"]
	return Identity{
		Name: name, AAGUID: info.AAGUID, Versions: info.Versions,
		PINSet: info.Has("clientPin"), PINCapable: capable, ForcePINChange: info.ForcePINChange,
		FingerprintCapable:   info.BioMode() != BioUnsupported,
		FingerprintsEnrolled: info.Has("bioEnroll") || info.Has("userVerificationMgmtPreview"),
	}
}
