// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"crypto/rand"
	"fmt"
)

// Transport carries CTAPHID reports to and from ONE authenticator.
//
// It is deliberately this small. Everything above it -- framing, the
// handshake, keepalives, the commands -- is the same on every operating
// system, so an implementation has only to move 64 bytes at a time and say
// what the device is called.
//
// Receive must return the NEXT report, blocking until one arrives, the context
// ends, or the device goes away. It must not drop reports between calls: a key
// answers a ping in under a millisecond, and an implementation that only
// listens while asked will miss it.
type Transport interface {
	// Send writes one report of exactly [ReportSize] bytes.
	Send(report []byte) error
	// Receive returns the next report.
	Receive(ctx context.Context) ([]byte, error)
	// Name is what the device calls itself, for error messages a person reads.
	Name() string
	// Close releases the device.
	Close() error
}

// randomNonce is a seam: a test drives the handshake without depending on what
// the machine's randomness happens to produce.
var randomNonce = func(b []byte) error { _, err := rand.Read(b); return err }

// Key is an authenticator with a negotiated channel.
type Key struct {
	t       Transport
	channel uint32
	version Version
	caps    Capabilities
}

// Name is what the key calls itself.
func (k *Key) Name() string { return k.t.Name() }

// Version is the key's firmware and transport version.
func (k *Key) Version() Version { return k.version }

// Capabilities is what the key said it can do.
func (k *Key) Capabilities() Capabilities { return k.caps }

// Channel is the negotiated channel id.
func (k *Key) Channel() uint32 { return k.channel }

// String renders the key the way a log reads.
func (k *Key) String() string {
	return fmt.Sprintf("%s (%s, %s) on channel %#08x", k.t.Name(), k.version, k.caps, k.channel)
}

// Close releases the transport.
func (k *Key) Close() error {
	if k.t == nil {
		return nil
	}
	t := k.t
	k.t = nil
	return t.Close()
}

// Open negotiates a channel on t and returns the key behind it.
//
// The handshake is not optional and is done here rather than left to the
// caller: every later message carries the channel id, so a Key without one
// could not be used for anything, and returning one would be handing back a
// half-built object to be misused.
//
// The Key takes ownership of t: [Key.Close] closes it, and so does a failed
// Open, so a caller never has to unwind a half-open device.
func Open(ctx context.Context, t Transport) (*Key, error) {
	k := &Key{t: t, channel: BroadcastChannel}
	var nonce [8]byte
	if err := randomNonce(nonce[:]); err != nil {
		k.Close()
		return nil, fmt.Errorf("fido: cannot make a nonce: %w", err)
	}
	reply, err := k.roundTrip(ctx, CmdInit, nonce[:])
	if err != nil {
		k.Close()
		return nil, err
	}
	init, err := ParseInit(reply)
	if err != nil {
		k.Close()
		return nil, fmt.Errorf("fido: the key's INIT reply was malformed: %w", err)
	}
	if init.Nonce != nonce {
		k.Close()
		return nil, fmt.Errorf("fido: the key answered another program's INIT (nonce %x, wanted %x)", init.Nonce, nonce)
	}
	k.channel, k.version, k.caps = init.Channel, init.Version, init.Caps
	return k, nil
}

// Ping sends data and returns what came back, which a working channel returns
// unchanged. It is how to check a key is still there without asking it to do
// anything.
func (k *Key) Ping(ctx context.Context, data []byte) ([]byte, error) {
	return k.roundTrip(ctx, CmdPing, data)
}

// Wink makes the key blink, when it said it can.
//
// It is the one thing here a PERSON can see, which is what makes it useful for
// more than diagnostics: asked to prove which key is which, or that the key is
// the one on the desk rather than one left in a hub across the room, a blink
// answers.
//
// A key without [CapWink] is not asked, because a key that does not wink
// answers CTAPHID_ERROR and the caller would have to tell that refusal from a
// real fault.
func (k *Key) Wink(ctx context.Context) error {
	if !k.caps.Has(CapWink) {
		return fmt.Errorf("fido: %s cannot wink", k.t.Name())
	}
	_, err := k.roundTrip(ctx, CmdWink, nil)
	return err
}

// roundTrip sends one message and waits for its reply.
func (k *Key) roundTrip(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	packets, err := Split(k.channel, cmd, data)
	if err != nil {
		return nil, err
	}
	for _, p := range packets {
		if err := k.t.Send(p); err != nil {
			return nil, fmt.Errorf("fido: cannot send to %s: %w", k.t.Name(), err)
		}
	}
	rc := NewReassembler(k.channel)
	for {
		report, err := k.t.Receive(ctx)
		if err != nil {
			return nil, fmt.Errorf("fido: %s did not answer: %w", k.t.Name(), err)
		}
		msg, done, err := rc.Feed(report)
		if err != nil {
			// A report for another channel is another program talking to the
			// same key. Waiting is right: ours is still coming. libfido2 skips
			// these in the same loop, for the same reason.
			if err == ErrWrongChannel {
				continue
			}
			return nil, err
		}
		if !done {
			continue
		}
		if msg.Cmd == CmdKeepalive {
			// The key is still working -- almost always waiting for a finger.
			// It sends one of these about every hundred milliseconds for as
			// long as the person takes. Returning it would hand the caller a
			// status byte where the answer goes.
			continue
		}
		if msg.IsError() {
			code := byte(0)
			if len(msg.Data) > 0 {
				code = msg.Data[0]
			}
			return nil, fmt.Errorf("fido: %s refused the request (CTAPHID error %#02x)", k.t.Name(), code)
		}
		return msg.Data, nil
	}
}
