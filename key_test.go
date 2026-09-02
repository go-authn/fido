// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeTransport is a key that answers. Faking one is the point of the
// Transport interface: every branch below runs on any machine, with no
// hardware and no operating system in the way.
type fakeTransport struct {
	name     string
	sendErr  error
	recvErr  error
	sent     [][]byte
	inbox    [][]byte
	reply    func(sent []byte) [][]byte
	closed   int
	blockAll bool
}

func (f *fakeTransport) Name() string { return f.name }
func (f *fakeTransport) Close() error { f.closed++; return nil }

func (f *fakeTransport) Send(report []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, append([]byte(nil), report...))
	if f.reply != nil {
		f.inbox = append(f.inbox, f.reply(report)...)
	}
	return nil
}

func (f *fakeTransport) Receive(ctx context.Context) ([]byte, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	if f.blockAll || len(f.inbox) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := f.inbox[0]
	f.inbox = f.inbox[1:]
	return r, nil
}

// withNonce makes the handshake deterministic.
func withNonce(t *testing.T) [8]byte {
	t.Helper()
	old := randomNonce
	t.Cleanup(func() { randomNonce = old })
	var want [8]byte
	for i := range want {
		want[i] = byte(0xA0 + i)
	}
	randomNonce = func(b []byte) error { copy(b, want[:]); return nil }
	return want
}

func initReply(nonce [8]byte, channel uint32, caps byte) []byte {
	payload := make([]byte, 17)
	copy(payload, nonce[:])
	binary.BigEndian.PutUint32(payload[8:12], channel)
	payload[12], payload[13], payload[14], payload[15] = 2, 5, 7, 4
	payload[16] = caps
	pkts, _ := Split(BroadcastChannel, CmdInit, payload)
	return pkts[0]
}

// answering is a transport that behaves: it handshakes, echoes pings and
// acknowledges winks.
//
// It REASSEMBLES what it is sent before answering. An earlier version read
// every report as though it began a message, which works only while every
// question fits in one -- and then panics on the first that does not.
func answering(nonce [8]byte, channel uint32, caps byte) *fakeTransport {
	f := &fakeTransport{name: "Test Key"}
	bcast := NewReassembler(BroadcastChannel)
	own := NewReassembler(channel)
	f.reply = func(sent []byte) [][]byte {
		var msg Message
		var done bool
		if ch := binary.BigEndian.Uint32(sent[0:4]); ch == BroadcastChannel {
			msg, done, _ = bcast.Feed(sent)
		} else {
			msg, done, _ = own.Feed(sent)
		}
		if !done {
			return nil
		}
		switch msg.Cmd {
		case CmdInit:
			return [][]byte{initReply(nonce, channel, caps)}
		case CmdPing:
			p, _ := Split(channel, CmdPing, msg.Data)
			return p
		case CmdWink:
			p, _ := Split(channel, CmdWink, nil)
			return p
		}
		return nil
	}
	return f
}

func TestOpenHandshakesAndAnswers(t *testing.T) {
	nonce := withNonce(t)
	f := answering(nonce, 0x33445566, byte(CapWink|CapCBOR))
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()

	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if k.Channel() != 0x33445566 {
		t.Errorf("channel %#08x", k.Channel())
	}
	if v := k.Version(); v.CTAPHID != 2 || v.Major != 5 || v.Minor != 7 || v.Build != 4 {
		t.Errorf("version %v", v)
	}
	if !k.Capabilities().Has(CapCBOR) {
		t.Error("the capabilities did not survive the handshake")
	}
	if k.Name() != "Test Key" || !strings.Contains(k.String(), "5.7.4") {
		t.Errorf("String() = %q", k.String())
	}
	msg := []byte("multi-factor")
	echo, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Errorf("the key echoed %q", echo)
	}
	if err := k.Wink(ctx); err != nil {
		t.Errorf("Wink: %v", err)
	}
	if err := k.Close(); err != nil || f.closed != 1 {
		t.Errorf("Close = %v, transport closed %d time(s)", err, f.closed)
	}
	if err := k.Close(); err != nil || f.closed != 1 {
		t.Errorf("Close twice closed the transport %d time(s)", f.closed)
	}
}

// TestOpenClosesTheTransportWhenItFails: a caller that gets an error back has
// nothing to close, so Open must not leave a device open behind it.
func TestOpenClosesTheTransportWhenItFails(t *testing.T) {
	nonce := withNonce(t)
	cases := []struct {
		name string
		make func() *fakeTransport
		want string
	}{
		{"the key cannot be written to", func() *fakeTransport {
			return &fakeTransport{name: "K", sendErr: errors.New("gone")}
		}, "cannot send"},
		{"the key says nothing", func() *fakeTransport {
			return &fakeTransport{name: "K", blockAll: true}
		}, "did not answer"},
		{"the reply is malformed", func() *fakeTransport {
			f := &fakeTransport{name: "K"}
			f.reply = func([]byte) [][]byte {
				p, _ := Split(BroadcastChannel, CmdInit, make([]byte, 4))
				return [][]byte{p[0]}
			}
			return f
		}, "malformed"},
		{"the reply is another program's", func() *fakeTransport {
			f := &fakeTransport{name: "K"}
			f.reply = func([]byte) [][]byte {
				r := initReply(nonce, 0x1, 0x05)
				r[7] ^= 0xFF
				return [][]byte{r}
			}
			return f
		}, "nonce"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.make()
			ctx, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer stop()
			if _, err := Open(ctx, f); err == nil {
				t.Fatal("Open succeeded")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
			if f.closed != 1 {
				t.Errorf("the transport was closed %d time(s), want once", f.closed)
			}
		})
	}
}

func TestOpenWithNoRandomness(t *testing.T) {
	old := randomNonce
	t.Cleanup(func() { randomNonce = old })
	randomNonce = func([]byte) error { return errors.New("dry") }
	f := &fakeTransport{name: "K"}
	if _, err := Open(context.Background(), f); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Errorf("Open with no randomness = %v", err)
	}
	if f.closed != 1 {
		t.Error("the transport was left open")
	}
}

// TestKeepalivesAreNotAnswers is the case that breaks everything needing a
// finger: a key waiting to be touched sends CTAPHID_KEEPALIVE about every
// hundred milliseconds, and a reader that returns the first complete message
// hands back a status byte instead of the reply -- early, so it reads as the
// key talking nonsense rather than as a missing feature.
func TestKeepalivesAreNotAnswers(t *testing.T) {
	nonce := withNonce(t)
	const ch = 0x5150
	f := answering(nonce, ch, byte(CapWink|CapCBOR))
	inner := f.reply
	f.reply = func(sent []byte) [][]byte {
		if (sent[4] &^ 0x80) == CmdPing {
			var out [][]byte
			for i := 0; i < 3; i++ {
				p, _ := Split(ch, CmdKeepalive, []byte{0x02}) // 2 = waiting for the user
				out = append(out, p[0])
			}
			n := binary.BigEndian.Uint16(sent[5:7])
			echo, _ := Split(ch, CmdPing, sent[7:7+n])
			return append(out, echo...)
		}
		return inner(sent)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	msg := []byte("touch me")
	got, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping through keepalives: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("got %q, want %q -- a keepalive was returned as the answer", got, msg)
	}
}

// TestAnotherProgramsTrafficIsWaitedThrough: two programs on one key is a real
// situation, and the other one's reports must not end the wait.
func TestAnotherProgramsTrafficIsWaitedThrough(t *testing.T) {
	nonce := withNonce(t)
	const ch = 0x6161
	f := answering(nonce, ch, byte(CapWink|CapCBOR))
	inner := f.reply
	f.reply = func(sent []byte) [][]byte {
		if (sent[4] &^ 0x80) == CmdPing {
			other, _ := Split(0xABCD, CmdPing, []byte("not ours"))
			n := binary.BigEndian.Uint16(sent[5:7])
			mine, _ := Split(ch, CmdPing, sent[7:7+n])
			return append(other, mine...)
		}
		return inner(sent)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	got, err := k.Ping(ctx, []byte("mine"))
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if string(got) != "mine" {
		t.Errorf("got %q -- another channel's report was taken as the answer", got)
	}
}

func TestARefusalIsReportedWithItsCode(t *testing.T) {
	nonce := withNonce(t)
	const ch = 0x7
	f := answering(nonce, ch, byte(CapWink|CapCBOR))
	inner := f.reply
	f.reply = func(sent []byte) [][]byte {
		if (sent[4] &^ 0x80) == CmdPing {
			p, _ := Split(ch, CmdError, []byte{0x06})
			return p
		}
		return inner(sent)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	_, err = k.Ping(ctx, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "0x06") {
		t.Errorf("a CTAPHID_ERROR reply = %v", err)
	}
}

func TestAKeyThatCannotWinkIsNotAsked(t *testing.T) {
	nonce := withNonce(t)
	f := answering(nonce, 0x1, byte(CapCBOR|CapNoMsg))
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	before := len(f.sent)
	if err := k.Wink(ctx); err == nil || !strings.Contains(err.Error(), "cannot wink") {
		t.Errorf("Wink without the capability = %v", err)
	}
	if len(f.sent) != before {
		t.Error("a key that cannot wink was asked to anyway")
	}
}

func TestPingRefusesAMessageTooLong(t *testing.T) {
	nonce := withNonce(t)
	f := answering(nonce, 0xb, byte(CapWink|CapCBOR))
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	if _, err := k.Ping(ctx, make([]byte, MaxMessage+1)); !errors.Is(err, ErrTooLong) {
		t.Errorf("Ping of an over-long message = %v, want ErrTooLong", err)
	}
}

func TestAReceiveThatFails(t *testing.T) {
	nonce := withNonce(t)
	f := answering(nonce, 0xc, byte(CapWink|CapCBOR))
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	f.recvErr = errors.New("unplugged")
	if _, err := k.Ping(ctx, []byte("x")); err == nil || !strings.Contains(err.Error(), "unplugged") {
		t.Errorf("a transport that fails to read = %v", err)
	}
}

// TestAMalformedReportEndsTheWait: a short report is not somebody else's
// traffic, it is a fault, and waiting for a reply that will never be
// well-formed would hang until the context ended.
func TestAMalformedReportEndsTheWait(t *testing.T) {
	nonce := withNonce(t)
	const ch = 0xd
	f := answering(nonce, ch, byte(CapWink|CapCBOR))
	inner := f.reply
	f.reply = func(sent []byte) [][]byte {
		if (sent[4] &^ 0x80) == CmdPing {
			return [][]byte{make([]byte, 3)}
		}
		return inner(sent)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	if _, err := k.Ping(ctx, []byte("x")); !errors.Is(err, ErrShortPacket) {
		t.Errorf("a 3-byte report = %v, want ErrShortPacket", err)
	}
}

func TestAKeyWithNoTransportClosesQuietly(t *testing.T) {
	var k Key
	if err := k.Close(); err != nil {
		t.Errorf("Close on an empty Key = %v", err)
	}
}

// TestAReplyInSeveralPackets exercises reassembly through the real path. A
// short ping fits in one report and proves nothing about the continuation
// packets, which is where the sequence numbering can be wrong.
func TestAReplyInSeveralPackets(t *testing.T) {
	nonce := withNonce(t)
	f := answering(nonce, 0xe, byte(CapWink|CapCBOR))
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()

	// Long enough to need three reports, with a pattern that would survive a
	// reordering only by luck.
	msg := make([]byte, initPayload+contPayload+10)
	for i := range msg {
		msg[i] = byte(i*31 + 7)
	}
	got, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("a %d-byte echo came back as %d bytes", len(msg), len(got))
	}
	// And the question went out in three reports too, so both directions are
	// covered by this one exchange.
	if n := len(f.sent); n < 4 {
		t.Errorf("%d reports sent in total, want the handshake plus three", n)
	}
}
