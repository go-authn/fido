// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestSplitFitsAMessageInOnePacket(t *testing.T) {
	data := []byte("go-macos/fido")
	pkts, err := Split(0x11223344, CmdPing, data)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("%d packet(s) for %d bytes, want 1", len(pkts), len(data))
	}
	p := pkts[0]
	if len(p) != ReportSize {
		t.Errorf("packet is %d bytes, want a whole %d-byte report", len(p), ReportSize)
	}
	if got := binary.BigEndian.Uint32(p[0:4]); got != 0x11223344 {
		t.Errorf("channel %#08x", got)
	}
	if p[4] != 0x80|CmdPing {
		t.Errorf("command byte %#02x, want the high bit set on %#02x", p[4], CmdPing)
	}
	if got := binary.BigEndian.Uint16(p[5:7]); int(got) != len(data) {
		t.Errorf("length field %d, want %d", got, len(data))
	}
	if !bytes.Equal(p[7:7+len(data)], data) {
		t.Error("the payload is not where the specification puts it")
	}
	for _, b := range p[7+len(data):] {
		if b != 0 {
			t.Error("the packet is not zero-padded, so a key reading the whole report reads rubbish")
			break
		}
	}
}

func TestSplitAndReassembleAreInverses(t *testing.T) {
	// Sizes that straddle every boundary: empty, one short of the first
	// packet, exactly full, one over, and several continuations deep.
	for _, n := range []int{0, 1, initPayload - 1, initPayload, initPayload + 1,
		initPayload + contPayload, initPayload + contPayload + 1, 1000} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 7)
		}
		pkts, err := Split(0xdeadbeef, CmdPing, data)
		if err != nil {
			t.Fatalf("%d bytes: Split: %v", n, err)
		}
		rc := NewReassembler(0xdeadbeef)
		var got Message
		done := false
		for i, p := range pkts {
			if len(p) != ReportSize {
				t.Fatalf("%d bytes: packet %d is %d bytes", n, i, len(p))
			}
			var err error
			got, done, err = rc.Feed(p)
			if err != nil {
				t.Fatalf("%d bytes: packet %d: %v", n, i, err)
			}
			if done != (i == len(pkts)-1) {
				t.Fatalf("%d bytes: complete after packet %d of %d", n, i+1, len(pkts))
			}
		}
		if !done {
			t.Fatalf("%d bytes: never completed", n)
		}
		if !bytes.Equal(got.Data, data) {
			t.Errorf("%d bytes: came back as %d", n, len(got.Data))
		}
		if got.Cmd != CmdPing || got.Channel != 0xdeadbeef {
			t.Errorf("%d bytes: came back as %v", n, got)
		}
	}
}

func TestSplitRefusesAMessageTooLong(t *testing.T) {
	if _, err := Split(1, CmdPing, make([]byte, MaxMessage+1)); !errors.Is(err, ErrTooLong) {
		t.Errorf("Split of an over-long message = %v, want ErrTooLong", err)
	}
	// The positive control: one byte less is accepted, so the refusal is about
	// the length and not about the function.
	if _, err := Split(1, CmdPing, make([]byte, MaxMessage)); err != nil {
		t.Errorf("Split of the largest legal message: %v", err)
	}
}

func TestReassemblerRefusesWhatIsNotItsTraffic(t *testing.T) {
	rc := NewReassembler(0x1000)
	short := make([]byte, 4)
	if _, _, err := rc.Feed(short); !errors.Is(err, ErrShortPacket) {
		t.Errorf("a 4-byte report = %v, want ErrShortPacket", err)
	}
	other, _ := Split(0x2000, CmdPing, []byte("x"))
	if _, _, err := rc.Feed(other[0]); !errors.Is(err, ErrWrongChannel) {
		t.Errorf("another channel's report = %v, want ErrWrongChannel", err)
	}
	// A continuation with nothing started.
	cont := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(cont[0:4], 0x1000)
	cont[4] = 0
	if _, _, err := rc.Feed(cont); !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("a continuation with no message started = %v, want ErrOutOfOrder", err)
	}
	// An initialisation packet too short to hold its own length field.
	tiny := make([]byte, 6)
	binary.BigEndian.PutUint32(tiny[0:4], 0x1000)
	tiny[4] = 0x80 | CmdPing
	if _, _, err := rc.Feed(tiny); !errors.Is(err, ErrShortPacket) {
		t.Errorf("a truncated init packet = %v, want ErrShortPacket", err)
	}
	// And a continuation out of sequence.
	big := make([]byte, initPayload+contPayload)
	pkts, _ := Split(0x1000, CmdPing, big)
	if _, _, err := rc.Feed(pkts[0]); err != nil {
		t.Fatalf("the first packet was refused: %v", err)
	}
	pkts[1][4] = 3 // should be 0
	if _, _, err := rc.Feed(pkts[1]); !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("a continuation numbered 3 where 0 was due = %v, want ErrOutOfOrder", err)
	}
}

func TestCapabilitiesReadAsTheSpecificationWritesThem(t *testing.T) {
	// 0x05 is what a YubiKey FIDO 5.7.4 really answered: wink and CBOR set,
	// NMSG clear, which means it speaks CTAP2 AND the older CTAP1.
	c := Capabilities(0x05)
	if !c.Has(CapWink) || !c.Has(CapCBOR) {
		t.Error("0x05 should carry wink and CBOR")
	}
	if c.Has(CapNoMsg) {
		t.Error("0x05 has NMSG clear, so CTAP1 is supported")
	}
	got := c.String()
	for _, want := range []string{"wink", "ctap2", "ctap1"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not mention %q", got, want)
		}
	}
	// A key that speaks only CTAP2 says so by SETTING the no-message bit.
	if got := Capabilities(CapCBOR | CapNoMsg).String(); strings.Contains(got, "ctap1") {
		t.Errorf("%q claims CTAP1 with the NMSG bit set", got)
	}
	// A capability byte of ZERO is not a key that does nothing: NMSG is an
	// ABSENCE, so 0x00 means "CTAP1 only, no wink, no CBOR". Reading it as
	// nothing would refuse a perfectly ordinary U2F key.
	if got := Capabilities(0).String(); got != "ctap1" {
		t.Errorf("capabilities 0x00 render as %q, want ctap1 -- NMSG is an absence", got)
	}
	// A key that claims NO protocol at all is representable, and says so.
	if got := Capabilities(CapNoMsg).String(); !strings.Contains(got, "none") {
		t.Errorf("a key claiming no protocol renders as %q", got)
	}
}

func TestParseInitReadsARealReply(t *testing.T) {
	// The bytes a YubiKey FIDO really sent on 2026-09-02, payload only.
	raw := []byte{
		0x6e, 0x97, 0x34, 0xcc, 0x1c, 0x04, 0x7e, 0x71, // nonce
		0x76, 0x5e, 0x8a, 0x9d, // channel
		0x02,             // CTAPHID version
		0x05, 0x07, 0x04, // firmware 5.7.4
		0x05, // capabilities
	}
	r, err := ParseInit(raw)
	if err != nil {
		t.Fatalf("ParseInit: %v", err)
	}
	if r.Channel != 0x765e8a9d {
		t.Errorf("channel %#08x", r.Channel)
	}
	if r.Version.CTAPHID != 2 || r.Version.Major != 5 || r.Version.Minor != 7 || r.Version.Build != 4 {
		t.Errorf("version %v, want CTAPHID v2 firmware 5.7.4", r.Version)
	}
	if !r.Caps.Has(CapCBOR) {
		t.Error("this key speaks CTAP2 and the parse says otherwise")
	}
	if _, err := ParseInit(raw[:16]); !errors.Is(err, ErrTruncated) {
		t.Errorf("a reply one byte short = %v, want ErrTruncated", err)
	}
}

func TestMessageRendersAndReportsRefusal(t *testing.T) {
	if !(Message{Cmd: CmdError}).IsError() {
		t.Error("a CTAPHID_ERROR message does not report itself as one")
	}
	if (Message{Cmd: CmdPing}).IsError() {
		t.Error("a ping reports itself as an error")
	}
	if got := (Message{Channel: 0x1234, Cmd: CmdPing, Data: []byte("ab")}).String(); !strings.Contains(got, "0x00001234") || !strings.Contains(got, "2 byte") {
		t.Errorf("String() = %q", got)
	}
	if got := (Version{CTAPHID: 2, Major: 5, Minor: 7, Build: 4}).String(); !strings.Contains(got, "5.7.4") {
		t.Errorf("Version.String() = %q", got)
	}
}

// TestTheMessageLimitIsTheFramingsNotTheLengthFields. The two length bytes
// would allow 65535 and an earlier version of this package used that, with a
// comment asserting the framing reached it. It does not: past 7609 bytes the
// sequence numbers run into the high bit, which a key reads as the start of a
// new message.
func TestTheMessageLimitIsTheFramingsNotTheLengthFields(t *testing.T) {
	if MaxMessage >= 0xFFFF {
		t.Fatalf("MaxMessage is %d, which is the length field's limit and not the framing's", MaxMessage)
	}
	pkts, err := Split(1, CmdPing, make([]byte, MaxMessage))
	if err != nil {
		t.Fatalf("the largest legal message was refused: %v", err)
	}
	if len(pkts) != 1+MaxContinuations {
		t.Errorf("%d packets, want one init and %d continuations", len(pkts), MaxContinuations)
	}
	for i, p := range pkts[1:] {
		if p[4]&0x80 != 0 {
			t.Fatalf("continuation %d is numbered %#02x, which a key reads as a command", i, p[4])
		}
		if int(p[4]) != i {
			t.Fatalf("continuation %d is numbered %d", i, p[4])
		}
	}
	if _, err := Split(1, CmdPing, make([]byte, MaxMessage+1)); !errors.Is(err, ErrTooLong) {
		t.Error("one byte past the limit was accepted")
	}
}
