// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package fido speaks the FIDO client-to-authenticator protocol to a security
// key, in pure Go with CGO_ENABLED=0 and on any operating system.
//
// Nothing here is platform-specific. A [Transport] carries 64-byte reports to
// and from one authenticator, and where those reports come from -- IOKit on
// macOS, hidraw on Linux, WebHID in a browser -- is somebody else's problem.
// See go-macos/fido for the macOS one.
//
// # The second factor
//
// An operating system already offers the first factor: Touch ID, a watch, a
// passcode. Those answer one question -- is the person at this machine the one
// who unlocked it? A security key answers a different one: is the thing they
// carry present, right now, and did a human touch it? Multi-factor means asking
// both, and getting two independent answers.
//
// # CTAPHID
//
// A message is cut into 64-byte reports: one INITIALISATION packet carrying the
// command and the total length, then CONTINUATION packets numbered from zero. A
// channel id is negotiated first, with [CmdInit], and every later message
// carries it.
//
// Yubico's libfido2 and the CTAP specification were read as documentation for
// this, and the reading caught two faults that testing against a key would not
// have: see [CmdKeepalive] and [MaxMessage].
package fido

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ReportSize is the size of every CTAPHID report, in bytes. The specification
// fixes it at 64 and every authenticator observed publishes exactly that in
// both directions.
const ReportSize = 64

// BroadcastChannel is the channel a key is addressed on before it has given
// one out. Only [CmdInit] may be sent there.
const BroadcastChannel uint32 = 0xFFFFFFFF

// The CTAPHID commands used here. The command byte travels with its high bit
// set, which is what distinguishes an initialisation packet from a
// continuation one -- a continuation packet carries a sequence number in the
// same position, and sequence numbers never reach 0x80.
const (
	// CmdPing echoes its payload back. It is the honest way to check that a
	// channel works, because a key that answers a ping with the same bytes has
	// received, framed and returned them.
	CmdPing byte = 0x01
	// CmdInit negotiates a channel. Sent on [BroadcastChannel] with an
	// eight-byte nonce, it comes back with that nonce, a fresh channel id, and
	// what the key can do.
	CmdInit byte = 0x06
	// CmdWink makes the key blink or flash. It changes nothing and stores
	// nothing, and it is the cheapest way to ask a person WHICH of the keys in
	// front of them is this one.
	CmdWink byte = 0x08
	// CmdCBOR carries a CTAP2 message. Not used yet; named so the capability
	// below is not a number without a meaning.
	CmdCBOR byte = 0x10
	// CmdMsg carries an older CTAP1/U2F message.
	CmdMsg byte = 0x03
	// CmdLock reserves the key for one channel. Optional, and not used here.
	CmdLock byte = 0x04
	// CmdCancel abandons a request the key is still working on -- which for
	// anything needing a touch means the person never touched it.
	CmdCancel byte = 0x11
	// CmdKeepalive is what a key sends WHILE it works, and it is not an answer.
	// A key waiting for a finger sends one about every hundred milliseconds for
	// as long as the person takes, and a reader that returns the first complete
	// message it sees returns THAT instead of the reply. libfido2 skips them in
	// its receive loop and keeps waiting; so does this.
	CmdKeepalive byte = 0x3B
	// CmdError is what a key answers with when it will not do something.
	CmdError byte = 0x3F
)

// initPayload is how many bytes of a message fit in its initialisation packet:
// the report minus the channel, the command and the two length bytes.
const initPayload = ReportSize - 7

// contPayload is how many fit in each continuation packet: the report minus the
// channel and the sequence number.
const contPayload = ReportSize - 5

// MaxContinuations is how many continuation packets one message may use. The
// sequence number shares its byte with the command, and a command is marked by
// its high bit, so a sequence number may never reach 0x80. libfido2 checks the
// same thing when it sends.
const MaxContinuations = 128

// MaxMessage is the largest message CTAPHID can actually carry.
//
// The two length bytes would allow 65535, and an earlier version of this file
// used that -- with a comment claiming the framing reached it. It does not:
// 57 bytes in the initialisation packet plus 128 continuations of 59 is 7609,
// and a longer message would need sequence numbers past 0x7F, which the key
// would read as initialisation packets. The arithmetic was wrong and the
// comment asserted it anyway.
const MaxMessage = initPayload + MaxContinuations*contPayload

// Errors this package returns for what a caller can act on.
var (
	// ErrNoKey means no FIDO authenticator is attached.
	ErrNoKey = errors.New("fido: no security key is attached")
	// ErrTooLong means the message will not fit in a CTAPHID transfer.
	ErrTooLong = errors.New("fido: the message is longer than CTAPHID can carry")
	// ErrShortPacket means a report arrived that is not a whole CTAPHID packet.
	ErrShortPacket = errors.New("fido: a report was shorter than a CTAPHID packet")
	// ErrWrongChannel means a report arrived for a different channel, which is
	// what happens when two programs talk to one key at once.
	ErrWrongChannel = errors.New("fido: the report belongs to another channel")
	// ErrOutOfOrder means continuation packets did not arrive in sequence.
	ErrOutOfOrder = errors.New("fido: a continuation packet arrived out of order")
	// ErrTruncated means the key stopped sending before the length it promised.
	ErrTruncated = errors.New("fido: the key sent less than it said it would")
)

// Split cuts a message into the reports that carry it: one initialisation
// packet then as many continuation packets as are needed, each exactly
// [ReportSize] bytes and zero-padded.
//
// Every packet is padded to the full report size deliberately. A short output
// report is legal HID and some keys accept it, but the specification says the
// transfer is report-sized and a key that reads past the bytes given would read
// whatever the previous transfer left there.
func Split(channel uint32, cmd byte, data []byte) ([][]byte, error) {
	if len(data) > MaxMessage {
		return nil, ErrTooLong
	}
	first := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(first[0:4], channel)
	first[4] = 0x80 | cmd
	binary.BigEndian.PutUint16(first[5:7], uint16(len(data)))
	n := copy(first[7:], data)
	out := [][]byte{first}
	for seq := 0; n < len(data); seq++ {
		p := make([]byte, ReportSize)
		binary.BigEndian.PutUint32(p[0:4], channel)
		p[4] = byte(seq)
		n += copy(p[5:], data[n:])
		out = append(out, p)
	}
	return out, nil
}

// Message is a CTAPHID message reassembled from its reports.
type Message struct {
	Channel uint32
	Cmd     byte
	Data    []byte
}

// IsError reports whether the key refused, rather than answered.
func (m Message) IsError() bool { return m.Cmd == CmdError }

// String renders the message the way a probe log reads.
func (m Message) String() string {
	return fmt.Sprintf("channel %#08x cmd %#02x, %d byte(s)", m.Channel, m.Cmd, len(m.Data))
}

// Reassembler puts a message back together from the reports a key sends.
//
// It is a type rather than a function because the reports arrive one at a time,
// from a callback, and the caller needs to know after each one whether the
// message is complete.
type Reassembler struct {
	channel uint32
	msg     Message
	want    int
	seq     int
	started bool
}

// NewReassembler collects reports for one channel, refusing any other.
func NewReassembler(channel uint32) *Reassembler {
	return &Reassembler{channel: channel}
}

// Feed takes one report. done is true when the message is whole, and the
// message is then returned and the reassembler is ready for the next one.
//
// A report for another channel is an error rather than something to ignore: two
// programs talking to one key is a real situation, and silently dropping the
// other one's traffic would leave a caller waiting for a reply that was already
// discarded.
func (r *Reassembler) Feed(report []byte) (msg Message, done bool, err error) {
	if len(report) < 5 {
		return Message{}, false, ErrShortPacket
	}
	ch := binary.BigEndian.Uint32(report[0:4])
	if ch != r.channel {
		return Message{}, false, ErrWrongChannel
	}
	if report[4]&0x80 != 0 {
		if len(report) < 7 {
			return Message{}, false, ErrShortPacket
		}
		r.msg = Message{Channel: ch, Cmd: report[4] &^ 0x80}
		r.want = int(binary.BigEndian.Uint16(report[5:7]))
		r.seq, r.started = 0, true
		r.msg.Data = append([]byte(nil), report[7:]...)
		return r.finish()
	}
	if !r.started {
		return Message{}, false, ErrOutOfOrder
	}
	if int(report[4]) != r.seq {
		return Message{}, false, ErrOutOfOrder
	}
	r.seq++
	r.msg.Data = append(r.msg.Data, report[5:]...)
	return r.finish()
}

// finish trims the padding once enough bytes have arrived.
func (r *Reassembler) finish() (Message, bool, error) {
	if len(r.msg.Data) < r.want {
		return Message{}, false, nil
	}
	m := r.msg
	m.Data = m.Data[:r.want]
	r.started = false
	return m, true, nil
}

// Capabilities is what a key said it can do, in the CTAPHID_INIT reply.
type Capabilities byte

// The capability bits.
const (
	// CapWink means [CmdWink] does something visible.
	CapWink Capabilities = 0x01
	// CapCBOR means the key speaks CTAP2.
	CapCBOR Capabilities = 0x04
	// CapNoMsg means the key does NOT speak the older CTAP1/U2F messages. It is
	// spelled as an absence in the specification, and kept that way here rather
	// than inverted, so a reader comparing this with the specification does not
	// have to hold two conventions at once.
	CapNoMsg Capabilities = 0x08
)

// Has reports whether every bit in c is set.
func (c Capabilities) Has(want Capabilities) bool { return c&want == want }

// String lists what the key can do, in the order the bits are defined.
func (c Capabilities) String() string {
	var out []byte
	add := func(s string) {
		if len(out) > 0 {
			out = append(out, ", "...)
		}
		out = append(out, s...)
	}
	if c.Has(CapWink) {
		add("wink")
	}
	if c.Has(CapCBOR) {
		add("ctap2")
	}
	if !c.Has(CapNoMsg) {
		add("ctap1")
	}
	if len(out) == 0 {
		return fmt.Sprintf("none (%#02x)", byte(c))
	}
	return string(out)
}

// Version is what a key answered about itself.
type Version struct {
	// CTAPHID is the transport protocol version, 2 on everything current.
	CTAPHID byte
	// Major, Minor and Build are the key's own firmware version.
	Major, Minor, Build byte
}

// String renders the version the way the manufacturer writes it.
func (v Version) String() string {
	return fmt.Sprintf("CTAPHID v%d, firmware %d.%d.%d", v.CTAPHID, v.Major, v.Minor, v.Build)
}

// InitReply is what CTAPHID_INIT answers.
type InitReply struct {
	// Nonce is the nonce sent, echoed back. A reply whose nonce does not match
	// belongs to somebody else's INIT, which happens when two programs
	// initialise one key at the same time.
	Nonce [8]byte
	// Channel is the channel id to use from now on.
	Channel uint32
	Version Version
	Caps    Capabilities
}

// ParseInit reads the reply to [CmdInit].
//
// It does NOT check the nonce: whether a mismatched nonce is somebody else's
// reply to ignore or a fault to report is the caller's decision, and this
// returns what arrived.
func ParseInit(data []byte) (InitReply, error) {
	if len(data) < 17 {
		return InitReply{}, ErrTruncated
	}
	var r InitReply
	copy(r.Nonce[:], data[0:8])
	r.Channel = binary.BigEndian.Uint32(data[8:12])
	r.Version = Version{CTAPHID: data[12], Major: data[13], Minor: data[14], Build: data[15]}
	r.Caps = Capabilities(data[16])
	return r, nil
}
