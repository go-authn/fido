// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// realGetInfo is what a YubiKey FIDO 5.7.4 really answered on 2026-09-02,
// captured through this package's own transport and kept verbatim.
//
// A fixture written by hand from the specification only checks that the code
// agrees with whoever wrote the fixture. This one was produced by hardware that
// had never seen the decoder.
func realGetInfo(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/yubikey-fido-5.7.4-getinfo.hex")
	if err != nil {
		t.Fatalf("the captured reply is missing: %v", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("the captured reply is not hex: %v", err)
	}
	return b
}

func TestParseInfoOnAReplyFromARealKey(t *testing.T) {
	i, err := parseInfo(realGetInfo(t))
	if err != nil {
		t.Fatalf("parseInfo: %v", err)
	}
	for _, want := range []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"} {
		if !contains(i.Versions, want) {
			t.Errorf("versions %v do not include %q", i.Versions, want)
		}
	}
	if !contains(i.Extensions, "hmac-secret") {
		t.Errorf("extensions %v do not include hmac-secret", i.Extensions)
	}
	// The AAGUID identifies the MODEL. This one is a YubiKey FIDO.
	if got := hex.EncodeToString(i.AAGUID[:]); got != "b7d3f68e88a6471e9ecf2df26d041ede" {
		t.Errorf("aaguid %s", got)
	}
	// rk and up are declared true; clientPin and uv are declared FALSE, which
	// is not the same as absent -- this key can have a PIN and has none set.
	if !i.Has("rk") || !i.Has("up") {
		t.Errorf("options %v, want rk and up", i.Options)
	}
	if i.Has("clientPin") {
		t.Error("clientPin reads as true, but this key has no PIN set")
	}
	if _, declared := i.Options["clientPin"]; !declared {
		t.Error("clientPin is not even declared, so 'false' and 'absent' are being confused")
	}
	if got := i.String(); !strings.Contains(got, "FIDO_2_1") || !strings.Contains(got, "rk") {
		t.Errorf("String() = %q", got)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestParseInfoRefusesWhatIsNotADescription(t *testing.T) {
	noVersions, _ := cbor.Marshal(map[uint64]any{infoOptions: map[string]bool{"rk": true}})
	shortAAGUID, _ := cbor.Marshal(map[uint64]any{
		infoVersions: []string{"FIDO_2_0"},
		infoAAGUID:   []byte{1, 2, 3},
	})
	wrongType, _ := cbor.Marshal(map[uint64]any{
		infoVersions:   []string{"FIDO_2_0"},
		infoMaxMsgSize: "not a number",
	})
	for _, c := range []struct {
		name string
		body []byte
		want string
	}{
		{"nothing at all", nil, "no bytes"},
		{"not a map", []byte{0x01, 0x02}, "not a CBOR map"},
		{"no version named", noVersions, "named no protocol version"},
		{"an identifier of the wrong length", shortAAGUID, "3 bytes"},
		{"a field of the wrong type", wrongType, "field 0x05"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseInfo(c.body); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

// TestAFieldTheKeyDidNotSendIsNotAFieldSetToNothing: a key that says nothing
// about transports has not said it has none.
func TestAFieldTheKeyDidNotSendIsNotAFieldSetToNothing(t *testing.T) {
	body, _ := cbor.Marshal(map[uint64]any{infoVersions: []string{"FIDO_2_0"}})
	i, err := parseInfo(body)
	if err != nil {
		t.Fatalf("parseInfo: %v", err)
	}
	if i.Transports != nil || i.Extensions != nil || i.Options != nil {
		t.Error("absent fields came back as empty ones")
	}
	if i.MaxMsgSize != 0 {
		t.Errorf("MaxMsgSize = %d for a key that did not say", i.MaxMsgSize)
	}
	if i.Has("rk") {
		t.Error("an option nobody declared reads as true")
	}
	if got := i.String(); got != "FIDO_2_0" {
		t.Errorf("String() = %q", got)
	}
}

func TestStatusNamesWhatACallerCanActOn(t *testing.T) {
	if StatusOK.Error() {
		t.Error("success reports itself as an error")
	}
	if got := StatusOK.String(); got != "ok" {
		t.Errorf("StatusOK = %q", got)
	}
	if got := Status(0x31).String(); !strings.Contains(got, "PIN was wrong") {
		t.Errorf("0x31 = %q", got)
	}
	if got := Status(0x3A).String(); !strings.Contains(got, "did not touch") {
		t.Errorf("0x3A = %q", got)
	}
	// A code with no name here is rendered as its number rather than guessed
	// at, and still reports itself as an error.
	unnamed := Status(0x7F)
	if !unnamed.Error() || !strings.Contains(unnamed.String(), "0x7f") {
		t.Errorf("an unnamed status = %q", unnamed.String())
	}
}

// ctap2Key is a fake authenticator that answers CBOR commands.
func ctap2Key(t *testing.T, caps Capabilities, reply func(cmd byte, params []byte) []byte) *Key {
	t.Helper()
	nonce := withNonce(t)
	const ch = 0xC7A9
	f := answering(nonce, ch, byte(caps))
	inner := f.reply
	rc := NewReassembler(ch)
	f.reply = func(sent []byte) [][]byte {
		if binary.BigEndian.Uint32(sent[0:4]) == BroadcastChannel {
			return inner(sent)
		}
		msg, done, err := rc.Feed(sent)
		if err != nil || !done || msg.Cmd != CmdCBOR {
			return inner(sent)
		}
		out := reply(msg.Data[0], msg.Data[1:])
		p, _ := Split(ch, CmdCBOR, out)
		return p
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(stop)
	k, err := Open(ctx, f)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { k.Close() })
	return k
}

func TestGetInfoThroughTheWholeStack(t *testing.T) {
	body := realGetInfo(t)
	k := ctap2Key(t, CapWink|CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd != CmdGetInfo {
			t.Errorf("the key was asked command %#02x", cmd)
		}
		if len(params) != 0 {
			t.Errorf("getInfo was sent %d parameter byte(s); it takes none", len(params))
		}
		return append([]byte{byte(StatusOK)}, body...)
	})
	i, err := k.GetInfo(context.Background())
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !contains(i.Versions, "FIDO_2_1") {
		t.Errorf("versions %v", i.Versions)
	}
}

func TestAKeyThatDoesNotSpeakCTAP2IsNotAsked(t *testing.T) {
	asked := false
	k := ctap2Key(t, CapWink, func(byte, []byte) []byte {
		asked = true
		return []byte{0}
	})
	if _, err := k.GetInfo(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("GetInfo on a CTAP1-only key = %v", err)
	}
	if asked {
		t.Error("a key that cannot speak CTAP2 was asked anyway")
	}
}

func TestACTAP2RefusalIsReportedInWords(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte {
		return []byte{0x2B} // a PIN is required
	})
	_, err := k.GetInfo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "PIN is required") {
		t.Errorf("a CTAP2 refusal = %v", err)
	}
}

func TestAnEmptyCTAP2ReplyIsNotSuccess(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return nil })
	if _, err := k.GetInfo(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "nothing at all") {
		t.Errorf("an empty reply = %v", err)
	}
}

func TestACTAP2CommandThatCannotBeSent(t *testing.T) {
	k := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0} })
	if _, err := k.CBOR(context.Background(), CmdGetInfo, make([]byte, MaxMessage)); !errors.Is(err, ErrTooLong) {
		t.Errorf("an over-long CTAP2 command = %v, want ErrTooLong", err)
	}
}

// TestAnInfoNobodyFilledInStillReads. parseInfo refuses a reply that names no
// version, but Info is exported and a caller can build one; printing it must
// not come out as an empty line that reads like a key with no protocols.
func TestAnInfoNobodyFilledInStillReads(t *testing.T) {
	if got := (Info{}).String(); !strings.Contains(got, "no version stated") {
		t.Errorf("an empty Info renders as %q", got)
	}
	if got := (Info{Options: map[string]bool{"rk": true}}).String(); !strings.Contains(got, "rk") {
		t.Errorf("an Info with only options renders as %q", got)
	}
}
