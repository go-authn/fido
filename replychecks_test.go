package fido

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// ⛔ A reply to another command is not the answer. CTAP 2.1 11.2.9: each
// command's response carries that command; libfido2 refuses one that does
// not. Here the key answers a PING with a WINK, carrying the PING's data.
func TestAReplyToAnotherCommandIsRefused(t *testing.T) {
	nonce := withNonce(t)
	const ch = 0x7
	f := answering(nonce, ch, byte(CapWink|CapCBOR))
	inner := f.reply
	f.reply = func(sent []byte) [][]byte {
		if (sent[4] &^ 0x80) == CmdPing {
			p, _ := Split(ch, CmdWink, sent[7:8])
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
	if _, err := k.Ping(ctx, []byte("x")); err == nil || !strings.Contains(err.Error(), "answered command") {
		t.Errorf("a WINK in reply to a PING = %v", err)
	}
}

// A pinUvAuthToken has the length its protocol gives it (CTAP 2.1 6.5.6,
// 6.5.7): 16 or 32 bytes under protocol one, 32 under protocol two. A key
// that sends anything else has not sent a token.
func TestATokenOfTheWrongLengthIsNotOne(t *testing.T) {
	for _, c := range []struct {
		proto PINProtocol
		n     int
		ok    bool
	}{
		{PINProtocolOne, 16, true},
		{PINProtocolOne, 32, true},
		{PINProtocolOne, 48, false},
		{PINProtocolTwo, 32, true},
		{PINProtocolTwo, 16, false},
		{PINProtocolTwo, 64, false},
	} {
		a := newPINAuthenticator(t, "1234")
		a.token = make([]byte, c.n)
		if _, err := rand.Read(a.token); err != nil {
			t.Fatal(err)
		}
		k := ctap2Key(t, CapCBOR, a.reply)
		_, err := k.PINToken(context.Background(), "1234", c.proto, PermGetAssertion, "example.test")
		switch {
		case c.ok && err != nil:
			t.Errorf("%v, %d bytes: refused: %v", c.proto, c.n, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), "bytes")):
			t.Errorf("%v, %d bytes: %v", c.proto, c.n, err)
		}
	}
}
