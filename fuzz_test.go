package fido

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// What a key sends back is input from a device the program does not control:
// a counterfeit, an emulator, or a USB gadget pretending to be one. These run
// it through every parser that reads it. Nothing may panic, and nothing may
// hand back more than the framing allows. Their seeds -- captured from a real
// YubiKey and the WebAuthn reference sample -- run with every `go test`;
// `go test -fuzz <name>` explores.

func FuzzAuthData(f *testing.F) {
	t := &testing.T{}
	f.Add(referenceAuthData(t))
	f.Add(attested(t, []byte("credential-id-16"), nil))
	f.Add(build(0, 0, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseAuthData(b)
		if err != nil {
			return
		}
		_ = a.String()
		if k, err := a.PublicKey(); err == nil && !k.Curve.IsOnCurve(k.X, k.Y) {
			t.Fatalf("a public key off its curve was returned: %v", a)
		}
	})
}

func FuzzReassembler(f *testing.F) {
	const ch = 0xC7A9
	for _, n := range []int{0, 1, initPayload, initPayload + 1, MaxMessage} {
		pkts, err := Split(ch, CmdCBOR, make([]byte, n))
		if err != nil {
			f.Fatal(err)
		}
		var all []byte
		for _, p := range pkts {
			all = append(all, p...)
		}
		f.Add(all)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReassembler(ch)
		for len(b) > 0 {
			n := min(ReportSize, len(b))
			msg, done, err := r.Feed(b[:n])
			b = b[n:]
			if err != nil {
				continue
			}
			if done && len(msg.Data) > MaxMessage {
				t.Fatalf("a message of %d bytes, beyond the framing's %d", len(msg.Data), MaxMessage)
			}
		}
	})
}

func FuzzGetInfo(f *testing.F) {
	t := &testing.T{}
	f.Add(realGetInfo(t))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseInfo(b)
	})
}

func FuzzAgreementKey(f *testing.F) {
	for _, m := range []map[int64]any{
		{coseKty: coseKtyEC2, coseAlg: -25, coseCrv: coseCrvP256, coseX: make([]byte, 32), coseY: make([]byte, 32)},
		{coseKty: coseKtyEC2},
	} {
		b, err := cbor.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = coseToECDH(cbor.RawMessage(b))
	})
}
