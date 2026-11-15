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

func FuzzExtensionOutputs(f *testing.F) {
	for _, m := range []map[string]any{
		{"hmac-secret": true, "credProtect": uint(3)},
		{"hmac-secret": []byte("0123456789abcdef0123456789abcdef")},
		{"credProtect": "three"},
		{"unknown": []any{1, "x"}},
	} {
		b, err := cbor.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0xa1, 0x6b, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't', 0xa1, 0xa1, 0x01, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := AuthData{Extensions: b}.ExtensionOutputs()
		if err == nil && o.HMACSecret && o.hmacEnc != nil {
			t.Fatal("hmac-secret read as both a flag and a ciphertext")
		}
	})
}

// FuzzHMACSecretOutput feeds the decryption of an assertion's hmac-secret
// output whatever a key could send: it must refuse or return exactly one or two
// 32-byte secrets.
func FuzzHMACSecretOutput(f *testing.F) {
	f.Add(make([]byte, 32), uint8(1), true)
	f.Add(make([]byte, 48), uint8(2), true)
	f.Add(make([]byte, 64), uint8(2), false)
	f.Add([]byte{}, uint8(1), false)
	f.Fuzz(func(t *testing.T, enc []byte, salts uint8, v2 bool) {
		proto := PINProtocolOne
		if v2 {
			proto = PINProtocolTwo
		}
		s := &hmacSession{keys: pinKeys{proto: proto, aes: make([]byte, 32), hmac: make([]byte, 32)}, salts: int(salts%2) + 1}
		a := &Assertion{Extensions: ExtensionOutputs{hmacEnc: enc}}
		out, err := s.output(a)
		if err != nil {
			return
		}
		if len(out.First) != 32 || (s.salts == 2) != (len(out.Second) == 32) {
			t.Fatalf("secrets of %d and %d bytes for %d salt(s)", len(out.First), len(out.Second), s.salts)
		}
	})
}
