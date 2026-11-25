package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	authn "github.com/go-authn/fido"
	"github.com/go-authn/fido/mds"
)

// attestAAGUID is the YubiKey Bio's, as 16 bytes.
var attestAAGUID = func() [16]byte {
	var a [16]byte
	h, _ := hex.DecodeString(strings.ReplaceAll(bioAAGUID, "-", ""))
	copy(a[:], h)
	return a
}()

// extMode says what the leaf carries for id-fido-gen-ce-aaguid.
type extMode int

const (
	extMatch extMode = iota
	extMismatch
	extAbsent
	extMalformed
)

// attestCase is one registration the virtual authenticator answers.
type attestCase struct {
	ext      extMode
	badSig   bool
	wrongCA  bool // the MDS lists another root than the one that signed the leaf
	noUV     bool
	selfFmt  bool // format none
	unlisted bool
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mkCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := mustKey(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// virtualAuthenticator answers makeCredential with a packed attestation made as
// the case says, signing over authData||clientDataHash as a real key does.
func virtualAuthenticator(t *testing.T, ac attestCase) (func(authn.MakeCredentialRequest) (*authn.Attestation, error), *x509.Certificate) {
	ca, caKey := mkCA(t, "Test Attestation Root")
	other, _ := mkCA(t, "Another Root")
	listed := ca
	if ac.wrongCA {
		listed = other
	}
	return func(req authn.MakeCredentialRequest) (*authn.Attestation, error) {
		credKey := mustKey(t)
		ecdhPub, _ := credKey.PublicKey.ECDH()
		raw := ecdhPub.Bytes() // 0x04 || X || Y
		cose, err := ctap2Enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
		if err != nil {
			return nil, err
		}
		flags := byte(0x01 | 0x40) // UP, AT
		if !ac.noUV {
			flags |= 0x04
		}
		rpHash := sha256.Sum256([]byte(req.RP.ID))
		ad := append([]byte(nil), rpHash[:]...)
		ad = append(ad, flags, 0, 0, 0, 1)
		ad = append(ad, attestAAGUID[:]...)
		credID := bytes.Repeat([]byte{7}, 32)
		ad = append(ad, 0, byte(len(credID)))
		ad = append(ad, credID...)
		ad = append(ad, cose...)
		parsed, err := authn.ParseAuthData(ad)
		if err != nil {
			return nil, err
		}
		if ac.selfFmt {
			return &authn.Attestation{Format: "none", AuthData: ad, Parsed: parsed, Statement: []byte{0xa0}}, nil
		}

		leafKey := mustKey(t)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0xabcdef),
			Subject: pkix.Name{Country: []string{"SE"}, Organization: []string{"Test Vendor"},
				OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test Leaf"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
			BasicConstraintsValid: true,
		}
		octets := func(b []byte) []byte { v, _ := asn1.Marshal(b); return v }
		switch ac.ext {
		case extMatch:
			tpl.ExtraExtensions = []pkix.Extension{{Id: oidAAGUID, Value: octets(attestAAGUID[:])}}
		case extMismatch:
			other := attestAAGUID
			other[15] ^= 0xff
			tpl.ExtraExtensions = []pkix.Extension{{Id: oidAAGUID, Value: octets(other[:])}}
		case extMalformed:
			tpl.ExtraExtensions = []pkix.Extension{{Id: oidAAGUID, Value: octets([]byte{1, 2, 3})}}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &leafKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(append(append([]byte(nil), ad...), req.ClientDataHash...))
		sig, err := ecdsa.SignASN1(rand.Reader, leafKey, sum[:])
		if err != nil {
			return nil, err
		}
		if ac.badSig {
			sig[len(sig)-1] ^= 0xff
		}
		st, err := ctap2Enc.Marshal(map[string]any{"alg": -7, "sig": sig, "x5c": [][]byte{der}})
		if err != nil {
			return nil, err
		}
		return &authn.Attestation{Format: "packed", AuthData: ad, Parsed: parsed, Statement: st}, nil
	}, listed
}

func blobListing(root *x509.Certificate, unlisted bool) *mds.Blob {
	e := entryWith(bioAAGUID, "Test Bio")
	e.MetadataStatement.AttestationRootCertificates = []string{base64.StdEncoding.EncodeToString(root.Raw)}
	if unlisted {
		e.AAGUID = "00000000-0000-0000-0000-0000000000ff"
	}
	return &mds.Blob{No: 9, Entries: []mds.Entry{e}}
}

func attestFake(t *testing.T, ac attestCase) *fake {
	t.Helper()
	f := newFake()
	f.info.Options["uv"] = true
	fn, listed := virtualAuthenticator(t, ac)
	f.mcFn = func(r authn.MakeCredentialRequest) (*authn.Attestation, error) { f.mcReq = r; return fn(r) }
	use(t, f, nil)
	useBlob(t, blobListing(listed, ac.unlisted), nil)
	return f
}

func (f *fake) MakeCredential(_ context.Context, r authn.MakeCredentialRequest) (*authn.Attestation, error) {
	return f.mcFn(r)
}

func TestAttestVerifiesAMatchingExtension(t *testing.T) {
	f := attestFake(t, attestCase{ext: extMatch})
	out, _, err := run("attest")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"fmt:            packed", "authData AAGUID: " + bioAAGUID, "UP|UV|AT", "discardable", "non-resident",
		"x5c[0]", "Test Leaf", "serial:    abcdef", "PRESENT " + bioAAGUID, "EQUALS authData's AAGUID",
		"statement:      VERIFIED", "chain:          VERIFIED", "blob no 9",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if f.mcReq.RP.ID != attestRPID || !f.mcReq.Options["uv"] || f.mcReq.Options["rk"] || len(f.mcReq.User.ID) != 32 || f.mcReq.Token.Valid() {
		t.Errorf("request %+v", f.mcReq)
	}
	if f.writes != 0 || !f.closed {
		t.Errorf("writes %d closed %v", f.writes, f.closed)
	}
}

func TestAttestReportsAMismatchingExtension(t *testing.T) {
	attestFake(t, attestCase{ext: extMismatch})
	out, _, err := run("attest")
	if err == nil || !strings.Contains(err.Error(), "statement") {
		t.Fatalf("a mismatch must fail: %v", err)
	}
	for _, want := range []string{"DIFFERS from authData's AAGUID", "statement:      NOT VERIFIED", "differs from authData AAGUID"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "chain:          VERIFIED") {
		t.Error("a chain was reported verified after the statement failed")
	}
}

func TestAttestReportsAnAbsentExtension(t *testing.T) {
	attestFake(t, attestCase{ext: extAbsent})
	out, _, err := run("attest")
	if err != nil {
		t.Fatalf("an absent extension is not a failure of the library's verdict: %v\n%s", err, out)
	}
	if !strings.Contains(out, "(1.3.6.1.4.1.45724.1.1.4): ABSENT") || !strings.Contains(out, "statement:      VERIFIED") {
		t.Errorf("%s", out)
	}
}

func TestAttestReportsAMalformedExtension(t *testing.T) {
	attestFake(t, attestCase{ext: extMalformed})
	out, _, err := run("attest")
	if err == nil || !strings.Contains(out, "PRESENT but malformed (the OCTET STRING is 3 bytes, not 16)") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestAttestChainFailure(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch, wrongCA: true})
	out, _, err := run("attest")
	if err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(out, "statement:      VERIFIED") || !strings.Contains(out, "chain:          NOT VERIFIED against the 1 MDS attestation root(s)") {
		t.Errorf("%s", out)
	}
}

func TestAttestUnlistedAndUnloadableMDS(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch, unlisted: true})
	out, _, err := run("attest")
	if err == nil || !strings.Contains(out, "is not listed in the FIDO MDS (blob no 9)") {
		t.Errorf("%v\n%s", err, out)
	}
	attestFake(t, attestCase{ext: extMatch})
	useBlob(t, nil, errors.New("offline"))
	out, _, err = run("attest")
	if err == nil || !strings.Contains(out, "NOT CHECKED: the MDS could not be loaded: offline") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestAttestBadSignature(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch, badSig: true})
	out, _, err := run("attest")
	if err == nil || !strings.Contains(out, "statement:      NOT VERIFIED") || strings.Contains(out, "chain:          VERIFIED") {
		t.Fatalf("%v\n%s", err, out)
	}
	// The certificate is still shown: a failing statement shows what it carried.
	if !strings.Contains(out, "x5c[0]") {
		t.Error("the certificate was not printed")
	}
}

func TestAttestWithoutUVAndWithNoneFormat(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch, noUV: true})
	if out, _, err := run("attest"); err == nil || !strings.Contains(out, "NOT VERIFIED") {
		t.Errorf("a registration without the UV flag was accepted: %v\n%s", err, out)
	}
	attestFake(t, attestCase{selfFmt: true})
	out, _, err := run("attest")
	if err == nil || !strings.Contains(out, "proves nothing about the hardware") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestAttestUsesThePINWhenTheKeyHasNoBuiltInVerification(t *testing.T) {
	f := attestFake(t, attestCase{ext: extMatch})
	delete(f.info.Options, "uv")
	tm := &term{answers: []string{"s3cret"}}
	tm.install(t)
	if out, _, err := run("attest"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.tokenPIN != "s3cret" || f.perms != authn.PermMakeCredential || f.mcReq.Options["uv"] {
		t.Errorf("pin %q perms %v opts %v", f.tokenPIN, f.perms, f.mcReq.Options)
	}
	for _, h := range f.held {
		if !bytes.Equal(h, make([]byte, len(h))) {
			t.Error("the PIN slice was not wiped")
		}
	}
	// No PIN and no built-in verification: refused before the key is asked.
	f = attestFake(t, attestCase{ext: extMatch})
	delete(f.info.Options, "uv")
	delete(f.info.Options, "clientPin")
	if _, _, err := run("attest"); err == nil || f.mcReq.RP.ID != "" {
		t.Errorf("a key that cannot verify was asked: %v", err)
	}
}

func TestAttestSaveTo(t *testing.T) {
	f := attestFake(t, attestCase{ext: extMatch})
	p := filepath.Join(t.TempDir(), "att.cbor")
	out, _, err := run("attest", "--save-to", p)
	if err != nil || !strings.Contains(out, "saved to") {
		t.Fatalf("%v\n%s", err, out)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
		t.Fatalf("%v %v", fi, err)
	}
	sentHash := f.mcReq.ClientDataHash
	// Never overwritten, and refused before the key is touched.
	f.mcReq = authn.MakeCredentialRequest{}
	if _, _, err := run("attest", "--save-to", p); err == nil || !strings.Contains(err.Error(), "never overwrites") || f.mcReq.RP.ID != "" {
		t.Errorf("overwrite: %v", err)
	}
	// A symlink is a name that exists, even when it dangles.
	l := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), l); err != nil {
		t.Skip(err)
	}
	if _, _, err := run("attest", "--save-to", l); err == nil {
		t.Error("a dangling symlink was written through")
	}
	// The saved envelope holds the attestation object and what it was signed with.
	b, _ := os.ReadFile(p)
	e, err := decodeEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := cbor.Unmarshal(e.AttestationObject, &m); err != nil || m["fmt"] != "packed" {
		t.Errorf("%v %v", m, err)
	}
	if e.RPID != attestRPID || !bytes.Equal(e.ClientDataHash, sentHash) {
		t.Errorf("rp %q hash %x vs sent %x", e.RPID, e.ClientDataHash, sentHash)
	}
}

// savedEnvelope runs attest --save-to and returns the path and its envelope.
func savedEnvelope(t *testing.T) (string, envelope) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "att.cbor")
	// The envelope is written before the verdicts: a failing attestation is saved too.
	run("attest", "--save-to", p)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := decodeEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	return p, e
}

func rewrite(t *testing.T, e envelope) string {
	t.Helper()
	b, err := encodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "t.cbor")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAttestVerifyFileRoundTrip(t *testing.T) {
	f := attestFake(t, attestCase{ext: extMatch})
	p, _ := savedEnvelope(t)
	f.mcReq = authn.MakeCredentialRequest{}
	use(t, newFake(), errNoKey) // no key is needed, or even present
	out, _, err := run("attest", "--verify-file", p)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"statement:      VERIFIED", "chain:          VERIFIED", "blob no 9", "serial:    abcdef"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestAttestVerifyFileTamperedHash(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch})
	_, e := savedEnvelope(t)
	// Only the hash field changed: it no longer matches clientDataJSON.
	e.ClientDataHash[0] ^= 1
	out, _, err := run("attest", "--verify-file", rewrite(t, e))
	if err == nil || !strings.Contains(err.Error(), "signature cannot verify") {
		t.Fatalf("%v\n%s", err, out)
	}
	// clientDataJSON changed consistently (new challenge, new hash): the
	// attestation signature, made over the old hash, fails.
	attestFake(t, attestCase{ext: extMatch})
	_, e = savedEnvelope(t)
	e.ClientDataJSON = []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","origin":"` + attestOrigin + `"}`)
	h := sha256.Sum256(e.ClientDataJSON)
	e.ClientDataHash = h[:]
	out, _, err = run("attest", "--verify-file", rewrite(t, e))
	if err == nil || !strings.Contains(out, "statement:      NOT VERIFIED") || !strings.Contains(out, "signature") || strings.Contains(out, "chain:          VERIFIED") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestAttestVerifyFileRefusals(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch, wrongCA: true})
	p, e := savedEnvelope(t)
	if out, _, err := run("attest", "--verify-file", p); err == nil || !strings.Contains(out, "chain:          NOT VERIFIED") {
		t.Errorf("a wrong root verified: %v\n%s", err, out)
	}
	e.V = 2
	b, _ := ctap2Enc.Marshal(e)
	p2 := filepath.Join(t.TempDir(), "v2")
	os.WriteFile(p2, b, 0o600)
	if _, _, err := run("attest", "--verify-file", p2); err == nil || !strings.Contains(err.Error(), "version 2 is not supported") {
		t.Errorf("%v", err)
	}
	if _, _, err := run("attest", "--verify-file", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing file verified")
	}
	if _, _, err := run("attest", "--verify-file", p, "--save-to", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("--verify-file with --save-to accepted")
	}
	// The bare attestation object (the format before envelopes) is refused.
	obj := filepath.Join(t.TempDir(), "obj")
	os.WriteFile(obj, e.AttestationObject, 0o600)
	if _, _, err := run("attest", "--verify-file", obj); err == nil || !strings.Contains(err.Error(), "not an attestation envelope") {
		t.Errorf("%v", err)
	}
}

func TestDecodeEnvelopeRefusals(t *testing.T) {
	good := envelope{RPID: "x", ClientDataJSON: []byte("{}"), ClientDataHash: make([]byte, 32), AttestationObject: []byte{1}}
	enc := func(m map[string]any) []byte { b, _ := ctap2Enc.Marshal(m); return b }
	gb, _ := encodeEnvelope(good)
	cases := map[string][]byte{
		"trailing":    append(append([]byte(nil), gb...), 0),
		"unknown key": enc(map[string]any{"v": 1, "rpId": "x", "clientDataJSON": []byte("{}"), "clientDataHash": make([]byte, 32), "attestationObject": []byte{1}, "extra": 1}),
		"short hash":  enc(map[string]any{"v": 1, "rpId": "x", "clientDataJSON": []byte("{}"), "clientDataHash": []byte{1}, "attestationObject": []byte{1}}),
		"no rp":       enc(map[string]any{"v": 1, "rpId": "", "clientDataJSON": []byte("{}"), "clientDataHash": make([]byte, 32), "attestationObject": []byte{1}}),
		"no object":   enc(map[string]any{"v": 1, "rpId": "x", "clientDataJSON": []byte("{}"), "clientDataHash": make([]byte, 32), "attestationObject": []byte{}}),
		"no json":     enc(map[string]any{"v": 1, "rpId": "x", "clientDataJSON": []byte{}, "clientDataHash": make([]byte, 32), "attestationObject": []byte{1}}),
		"too big":     make([]byte, maxEnvelopeSize+1),
		"empty":       nil,
		"v0":          enc(map[string]any{"v": 0, "rpId": "x", "clientDataJSON": []byte("{}"), "clientDataHash": make([]byte, 32), "attestationObject": []byte{1}}),
	}
	for name, b := range cases {
		if _, err := decodeEnvelope(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := decodeEnvelope(gb); err != nil {
		t.Errorf("good refused: %v", err)
	}
}

func TestEnvelopeVerifyInputsRefusals(t *testing.T) {
	cdOf := func(s string) envelope {
		h := sha256.Sum256([]byte(s))
		return envelope{ClientDataJSON: []byte(s), ClientDataHash: h[:], AttestationObject: []byte{0xa0}}
	}
	for name, e := range map[string]envelope{
		"not json":     cdOf("x"),
		"no challenge": cdOf(`{"type":"webauthn.create"}`),
		"not cbor":     func() envelope { e := cdOf(`{"challenge":"AAAA"}`); e.AttestationObject = []byte{0xff}; return e }(),
		"bad authData": cdOf(`{"challenge":"AAAA"}`),
	} {
		if _, _, _, err := e.verifyInputs(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAttestOpenAndKeyErrors(t *testing.T) {
	use(t, newFake(), errNoKey)
	if _, _, err := run("attest"); !errors.Is(err, errNoKey) {
		t.Errorf("%v", err)
	}
	f := attestFake(t, attestCase{})
	f.mcFn = func(authn.MakeCredentialRequest) (*authn.Attestation, error) { return nil, boom }
	if _, _, err := run("attest"); !errors.Is(err, boom) {
		t.Errorf("%v", err)
	}
	f = attestFake(t, attestCase{})
	f.infoErr = boom
	if _, _, err := run("attest"); !errors.Is(err, boom) {
		t.Errorf("%v", err)
	}
}

func TestParseStmtBounds(t *testing.T) {
	big8 := make([][]byte, 9)
	enc := func(m map[string]any) []byte { b, _ := ctap2Enc.Marshal(m); return b }
	for name, raw := range map[string][]byte{
		"nine certificates": enc(map[string]any{"alg": -7, "sig": []byte{1}, "x5c": big8}),
		"huge certificate":  enc(map[string]any{"alg": -7, "sig": []byte{1}, "x5c": [][]byte{make([]byte, maxStmtCertSz+1)}}),
		"huge signature":    enc(map[string]any{"alg": -7, "sig": make([]byte, maxStmtSig+1)}),
		"not a map":         {0x01},
	} {
		if _, err := parseStmt(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if s, err := parseStmt(nil); err != nil || len(s.X5C) != 0 {
		t.Errorf("empty: %v", err)
	}
}

func FuzzParseStmt(f *testing.F) {
	good, _ := ctap2Enc.Marshal(map[string]any{"alg": -7, "sig": []byte{1, 2}, "x5c": [][]byte{{1}, {2}}})
	f.Add(good)
	f.Add([]byte{0xa0})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := parseStmt(b)
		if err == nil && (len(s.X5C) > maxStmtCerts || len(s.Sig) > maxStmtSig) {
			t.Fatalf("bounds exceeded: %d certs, %d sig bytes", len(s.X5C), len(s.Sig))
		}
	})
}

func FuzzCertAAGUID(f *testing.F) {
	f.Add([]byte{0x04, 0x03, 1, 2, 3})
	octets, _ := asn1.Marshal(attestAAGUID[:])
	f.Add(octets)
	f.Add(append(octets, 0))
	f.Fuzz(func(t *testing.T, v []byte) {
		c := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidAAGUID, Value: v}}}
		x := certAAGUID(c)
		if !x.Present || (x.Value == nil) == (x.Err == "") || (x.Value != nil && len(x.Value) != 16) {
			t.Fatalf("inconsistent: %+v", x)
		}
	})
}

func TestFmtAAGUID(t *testing.T) {
	if got := fmtAAGUID(attestAAGUID[:]); got != bioAAGUID {
		t.Errorf("%s != %s", got, bioAAGUID)
	}
	if got := fmtAAGUID([]byte{1, 2}); got != "0102" {
		t.Errorf("%s", got)
	}
	if !strings.Contains(flagNames(0), "none") {
		t.Error("flags none")
	}
}

func TestAttestPINPathRefusals(t *testing.T) {
	pinKey := func() *fake {
		f := attestFake(t, attestCase{ext: extMatch})
		delete(f.info.Options, "uv")
		return f
	}
	f := pinKey()
	f.info.ForcePINChange = true
	if _, _, err := run("attest"); err == nil || !strings.Contains(err.Error(), "pin change") {
		t.Errorf("force change: %v", err)
	}
	f = pinKey()
	f.retriesErr = boom
	if _, _, err := run("attest"); !errors.Is(err, boom) {
		t.Errorf("retries: %v", err)
	}
	f = pinKey()
	(&term{err: boom}).install(t)
	if _, _, err := run("attest"); !errors.Is(err, boom) {
		t.Errorf("terminal: %v", err)
	}
	f = pinKey()
	f.tokenErr = boom
	(&term{answers: []string{"x"}}).install(t)
	if _, _, err := run("attest"); !errors.Is(err, boom) {
		t.Errorf("token: %v", err)
	}
	// A PIN given as a file wins over built-in verification.
	f = attestFake(t, attestCase{ext: extMatch})
	if _, _, err := run("attest", "--pin-file", secretFile(t, "filepin\n", 0o600)); err != nil || f.tokenPIN != "filepin" || f.mcReq.Options["uv"] {
		t.Errorf("pin-file: %v %q", err, f.tokenPIN)
	}
}

func TestAttestSaveToUnwritable(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch})
	p := filepath.Join(t.TempDir(), "no", "such", "dir", "a.cbor")
	if _, _, err := run("attest", "--save-to", p); err == nil || !strings.Contains(err.Error(), "--save-to") {
		t.Errorf("%v", err)
	}
}

func TestAttestShowsAStatementItCannotRead(t *testing.T) {
	garbage, _ := ctap2Enc.Marshal(map[string]any{"alg": -7, "sig": []byte{1}, "x5c": [][]byte{{1, 2, 3}}})
	tooMany, _ := ctap2Enc.Marshal(map[string]any{"alg": -7, "sig": []byte{1}, "x5c": make([][]byte, 9)})
	for name, st := range map[string][]byte{"not a certificate": garbage, "too many": tooMany, "not CBOR map": {0x01}} {
		f := attestFake(t, attestCase{ext: extMatch})
		inner := f.mcFn
		f.mcFn = func(r authn.MakeCredentialRequest) (*authn.Attestation, error) {
			a, err := inner(r)
			if a != nil {
				a.Statement = st
			}
			return a, err
		}
		out, _, err := run("attest")
		if err == nil || !strings.Contains(out, "fmt:            packed") {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if name == "not a certificate" && !strings.Contains(out, "NOT A CERTIFICATE") {
			t.Errorf("%s", out)
		}
		if name != "not a certificate" && !strings.Contains(out, "UNREADABLE") {
			t.Errorf("%s: %s", name, out)
		}
	}
}

func TestAttestMDSRootsUnreadable(t *testing.T) {
	attestFake(t, attestCase{ext: extMatch})
	e := entryWith(bioAAGUID, "Broken")
	e.MetadataStatement.AttestationRootCertificates = []string{"!!"}
	useBlob(t, &mds.Blob{No: 3, Entries: []mds.Entry{e}}, nil)
	out, _, err := run("attest")
	if err == nil || !strings.Contains(out, "NOT CHECKED: the MDS roots of") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestCertAAGUIDMalformations(t *testing.T) {
	for name, v := range map[string][]byte{"not DER": {0xff}, "trailing": append(mustOctets(attestAAGUID[:]), 0), "short": mustOctets([]byte{1})} {
		x := certAAGUID(&x509.Certificate{Extensions: []pkix.Extension{{Id: oidAAGUID, Value: v}}})
		if !x.Present || x.Value != nil || x.Err == "" {
			t.Errorf("%s: %+v", name, x)
		}
	}
	if x := certAAGUID(&x509.Certificate{}); x.Present {
		t.Error("absent reported present")
	}
}

func mustOctets(b []byte) []byte { v, _ := asn1.Marshal(b); return v }

func TestAttestationObjectOfAnEmptyAndAnInvalidStatement(t *testing.T) {
	b, err := attestationObject(&authn.Attestation{Format: "none", AuthData: []byte{1}})
	if err != nil || !bytes.Contains(b, []byte{0xa0}) {
		t.Errorf("empty statement: %v %x", err, b)
	}
	if _, err := attestationObject(&authn.Attestation{Format: "packed", Statement: []byte{0xff}}); err == nil {
		t.Error("an invalid statement was encoded")
	}
	f := attestFake(t, attestCase{ext: extMatch})
	f.mcFn = func(authn.MakeCredentialRequest) (*authn.Attestation, error) {
		return &authn.Attestation{Format: "packed", Statement: []byte{0xff}}, nil
	}
	if _, _, err := run("attest"); err == nil {
		t.Error("an invalid statement was reported")
	}
}
