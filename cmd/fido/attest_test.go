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
	// The saved object parses back as the attestation it was.
	b, _ := os.ReadFile(p)
	var m map[string]any
	if err := cbor.Unmarshal(b, &m); err != nil || m["fmt"] != "packed" {
		t.Errorf("%v %v", m, err)
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
