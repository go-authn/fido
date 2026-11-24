// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mds

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var epoch = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// pki is a test CA hierarchy shaped like the real one: root, intermediate,
// leaf for mds.fidoalliance.org, each with a CRL distribution point.
type pki struct {
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey *ecdsa.PrivateKey
	crls                       map[string][]byte
}

const (
	rootCRL  = "http://crl.test/root.crl"
	interCRL = "http://crl.test/inter.crl"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, tpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{crls: map[string][]byte{}}
	p.rootKey, p.interKey, p.leafKey = newKey(t), newKey(t), newKey(t)
	nb, na := epoch.AddDate(-1, 0, 0), epoch.AddDate(5, 0, 0)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	p.root = sign(t, rootTpl, rootTpl, &p.rootKey.PublicKey, p.rootKey)
	interTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, CRLDistributionPoints: []string{rootCRL},
	}
	p.inter = sign(t, interTpl, p.root, &p.interKey.PublicKey, p.rootKey)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: Hostname}, DNSNames: []string{Hostname},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{interCRL},
	}
	p.leaf = sign(t, leafTpl, p.inter, &p.leafKey.PublicKey, p.interKey)
	p.setCRL(t, rootCRL, p.root, p.rootKey, epoch.AddDate(0, 0, -1), epoch.AddDate(0, 0, 7))
	p.setCRL(t, interCRL, p.inter, p.interKey, epoch.AddDate(0, 0, -1), epoch.AddDate(0, 0, 7))
	return p
}

func (p *pki) setCRL(t *testing.T, url string, issuer *x509.Certificate, key *ecdsa.PrivateKey, this, next time.Time, revoked ...*big.Int) {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: this})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: entries,
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	p.crls[url] = der
}

func (p *pki) opts() Options {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return Options{
		Roots: pool, Now: func() time.Time { return epoch },
		CRL: func(u string) ([]byte, error) {
			if der, ok := p.crls[u]; ok {
				return der, nil
			}
			return nil, errors.New("no such CRL " + u)
		},
	}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jws signs a payload with the leaf (ES256) under a header made of alg and
// the chain.
func (p *pki) jws(t *testing.T, alg string, chain []*x509.Certificate, payload string) string {
	t.Helper()
	var x5c []string
	for _, c := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	h, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "x5c": x5c})
	signed := b64u(h) + "." + b64u([]byte(payload))
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, p.leafKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + b64u(sig)
}

func payload(no int, next string, entries string) string {
	return `{"legalHeader":"legal","no":` + itoa(no) + `,"nextUpdate":"` + next + `","entries":[` + entries + `]}`
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

const bioEntry = `{"aaguid":"9dd8d593-2213-438a-97f8-d6b813d51c27","metadataStatement":{"description":"YubiKey Bio Fido Edition (Consumer Profile)","authenticatorVersion":50800,"attestationTypes":["basic_full"],"keyProtection":["hardware","secure_element"],"userVerificationDetails":[[{"userVerificationMethod":"fingerprint_internal"}],[{"userVerificationMethod":"passcode_external"}]],"attestationRootCertificates":["ROOT"]},"statusReports":[{"status":"FIDO_CERTIFIED_L1","effectiveDate":"2024-06-06","certificationDescriptor":"YubiKey Bio","certificateNumber":"FIDO20020240606001"}]}`

const keyEntry = `{"aaguid":"ee882879-721c-4913-9775-3dfcce97072a","metadataStatement":{"description":"YubiKey 5 Series","authenticatorVersion":2}}`

func (p *pki) good(t *testing.T) string {
	return p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, payload(7, "2026-12-01", bioEntry+","+keyEntry))
}

func TestAGoodBlobVerifies(t *testing.T) {
	p := newPKI(t)
	b, err := Verify([]byte(p.good(t)+"\n"), p.opts())
	if err != nil {
		t.Fatal(err)
	}
	if b.No != 7 || len(b.Entries) != 2 || b.NextUpdate() != time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("%+v", b)
	}
	if d := b.StaleAfter(epoch); d <= 0 || b.StaleAfter(b.NextUpdate()) != 0 {
		t.Fatalf("stale after %v", d)
	}
}

func TestAnRSASignedBlobVerifies(t *testing.T) {
	p := newPKI(t)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: Hostname}, DNSNames: []string{Hostname},
		NotBefore: epoch.AddDate(-1, 0, 0), NotAfter: epoch.AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{interCRL},
	}
	leaf := sign(t, tpl, p.inter, &rk.PublicKey, p.interKey)
	var x5c []string
	for _, c := range []*x509.Certificate{leaf, p.inter} {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "x5c": x5c})
	signed := b64u(h) + "." + b64u([]byte(payload(1, "2026-12-01", keyEntry)))
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify([]byte(signed+"."+b64u(sig)), p.opts()); err != nil {
		t.Fatal(err)
	}
	// RS256 declared, ES256 key: refused.
	if _, err := Verify([]byte(strings.Replace(p.good(t), p.good(t)[:strings.IndexByte(p.good(t), '.')], b64u([]byte(`{"alg":"RS256","x5c":["`+base64.StdEncoding.EncodeToString(p.leaf.Raw)+`"]}`)), 1)), p.opts()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("alg/key mismatch: %v", err)
	}
}

func TestEveryRefusalIsUnverified(t *testing.T) {
	p := newPKI(t)
	good := p.good(t)
	parts := strings.Split(good, ".")
	otherRoot := newPKI(t)

	revokedLeaf := newPKI(t)
	revokedLeaf.setCRL(t, interCRL, revokedLeaf.inter, revokedLeaf.interKey, epoch.AddDate(0, 0, -1), epoch.AddDate(0, 0, 7), revokedLeaf.leaf.SerialNumber)
	revokedInter := newPKI(t)
	revokedInter.setCRL(t, rootCRL, revokedInter.root, revokedInter.rootKey, epoch.AddDate(0, 0, -1), epoch.AddDate(0, 0, 7), revokedInter.inter.SerialNumber)
	staleCRL := newPKI(t)
	staleCRL.setCRL(t, interCRL, staleCRL.inter, staleCRL.interKey, epoch.AddDate(0, 0, -9), epoch.AddDate(0, 0, -2))
	futureCRL := newPKI(t)
	futureCRL.setCRL(t, interCRL, futureCRL.inter, futureCRL.interKey, epoch.AddDate(0, 0, 1), epoch.AddDate(0, 0, 7))
	forgedCRL := newPKI(t)
	forgedCRL.setCRL(t, interCRL, forgedCRL.inter, newKey(t), epoch.AddDate(0, 0, -1), epoch.AddDate(0, 0, 7))
	noCRL := newPKI(t)
	delete(noCRL.crls, interCRL)
	garbageCRL := newPKI(t)
	garbageCRL.crls[interCRL] = []byte("not a CRL")

	tamperedPayload := parts[0] + "." + b64u([]byte(payload(99, "2026-12-01", bioEntry))) + "." + parts[2]
	noX5C := p.jws(t, "ES256", nil, payload(1, "2026-12-01", ""))
	manyX5C := p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter, p.inter, p.inter, p.inter, p.inter, p.inter, p.inter, p.inter}, payload(1, "2026-12-01", ""))
	noRootSent := p.jws(t, "ES256", []*x509.Certificate{p.leaf}, payload(1, "2026-12-01", ""))

	cases := []struct {
		name string
		blob string
		o    Options
	}{
		{"payload altered after signing", tamperedPayload, p.opts()},
		{"alg none", strings.Replace(good, parts[0], b64u([]byte(`{"alg":"none","x5c":["`+base64.StdEncoding.EncodeToString(p.leaf.Raw)+`"]}`)), 1), p.opts()},
		{"alg HS256", p.jws(t, "HS256", []*x509.Certificate{p.leaf, p.inter}, payload(1, "2026-12-01", "")), p.opts()},
		{"no x5c", noX5C, p.opts()},
		{"x5c too long", manyX5C, p.opts()},
		{"chain does not end at the root", good, otherRoot.opts()},
		{"intermediate missing", noRootSent, p.opts()},
		{"signed by another key", func() string {
			q := newPKI(t)
			q.leafKey = p.leafKey // same leaf key, other CA
			return q.jws(t, "ES256", []*x509.Certificate{q.leaf, q.inter}, payload(1, "2026-12-01", ""))
		}(), p.opts()},
		{"leaf revoked", revokedLeaf.good(t), revokedLeaf.opts()},
		{"intermediate revoked", revokedInter.good(t), revokedInter.opts()},
		{"CRL past its nextUpdate", staleCRL.good(t), staleCRL.opts()},
		{"CRL not yet valid", futureCRL.good(t), futureCRL.opts()},
		{"CRL signed by another key", forgedCRL.good(t), forgedCRL.opts()},
		{"CRL unreachable", noCRL.good(t), noCRL.opts()},
		{"CRL is garbage", garbageCRL.good(t), garbageCRL.opts()},
		{"wrong hostname", good, func() Options { o := p.opts(); o.Hostname = "evil.example"; return o }()},
		{"certificate expired", good, func() Options {
			o := p.opts()
			o.Now = func() time.Time { return epoch.AddDate(10, 0, 0) }
			return o
		}()},
	}
	for _, c := range cases {
		_, err := Verify([]byte(c.blob), c.o)
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// The pinned root is the default: the test PKI does not chain to it.
	if _, err := Verify([]byte(good), Options{Now: p.opts().Now, CRL: p.opts().CRL}); !errors.Is(err, ErrUnverified) {
		t.Errorf("default root accepted a test chain: %v", err)
	}
}

func TestALeafForAnotherHostIsRefused(t *testing.T) {
	// Any GlobalSign EV site must not be able to sign a blob.
	p := newPKI(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "shop.example"}, DNSNames: []string{"shop.example"},
		NotBefore: epoch.AddDate(-1, 0, 0), NotAfter: epoch.AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{interCRL},
	}
	p.leaf = sign(t, tpl, p.inter, &p.leafKey.PublicKey, p.interKey)
	if _, err := Verify([]byte(p.good(t)), p.opts()); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "shop.example") && !strings.Contains(err.Error(), "valid for") {
		t.Fatalf("%v", err)
	}
}

func TestACertificateWithoutACRLIsRefused(t *testing.T) {
	p := newPKI(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: Hostname}, DNSNames: []string{Hostname},
		NotBefore: epoch.AddDate(-1, 0, 0), NotAfter: epoch.AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	p.leaf = sign(t, tpl, p.inter, &p.leafKey.PublicKey, p.interKey)
	_, err := Verify([]byte(p.good(t)), p.opts())
	if !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "no CRL distribution point") {
		t.Fatalf("%v", err)
	}
}

func TestAnExpiredBlobIsRefused(t *testing.T) {
	p := newPKI(t)
	o := p.opts()
	// nextUpdate 2026-11-24 is good all that day, not the next.
	blob := p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, payload(1, "2026-11-24", keyEntry))
	if _, err := Verify([]byte(blob), o); err != nil {
		t.Fatalf("on the day: %v", err)
	}
	o.Now = func() time.Time { return time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC) }
	if _, err := Verify([]byte(blob), o); !errors.Is(err, ErrExpired) {
		t.Fatalf("day after: %v", err)
	}
}

func TestMalformedBlobsAreRefused(t *testing.T) {
	p := newPKI(t)
	cases := map[string]string{
		"empty":             "",
		"one part":          "abc",
		"four parts":        "a.b.c.d",
		"header not base64": "!!.e30.e30",
		"header not JSON":   b64u([]byte("x")) + ".e30.e30",
		"padded base64":     "e30=.e30.e30",
		"payload not JSON":  p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, "{"),
		"no nextUpdate":     p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, `{"no":1,"entries":[]}`),
		"bad nextUpdate":    p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, `{"no":1,"nextUpdate":"soon","entries":[]}`),
		"negative no":       p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, `{"no":-1,"nextUpdate":"2026-12-01","entries":[]}`),
	}
	for name, blob := range cases {
		_, err := Verify([]byte(blob), p.opts())
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Verify(make([]byte, MaxBlobBytes+1), p.opts()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
}

func TestLookupSearchAndRoots(t *testing.T) {
	p := newPKI(t)
	pl := strings.Replace(payload(1, "2026-12-01", bioEntry+","+keyEntry), "ROOT", base64.StdEncoding.EncodeToString(p.root.Raw), 1)
	b, err := Verify([]byte(p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, pl)), p.opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"9dd8d593-2213-438a-97f8-d6b813d51c27", "9DD8D59322134 38A97F8D6B813D51C27"[:0] + "9DD8D593-2213-438A-97F8-D6B813D51C27", "9dd8d59322138438a97f8d6b813d51c27"[:0] + "9dd8d593" + "2213438a97f8d6b813d51c27"} {
		e := b.Lookup(id)
		if e == nil || e.Description() != "YubiKey Bio Fido Edition (Consumer Profile)" {
			t.Fatalf("%s: %+v", id, e)
		}
	}
	if b.Lookup("00000000-0000-0000-0000-000000000000") != nil || b.Lookup("xyz") != nil || b.Lookup("") != nil {
		t.Fatal("found what is not there")
	}
	e := b.Lookup("9dd8d593-2213-438a-97f8-d6b813d51c27")
	st := e.MetadataStatement
	if st.AuthenticatorVersion != 50800 || st.AttestationTypes[0] != "basic_full" || len(st.KeyProtection) != 2 ||
		st.UserVerificationDetails[0][0].UserVerificationMethod != "fingerprint_internal" {
		t.Fatalf("%+v", st)
	}
	if r := e.StatusReports[0]; r.Status != "FIDO_CERTIFIED_L1" || r.EffectiveDate != "2024-06-06" || r.CertificateNumber != "FIDO20020240606001" {
		t.Fatalf("%+v", r)
	}
	roots, err := e.RootCertificates()
	if err != nil || len(roots) != 1 || !roots[0].Equal(p.root) {
		t.Fatalf("%v %v", roots, err)
	}
	if roots, err = b.Lookup("ee882879-721c-4913-9775-3dfcce97072a").RootCertificates(); err != nil || roots != nil {
		t.Fatalf("%v %v", roots, err)
	}
	if got := b.Search("yubikey"); len(got) != 2 {
		t.Fatalf("%d hits", len(got))
	}
	if got := b.Search(" BIO "); len(got) != 1 || got[0].AAGUID != "9dd8d593-2213-438a-97f8-d6b813d51c27" {
		t.Fatalf("%v", got)
	}
	if got := b.Search("ee8828"); len(got) != 1 {
		t.Fatalf("by AAGUID: %v", got)
	}
	if b.Search("") != nil || b.Search("nothing like this") != nil {
		t.Fatal("search found nothing-matches")
	}
	bad := &Entry{MetadataStatement: &Statement{AttestationRootCertificates: []string{"!!"}}}
	if _, err := bad.RootCertificates(); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	bad.MetadataStatement.AttestationRootCertificates = []string{base64.StdEncoding.EncodeToString([]byte("x"))}
	if _, err := bad.RootCertificates(); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

func TestTheEntryBoundIsEnforced(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"no":1,"nextUpdate":"2026-12-01","entries":[`)
	for i := 0; i <= MaxEntries; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("{}")
	}
	sb.WriteString("]}")
	if _, err := parsePayload([]byte(sb.String())); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

// The embedded root is the certificate whose fingerprints GlobalSign
// publishes (https://support.globalsign.com/ca-certificates/root-certificates/globalsign-root-certificates,
// "TLS Root R46": serial and SHA-1), and it is self-signed, a CA, and in its
// validity period.
func TestThePinnedRootIsGlobalSignR46(t *testing.T) {
	c := Root()
	sum := sha256.Sum256(c.Raw)
	if hex.EncodeToString(sum[:]) != RootSHA256 {
		t.Fatal("sha256")
	}
	if c.SerialNumber.Text(16) != "11d2bbb9d723189e405f0a9d2dd0df2567d1" {
		t.Fatalf("serial %s", c.SerialNumber.Text(16))
	}
	if c.Subject.String() != "CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE" || c.Issuer.String() != c.Subject.String() {
		t.Fatalf("%s / %s", c.Subject, c.Issuer)
	}
	if !c.IsCA || c.CheckSignatureFrom(c) != nil {
		t.Fatal("not a self-signed CA")
	}
	if s1 := sha1.Sum(c.Raw); hex.EncodeToString(s1[:]) != RootSHA1 {
		t.Fatal("sha1")
	}
	if c.NotBefore != time.Date(2019, 3, 20, 0, 0, 0, 0, time.UTC) || c.NotAfter != time.Date(2046, 3, 20, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("%s to %s", c.NotBefore, c.NotAfter)
	}
}

func TestOffendingBytesAreNotTheRoot(t *testing.T) {
	old := rootR46DER
	defer func() { rootR46DER = old }()
	rootR46DER = append([]byte(nil), old...)
	rootR46DER[len(rootR46DER)-1] ^= 1
	defer func() {
		if recover() == nil {
			t.Fatal("a root that is not R46 was used")
		}
	}()
	Root()
}

func TestNormalizeAAGUID(t *testing.T) {
	for in, want := range map[string]string{
		"9DD8D593-2213-438A-97F8-D6B813D51C27": "9dd8d593-2213-438a-97f8-d6b813d51c27",
		"9dd8d593221 3438a97f8d6b813d51c27":    "",
		"00000000000000000000000000000000":     "00000000-0000-0000-0000-000000000000",
		"0000":                                 "",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz":     "",
	} {
		got, ok := NormalizeAAGUID(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
}

// client tests

type server struct {
	blob string
	hits int
	crls int
	err  error
}

func (s *server) fetch(string) ([]byte, error) {
	s.hits++
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.blob), nil
}

func newClient(t *testing.T, p *pki, s *server) *Client {
	t.Helper()
	o := p.opts()
	inner := o.CRL
	o.CRL = func(u string) ([]byte, error) { s.crls++; return inner(u) }
	return &Client{Dir: filepath.Join(t.TempDir(), "mds"), Options: o, Fetch: s.fetch}
}

func TestTheCacheIsUsedUntilNextUpdate(t *testing.T) {
	p := newPKI(t)
	s := &server{blob: p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, payload(5, "2026-11-30", keyEntry))}
	c := newClient(t, p, s)
	ctx := context.Background()
	if _, err := c.Load(ctx, false); err != nil || s.hits != 1 || s.crls != 2 {
		t.Fatalf("first load: %v hits %d crls %d", err, s.hits, s.crls)
	}
	s.err = errors.New("offline")
	b, err := c.Load(ctx, false)
	if err != nil || b.No != 5 || s.hits != 1 {
		t.Fatalf("cached load: %v hits %d", err, s.hits)
	}
	if s.crls != 2 {
		t.Fatalf("the CRLs were fetched again (%d): their nextUpdate had not passed", s.crls)
	}
	// Refresh goes to the network, and the network being down is an error,
	// not a silent fall-back to the cache.
	if _, err := c.Load(ctx, true); err == nil {
		t.Fatal("a forced refresh succeeded offline")
	}
	// Once nextUpdate has passed the cache is no longer trusted.
	c.Options.Now = func() time.Time { return time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := c.Load(ctx, false); err == nil || s.hits != 3 {
		t.Fatalf("expired cache served: %v hits %d", err, s.hits)
	}
	if fi, err := os.Stat(c.Dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(c.Dir, blobFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file %v %v", fi, err)
	}
}

func TestACorruptCacheIsReplacedNotTrusted(t *testing.T) {
	p := newPKI(t)
	s := &server{blob: p.good(t)}
	c := newClient(t, p, s)
	if _, err := c.Load(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	cached, err := os.ReadFile(filepath.Join(c.Dir, blobFile))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(cached), ".")
	tampered := parts[0] + "." + b64u([]byte(payload(99, "2026-12-01", ""))) + "." + parts[2]
	if err := os.WriteFile(filepath.Join(c.Dir, blobFile), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := c.Load(context.Background(), false)
	if err != nil || b.No != 7 || s.hits != 2 {
		t.Fatalf("%v %+v hits %d", err, b, s.hits)
	}
}

func TestARollbackIsRefused(t *testing.T) {
	p := newPKI(t)
	s := &server{blob: p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, payload(9, "2026-12-01", keyEntry))}
	c := newClient(t, p, s)
	if _, err := c.Load(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	s.blob = p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, payload(8, "2026-12-01", keyEntry))
	if _, err := c.Load(context.Background(), true); !errors.Is(err, ErrRollback) {
		t.Fatalf("%v", err)
	}
	s.blob = p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, payload(10, "2026-12-01", keyEntry))
	if b, err := c.Load(context.Background(), true); err != nil || b.No != 10 {
		t.Fatalf("%v", err)
	}
}

func TestAnUnverifiedDownloadIsNotStored(t *testing.T) {
	p := newPKI(t)
	parts := strings.Split(p.good(t), ".")
	s := &server{blob: parts[0] + "." + b64u([]byte(payload(1, "2026-12-01", ""))) + "." + parts[2]}
	c := newClient(t, p, s)
	if _, err := c.Load(context.Background(), false); !errors.Is(err, ErrUnverified) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, blobFile)); err == nil {
		t.Fatal("an unverified blob was cached")
	}
	s.err = errors.New("down")
	if _, err := c.Load(context.Background(), false); err == nil {
		t.Fatal("served with nothing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Load(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCRLCacheHonoursItsNextUpdate(t *testing.T) {
	p := newPKI(t)
	s := &server{blob: p.good(t)}
	c := newClient(t, p, s)
	if _, err := c.Load(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// A cached CRL that a CA has since replaced is fetched again once stale.
	c.Options.Now = func() time.Time { return epoch.AddDate(0, 0, 7).Add(time.Hour) }
	before := s.crls
	p.setCRL(t, interCRL, p.inter, p.interKey, epoch.AddDate(0, 0, 7), epoch.AddDate(0, 0, 14))
	p.setCRL(t, rootCRL, p.root, p.rootKey, epoch.AddDate(0, 0, 7), epoch.AddDate(0, 0, 14))
	c.Options.CRL = func(u string) ([]byte, error) { s.crls++; return p.crls[u], nil }
	// the blob itself (nextUpdate 12-01) is still good at +8 days: 12-02
	if _, err := c.Load(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if s.crls == before {
		t.Fatal("stale CRLs were not fetched again")
	}
}

func TestHTTPRefusals(t *testing.T) {
	for _, u := range []string{"ftp://x/y", "file:///etc/passwd", "://", "http://x/y"} {
		if _, err := httpGet(u, 10, true); err == nil {
			t.Errorf("fetched %q securely", u)
		}
	}
	if _, err := httpGet("gopher://x/y", 10, false); err == nil {
		t.Error("fetched gopher")
	}
}
