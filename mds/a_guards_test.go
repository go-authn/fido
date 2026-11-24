// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mds

// Tests that say WHICH guard refused. A refusal that any later line would also
// turn into an error is not held by a test that only expects an error, so each
// case here names a piece of the message the guard itself writes. This file
// sorts first on purpose: a guard that is gone often turns its input into a
// crash, and a crash ends the test binary, so every call that could crash is
// made through try, which reports the crash as a failure of its own case.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func try(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panicked: %v", name, r)
		}
	}()
	f()
}

func wantErr(t *testing.T, name string, err error, sentinel error, piece string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: no error (want ...%q...)", name, piece)
		return
	}
	if sentinel != nil && !errors.Is(err, sentinel) {
		t.Errorf("%s: %v is not %v", name, err, sentinel)
	}
	if !strings.Contains(err.Error(), piece) {
		t.Errorf("%s: %v (want ...%q...)", name, err, piece)
	}
}

func TestEachJWSRefusalSaysWhichPartIsBad(t *testing.T) {
	good := b64u([]byte("{}"))
	cases := []struct{ name, blob, want string }{
		{"two parts", "a.b", "not a compact JWS (2 parts)"},
		{"four parts", "a.b.c.d", "not a compact JWS (4 parts)"},
		{"header not base64", "!!!." + good + ".AA", "header: illegal base64"},
		{"header not JSON", b64u([]byte("not json")) + "." + good + ".AA", "header: invalid character"},
		{"payload not base64", good + ".!!!.AA", "payload: illegal base64"},
		{"signature not base64", good + "." + good + ".!!!", "signature: illegal base64"},
	}
	for _, c := range cases {
		try(t, c.name, func() {
			_, _, _, _, err := splitJWS([]byte(c.blob))
			wantErr(t, c.name, err, ErrMalformed, c.want)
		})
	}
	try(t, "good", func() {
		if _, _, sig, signed, err := splitJWS([]byte(good + "." + good + "." + b64u([]byte{1, 2}))); err != nil || len(sig) != 2 || signed != good+"."+good {
			t.Errorf("good: %v %x %q", err, sig, signed)
		}
	})
	try(t, "unverified", func() {
		_, err := parseUnverified([]byte("a.b"))
		wantErr(t, "parseUnverified", err, ErrMalformed, "not a compact JWS")
		_, err = parsePayload([]byte("{"))
		wantErr(t, "parsePayload", err, ErrMalformed, "payload: unexpected end")
	})
}

func TestEachSignatureRefusalSaysWhichCheckFailed(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256 := newKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(k crypto.PublicKey) *x509.Certificate { return &x509.Certificate{PublicKey: k} }
	sig64 := make([]byte, 64)
	cases := []struct {
		name string
		alg  string
		key  crypto.PublicKey
		sig  []byte
		want string
	}{
		{"RS256 with an EC key", "RS256", &p256.PublicKey, sig64, "alg RS256 but the leaf key is"},
		{"RS256 bad signature", "RS256", &rk.PublicKey, sig64, "signature:"},
		{"ES256 with an RSA key", "ES256", &rk.PublicKey, sig64, "alg ES256 but the leaf key is"},
		{"ES256 with a P-384 key", "ES256", &p384.PublicKey, sig64, "alg ES256 but the leaf key is"},
		{"ES256 signature of 65 bytes", "ES256", &p256.PublicKey, make([]byte, 65), "ES256 signature of 65 bytes"},
		{"ES256 signature of 10 bytes", "ES256", &p256.PublicKey, make([]byte, 10), "ES256 signature of 10 bytes"},
		{"ES256 bad signature", "ES256", &p256.PublicKey, sig64, "ES256 does not verify"},
		{"another alg", "none", &p256.PublicKey, sig64, "only RS256 and ES256"},
	}
	for _, c := range cases {
		try(t, c.name, func() {
			wantErr(t, c.name, verifySignature(c.alg, leaf(c.key), "a.b", c.sig), ErrUnverified, c.want)
		})
	}
}

func TestEachChainRefusalSaysWhichStepFailed(t *testing.T) {
	p := newPKI(t)
	hdr := func(x5c string) []byte {
		return []byte(b64u([]byte(`{"alg":"ES256","x5c":`+x5c+`}`)) + ".e30.AA")
	}
	cases := []struct{ name, blob, want string }{
		{"no chain", string(hdr(`[]`)), "no x5c"},
		{"chain too long", string(hdr("[" + strings.Repeat(`"AAAA",`, MaxChain) + `"AAAA"]`)), "bound"},
		{"x5c not base64", string(hdr(`["!!!"]`)), "x5c[0]: illegal base64"},
		{"x5c not a certificate", string(hdr(`["AAAA"]`)), "x5c[0]: x509"},
		{"payload not JSON, signed", p.jws(t, "ES256", []*x509.Certificate{p.leaf, p.inter}, "{not json"), "payload:"},
	}
	for _, c := range cases {
		try(t, c.name, func() {
			_, err := Verify([]byte(c.blob), p.opts())
			sentinel := ErrUnverified
			if strings.HasPrefix(c.name, "payload") {
				sentinel = ErrMalformed
			}
			wantErr(t, c.name, err, sentinel, c.want)
		})
	}
}

func TestEntriesWithoutAStatementOrWithABadRoot(t *testing.T) {
	var none, bad64, badDER Entry
	for e, js := range map[*Entry]string{
		&none:   `{"aaguid":"x"}`,
		&bad64:  `{"metadataStatement":{"attestationRootCertificates":["!!!"]}}`,
		&badDER: `{"metadataStatement":{"attestationRootCertificates":["AAAA"]}}`,
	} {
		if err := json.Unmarshal([]byte(js), e); err != nil {
			t.Fatal(err)
		}
	}
	try(t, "no statement", func() {
		if rc, err := none.RootCertificates(); rc != nil || err != nil || none.Description() != "" {
			t.Errorf("%v %v %q", rc, err, none.Description())
		}
	})
	try(t, "not base64", func() {
		_, err := bad64.RootCertificates()
		wantErr(t, "not base64", err, ErrMalformed, "attestationRootCertificates[0]: illegal base64")
	})
	try(t, "not a certificate", func() {
		_, err := badDER.RootCertificates()
		wantErr(t, "not a certificate", err, ErrMalformed, "attestationRootCertificates[0]: x509")
	})
}

func TestMalformedAAGUIDsMatchNothing(t *testing.T) {
	for _, s := range []string{"", "abcd", strings.Repeat("a", 30), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("g", 32)} {
		try(t, s, func() {
			if got, ok := NormalizeAAGUID(s); ok || got != "" {
				t.Errorf("%q: %q %v", s, got, ok)
			}
		})
	}
	b := &Blob{Entries: []Entry{{AAGUID: ""}, {AAGUID: "zz"}, {AAGUID: "ee882879-721c-4913-9775-3dfcce97072a"}}}
	try(t, "lookup", func() {
		for _, s := range []string{"", "zz", "ee88"} {
			if e := b.Lookup(s); e != nil {
				t.Errorf("Lookup(%q) = %+v", s, e)
			}
		}
		if e := b.Lookup("EE882879721C491397753DFCCE97072A"); e == nil || e.AAGUID != b.Entries[2].AAGUID {
			t.Errorf("Lookup of the third: %+v", e)
		}
	})
}

type failFile struct {
	werr, cerr error
	name       string
}

func (f failFile) Write(p []byte) (int, error) {
	if f.werr != nil {
		return 0, f.werr
	}
	return len(p), nil
}
func (f failFile) Close() error { return f.cerr }
func (f failFile) Name() string { return f.name }

func TestEachStoreFailureIsReturned(t *testing.T) {
	boom := errors.New("boom")
	for name, ff := range map[string]failFile{
		"write": {werr: boom},
		"close": {cerr: boom},
	} {
		ff.name = filepath.Join(t.TempDir(), "gone")
		try(t, name, func() {
			c := &Client{Dir: t.TempDir(), createTemp: func(string, string) (tempFile, error) { return ff, nil }}
			if err := c.store("x", []byte("data")); !errors.Is(err, boom) {
				t.Errorf("%s: %v", name, err)
			}
		})
	}
	pathOp := func(err error) string {
		var pe *fs.PathError
		var le *os.LinkError
		switch {
		case errors.As(err, &pe):
			return pe.Op
		case errors.As(err, &le):
			return le.Op
		}
		return "<" + strconv.Quote(err.Error()) + ">"
	}
	try(t, "the directory is a file", func() {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := (&Client{Dir: file}).store("x", nil); err == nil || pathOp(err) != "mkdir" {
			t.Errorf("%v", err)
		}
	})
	try(t, "the directory is not writable", func() {
		if os.Geteuid() == 0 || runtime.GOOS == "windows" {
			t.Skip("root writes anywhere, and Windows ignores the mode bits of a directory")
		}
		dir := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := (&Client{Dir: dir}).store("x", nil); err == nil || pathOp(err) != "open" {
			t.Errorf("%v", err)
		}
	})
	try(t, "the name is a directory", func() {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "x", "inside"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&Client{Dir: dir}).store("x", nil); err == nil || pathOp(err) != "rename" {
			t.Errorf("%v", err)
		}
	})
}

func TestLoadSaysWhatWentWrong(t *testing.T) {
	p := newPKI(t)
	ctx := context.Background()
	try(t, "url", func() {
		var got string
		c := &Client{Dir: t.TempDir(), Fetch: func(u string) ([]byte, error) { got = u; return nil, errors.New("x") }}
		c.Load(ctx, false)
		if got != DefaultURL {
			t.Errorf("default URL: %q", got)
		}
		c.URL = "https://example.test/blob"
		c.Load(ctx, false)
		if got != "https://example.test/blob" {
			t.Errorf("URL: %q", got)
		}
	})
	try(t, "download error", func() {
		sentinel := errors.New("network down")
		c := &Client{Dir: t.TempDir(), Options: p.opts(), Fetch: func(string) ([]byte, error) { return nil, sentinel }}
		_, err := c.Load(ctx, false)
		wantErr(t, "download", err, sentinel, "downloading the blob")
	})
	try(t, "store error", func() {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		c := &Client{Dir: file, Options: p.opts(), Fetch: func(string) ([]byte, error) { return []byte(p.good(t)), nil }}
		b, err := c.Load(ctx, false)
		if err == nil || b != nil || !strings.Contains(err.Error(), "mkdir") {
			t.Errorf("%v %v", b, err)
		}
	})
	try(t, "CRL download error", func() {
		o := p.opts()
		o.CRL = func(string) ([]byte, error) { return nil, errors.New("crl server down") }
		c := &Client{Dir: t.TempDir(), Options: o, Fetch: func(string) ([]byte, error) { return []byte(p.good(t)), nil }}
		_, err := c.Load(ctx, false)
		wantErr(t, "CRL", err, ErrUnverified, "crl server down")
	})
	try(t, "an oversize cache", func() {
		c := &Client{Dir: t.TempDir(), Options: p.opts(), Fetch: func(string) ([]byte, error) { return []byte(p.good(t)), nil }}
		if err := os.WriteFile(filepath.Join(c.Dir, blobFile), make([]byte, MaxBlobBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if b := c.readCached(c.Options); b != nil {
			t.Errorf("served: %+v", b)
		}
	})
}

func TestACRLThatCannotBeParsedIsRefusedWithoutACrash(t *testing.T) {
	p := newPKI(t)
	try(t, "garbage", func() {
		_, err := crlRevokes([]byte("not a CRL"), p.leaf, p.inter, epoch)
		if err == nil {
			t.Error("no error")
		}
	})
}

func TestHTTPGet(t *testing.T) {
	old := transport
	t.Cleanup(func() { transport = old })

	for _, c := range []struct {
		u      string
		secure bool
	}{{"ftp://x/y", true}, {"file:///etc/passwd", true}, {"://", true}, {"http://x/y", true}, {"gopher://x/y", false}, {"://", false}} {
		_, err := httpGet(c.u, 10, c.secure)
		wantErr(t, c.u, err, nil, "refusing to fetch")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("0123456789")) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r); w.Write([]byte("body")) })
	mux.HandleFunc("/cut", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("hello"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	mux.HandleFunc("/r/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r/"))
		if n == 0 {
			w.Write([]byte("arrived"))
			return
		}
		http.Redirect(w, r, "/r/"+strconv.Itoa(n-1), http.StatusFound)
	})
	plain := httptest.NewServer(mux)
	defer plain.Close()
	tlsMux := http.NewServeMux()
	tlsMux.Handle("/", mux)
	tlsMux.HandleFunc("/toplain", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
	})
	secure := httptest.NewTLSServer(tlsMux)
	defer secure.Close()

	get := func(name, u string, max int64, https bool) ([]byte, error) {
		var body []byte
		var err error
		try(t, name, func() { body, err = httpGet(u, max, https) })
		return body, err
	}
	if b, err := get("http without https required", plain.URL+"/ok", 10, false); err != nil || string(b) != "0123456789" {
		t.Errorf("plain: %q %v", b, err)
	}
	_, err := get("http with https required", plain.URL+"/ok", 10, true)
	wantErr(t, "http with https required", err, nil, "refusing to fetch")
	transport = secure.Client().Transport
	if b, err := get("https", secure.URL+"/ok", 10, true); err != nil || string(b) != "0123456789" {
		t.Errorf("https: %q %v", b, err)
	}
	if b, err := get("https redirected within https", secure.URL+"/r/2", 10, true); err != nil || string(b) != "arrived" {
		t.Errorf("https to https: %q %v", b, err)
	}
	_, err = get("https redirected away", secure.URL+"/toplain", 10, true)
	wantErr(t, "https redirected away", err, nil, "redirect away from https")
	transport = nil

	_, err = get("a 404", plain.URL+"/404", 10, false)
	wantErr(t, "a 404", err, nil, "404 Not Found")
	_, err = get("over the bound", plain.URL+"/ok", 9, false)
	wantErr(t, "over the bound", err, ErrTooLarge, "over 9 bytes")
	_, err = get("a body cut short", plain.URL+"/cut", 1000, false)
	wantErr(t, "a body cut short", err, nil, "unexpected EOF")
	if b, err := get("four redirects", plain.URL+"/r/4", 10, false); err != nil || string(b) != "arrived" {
		t.Errorf("four redirects: %q %v", b, err)
	}
	_, err = get("five redirects", plain.URL+"/r/5", 10, false)
	wantErr(t, "five redirects", err, nil, "too many redirects")

	dead := plain.URL
	plain.Close()
	_, err = get("a closed server", dead+"/ok", 10, false)
	wantErr(t, "a closed server", err, nil, "refused")
}
