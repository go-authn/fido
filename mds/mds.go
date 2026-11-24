// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package mds reads the FIDO Metadata Service (MDS3) blob and tells what a
// FIDO authenticator is from its AAGUID.
//
// Spec: FIDO Metadata Service v3.0 Proposed Standard 2021-05-18,
// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
// (section 3.1.6 payload, 3.1.7 JWT, 3.2 processing rules).
//
// A blob is never used unverified. There is no switch that turns the
// verification off: Verify returns a Blob only when
//
//   - the JWS header is RS256 or ES256 and carries an x5c chain (3.2: "if the
//     x5u attribute is missing, the chain should be retrieved from the x5c
//     attribute"; x5u is never fetched);
//   - the signature over header.payload verifies under the x5c leaf;
//   - the chain verifies against the pinned GlobalSign Root R46 (RFC 5280) at
//     the time asked for, and the leaf is valid for mds.fidoalliance.org: the
//     leaf is a TLS certificate, so without that check any certificate that
//     chains to GlobalSign could sign a blob;
//   - no certificate of the chain is revoked: each one's CRL distribution
//     points are fetched, their signature and validity window checked, and
//     the serial looked up ("all certificates MUST be checked for
//     revocation", 3.2). A certificate without a reachable, valid CRL is a
//     refusal: the check fails closed;
//   - nextUpdate has not passed.
//
// The pinned root is the one the FIDO Alliance names at
// https://fidoalliance.org/metadata/ ("The GlobalSign R46 root certificate is
// required to verify the BLOB's digital signature"), downloaded from
// http://secure.globalsign.com/cacert/rootr46.crt; its serial and SHA-1
// match the GlobalSign root list. Its SHA-256 is asserted in RootSHA256.
package mds

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RootSHA256 is the SHA-256 of the DER of GlobalSign Root R46
// (C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46; valid 2019-03-20 to
// 2046-03-20; serial 11D2BBB9D723189E405F0A9D2DD0DF2567D1).
const RootSHA256 = "4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9"

// RootSHA1 is the SHA-1 of the same certificate, the fingerprint GlobalSign
// lists for "TLS Root R46" on its root certificate page.
const RootSHA1 = "53a2b04bca6bd645e6398a8ec40dd2bf77c3a290"

//go:embed globalsign-root-r46.der
var rootR46DER []byte

// Limits. They are stated, not discovered: the real blob is about 11.4 MB
// (2026-11), so 64 MiB is a margin of more than five times, and nothing
// else a server sends is allowed to grow past its own bound.
const (
	// MaxBlobBytes bounds the downloaded JWS, in bytes.
	MaxBlobBytes = 64 << 20
	// MaxCRLBytes bounds one downloaded CRL.
	MaxCRLBytes = 16 << 20
	// MaxChain bounds the x5c chain length.
	MaxChain = 8
	// MaxEntries bounds the number of entries accepted from a payload.
	MaxEntries = 100000
	// Hostname is the name the leaf certificate must be valid for.
	Hostname = "mds.fidoalliance.org"
	// DefaultURL is the well-known blob location (3.2).
	DefaultURL = "https://mds3.fidoalliance.org/"
)

// Errors. Verification failures wrap ErrUnverified, so that a caller can
// tell "do not trust this" from "could not fetch it".
var (
	ErrUnverified = errors.New("mds: blob not verified")
	ErrMalformed  = errors.New("mds: malformed blob")
	ErrTooLarge   = errors.New("mds: blob too large")
	ErrExpired    = errors.New("mds: blob past its nextUpdate")
	ErrRollback   = errors.New("mds: blob older than the cached one")
)

func unverified(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnverified, fmt.Sprintf(format, a...))
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// Root returns the pinned GlobalSign Root R46 certificate. It panics if the
// embedded bytes are not the certificate named by RootSHA256 (a build that
// carries another root must not run).
func Root() *x509.Certificate {
	sum := sha256.Sum256(rootR46DER)
	if hex.EncodeToString(sum[:]) != RootSHA256 {
		panic("mds: embedded root is not GlobalSign Root R46")
	}
	c, err := x509.ParseCertificate(rootR46DER)
	if err != nil {
		panic("mds: embedded root: " + err.Error())
	}
	return c
}

// Options are the library-level knobs of Verify. The zero value is the real
// service: the pinned root, mds.fidoalliance.org, the clock, and CRLs fetched
// over HTTP. The command line exposes none of them.
type Options struct {
	// Roots replaces the pinned root. For tests and private deployments.
	Roots *x509.CertPool
	// Hostname replaces the name the leaf must be valid for.
	Hostname string
	// Now replaces the clock.
	Now func() time.Time
	// CRL returns the DER of the CRL at url. nil means HTTP with
	// MaxCRLBytes. It need not validate: Verify does.
	CRL func(url string) ([]byte, error)
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Blob is a verified MDS3 payload (3.1.6).
type Blob struct {
	LegalHeader string `json:"legalHeader"`
	// No is the serial number of the blob; it only grows (3.2).
	No int `json:"no"`
	// NextUpdate is the date by which the next blob appears.
	NextUpdateDate string  `json:"nextUpdate"`
	Entries        []Entry `json:"entries"`

	next time.Time
}

// NextUpdate is the instant the blob stops being valid: the END of the day
// named by nextUpdate, in UTC ("the date when the next update will be
// provided at latest").
func (b *Blob) NextUpdate() time.Time { return b.next }

// Entry is one authenticator model (3.1.1).
type Entry struct {
	AAGUID                               string         `json:"aaguid"`
	MetadataStatement                    *Statement     `json:"metadataStatement"`
	StatusReports                        []StatusReport `json:"statusReports"`
	TimeOfLastStatusChange               string         `json:"timeOfLastStatusChange"`
	AttestationCertificateKeyIdentifiers []string       `json:"attestationCertificateKeyIdentifiers"`
}

// Statement is the metadata statement of an entry. Only the fields this
// library uses are decoded; the others are ignored.
type Statement struct {
	Description                 string                 `json:"description"`
	AuthenticatorVersion        uint32                 `json:"authenticatorVersion"`
	ProtocolFamily              string                 `json:"protocolFamily"`
	Upv                         []map[string]int       `json:"upv"`
	AttestationTypes            []string               `json:"attestationTypes"`
	KeyProtection               []string               `json:"keyProtection"`
	MatcherProtection           []string               `json:"matcherProtection"`
	UserVerificationDetails     [][]VerificationMethod `json:"userVerificationDetails"`
	AttestationRootCertificates []string               `json:"attestationRootCertificates"`
}

// VerificationMethod is one user verification method descriptor.
type VerificationMethod struct {
	UserVerificationMethod string `json:"userVerificationMethod"`
}

// StatusReport is one status of an entry (3.1.3), the certification history.
type StatusReport struct {
	Status                           string `json:"status"`
	EffectiveDate                    string `json:"effectiveDate"`
	AuthenticatorVersion             uint32 `json:"authenticatorVersion"`
	Certificate                      string `json:"certificate"`
	URL                              string `json:"url"`
	CertificationDescriptor          string `json:"certificationDescriptor"`
	CertificateNumber                string `json:"certificateNumber"`
	CertificationPolicyVersion       string `json:"certificationPolicyVersion"`
	CertificationRequirementsVersion string `json:"certificationRequirementsVersion"`
}

// RootCertificates parses attestationRootCertificates: the trust anchors an
// attestation statement from this model must chain to. It is what a relying
// party feeds to its attestation verifier once the AAGUID is known.
func (e *Entry) RootCertificates() ([]*x509.Certificate, error) {
	if e.MetadataStatement == nil {
		return nil, nil
	}
	var out []*x509.Certificate
	for i, s := range e.MetadataStatement.AttestationRootCertificates {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, malformed("attestationRootCertificates[%d]: %v", i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, malformed("attestationRootCertificates[%d]: %v", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// Description is the model's name, or "" when the entry has no statement.
func (e *Entry) Description() string {
	if e.MetadataStatement == nil {
		return ""
	}
	return e.MetadataStatement.Description
}

// NormalizeAAGUID returns the canonical lowercase dashed form of a 16-byte
// AAGUID given with or without dashes, or false.
func NormalizeAAGUID(s string) (string, bool) {
	h := strings.ToLower(strings.ReplaceAll(s, "-", ""))
	if len(h) != 32 {
		return "", false
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", false
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], true
}

// Lookup finds an entry by AAGUID (any dash form, any case), or nil.
func (b *Blob) Lookup(aaguid string) *Entry {
	want, ok := NormalizeAAGUID(aaguid)
	if !ok {
		return nil
	}
	for i := range b.Entries {
		if got, ok := NormalizeAAGUID(b.Entries[i].AAGUID); ok && got == want {
			return &b.Entries[i]
		}
	}
	return nil
}

// Search returns the entries whose description or AAGUID contains word,
// ignoring case, in blob order.
func (b *Blob) Search(word string) []*Entry {
	w := strings.ToLower(strings.TrimSpace(word))
	if w == "" {
		return nil
	}
	var out []*Entry
	for i := range b.Entries {
		e := &b.Entries[i]
		if strings.Contains(strings.ToLower(e.Description()), w) || strings.Contains(strings.ToLower(e.AAGUID), w) {
			out = append(out, e)
		}
	}
	return out
}

// jwsHeader is the protected header of 3.1.7.
type jwsHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	X5C []string `json:"x5c"`
	X5U string   `json:"x5u"`
}

// splitJWS cuts a compact JWS into its parts, with the signing input.
func splitJWS(blob []byte) (hdr jwsHeader, payload, sig []byte, signed string, err error) {
	if len(blob) > MaxBlobBytes {
		return hdr, nil, nil, "", ErrTooLarge
	}
	s := strings.TrimSpace(string(blob))
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return hdr, nil, nil, "", malformed("not a compact JWS (%d parts)", len(parts))
	}
	dec := base64.RawURLEncoding.Strict()
	h, err := dec.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, nil, "", malformed("header: %v", err)
	}
	if err = json.Unmarshal(h, &hdr); err != nil {
		return hdr, nil, nil, "", malformed("header: %v", err)
	}
	if payload, err = dec.DecodeString(parts[1]); err != nil {
		return hdr, nil, nil, "", malformed("payload: %v", err)
	}
	if sig, err = dec.DecodeString(parts[2]); err != nil {
		return hdr, nil, nil, "", malformed("signature: %v", err)
	}
	return hdr, payload, sig, parts[0] + "." + parts[1], nil
}

// parsePayload decodes 3.1.6. It checks shape only; Verify decides trust.
func parsePayload(payload []byte) (*Blob, error) {
	var b Blob
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, malformed("payload: %v", err)
	}
	if len(b.Entries) > MaxEntries {
		return nil, malformed("%d entries (bound %d)", len(b.Entries), MaxEntries)
	}
	d, err := time.Parse(time.DateOnly, b.NextUpdateDate)
	if err != nil {
		return nil, malformed("nextUpdate %q: %v", b.NextUpdateDate, err)
	}
	b.next = d.AddDate(0, 0, 1)
	if b.No < 0 {
		return nil, malformed("no %d", b.No)
	}
	return &b, nil
}

// ParseUnverified decodes a blob WITHOUT verifying anything. It exists for
// the fuzz target and for reading the serial of a cached file; never use its
// result as metadata.
func parseUnverified(blob []byte) (*Blob, error) {
	_, payload, _, _, err := splitJWS(blob)
	if err != nil {
		return nil, err
	}
	return parsePayload(payload)
}

// verifySignature checks the JWS signature under the leaf's public key.
func verifySignature(alg string, leaf *x509.Certificate, signed string, sig []byte) error {
	sum := sha256.Sum256([]byte(signed))
	switch alg {
	case "RS256":
		k, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return unverified("alg RS256 but the leaf key is %T", leaf.PublicKey)
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig); err != nil {
			return unverified("signature: %v", err)
		}
	case "ES256":
		k, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || k.Curve.Params().BitSize != 256 {
			return unverified("alg ES256 but the leaf key is %T", leaf.PublicKey)
		}
		if len(sig) != 64 {
			return unverified("ES256 signature of %d bytes", len(sig))
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, sum[:], r, s) {
			return unverified("signature: ES256 does not verify")
		}
	default:
		return unverified("alg %q (only RS256 and ES256 are accepted)", alg)
	}
	return nil
}

// Verify checks a downloaded blob as the package comment lists and returns
// it. Any failure is an error that wraps ErrUnverified, ErrMalformed,
// ErrTooLarge or ErrExpired; no partial result is returned.
func Verify(blob []byte, o Options) (*Blob, error) {
	hdr, payload, sig, signed, err := splitJWS(blob)
	if err != nil {
		return nil, err
	}
	if n := len(hdr.X5C); n == 0 {
		return nil, unverified("no x5c chain in the header (x5u is not followed)")
	} else if n > MaxChain {
		return nil, unverified("x5c chain of %d certificates (bound %d)", n, MaxChain)
	}
	certs := make([]*x509.Certificate, len(hdr.X5C))
	for i, s := range hdr.X5C {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, unverified("x5c[%d]: %v", i, err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, unverified("x5c[%d]: %v", i, err)
		}
	}
	if err = verifySignature(hdr.Alg, certs[0], signed, sig); err != nil {
		return nil, err
	}
	now := o.now()
	roots := o.Roots
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AddCert(Root())
	}
	host := o.Hostname
	if host == "" {
		host = Hostname
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		DNSName:       host,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, unverified("chain: %v", err)
	}
	var revErr error
	for _, chain := range chains {
		if revErr = checkRevocation(chain, now, o.crl()); revErr == nil {
			break
		}
	}
	if revErr != nil {
		return nil, revErr
	}
	b, err := parsePayload(payload)
	if err != nil {
		return nil, err
	}
	if !now.Before(b.next) {
		return nil, fmt.Errorf("%w: nextUpdate %s", ErrExpired, b.NextUpdateDate)
	}
	return b, nil
}
