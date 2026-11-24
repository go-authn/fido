// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mds

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// crl returns the CRL fetcher: the option, else HTTP.
func (o Options) crl() func(string) ([]byte, error) {
	if o.CRL != nil {
		return o.CRL
	}
	return func(u string) ([]byte, error) { return httpGet(u, MaxCRLBytes, false) }
}

// httpGet downloads u, reading at most max bytes and refusing more. With
// secure, only https is fetched and a redirect may not leave it; without,
// http is allowed too: CRLs are signed and the CAs serve them over http
// (RFC 5280 4.2.1.13), whereas the blob's authenticity does not depend on
// the transport but https is still the right default for it.
func httpGet(u string, max int64, secure bool) ([]byte, error) {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "https" && (secure || p.Scheme != "http")) {
		return nil, fmt.Errorf("mds: refusing to fetch %q", u)
	}
	c := &http.Client{
		Timeout: 3 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("mds: too many redirects")
			}
			if secure && req.URL.Scheme != "https" {
				return errors.New("mds: redirect away from https")
			}
			return nil
		},
	}
	resp, err := c.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mds: %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%w: %s is over %d bytes", ErrTooLarge, u, max)
	}
	return body, nil
}

// checkRevocation applies 3.2 ("all certificates MUST be checked for
// revocation") to one verified chain, leaf first, root last. The root is
// the trust anchor and has no issuer to revoke it. For each other
// certificate at least one of its CRL distribution points must yield a CRL
// that is signed by the certificate's issuer, current at now, and does not
// list its serial. No distribution point, or none that answers validly, is
// a refusal.
func checkRevocation(chain []*x509.Certificate, now time.Time, fetch func(string) ([]byte, error)) error {
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		if len(cert.CRLDistributionPoints) == 0 {
			return unverified("%s has no CRL distribution point, revocation cannot be checked", cert.Subject)
		}
		var last error
		ok := false
		for _, u := range cert.CRLDistributionPoints {
			der, err := fetch(u)
			if err != nil {
				last = err
				continue
			}
			revoked, err := crlRevokes(der, cert, issuer, now)
			if err != nil {
				last = err
				continue
			}
			if revoked {
				return unverified("%s is revoked (CRL %s)", cert.Subject, u)
			}
			ok = true
			break
		}
		if !ok {
			return unverified("no valid CRL for %s: %v", cert.Subject, last)
		}
	}
	return nil
}

// crlRevokes parses a CRL, checks its signature under the issuer and its
// window at now, and reports whether cert's serial is on it.
func crlRevokes(der []byte, cert, issuer *x509.Certificate, now time.Time) (bool, error) {
	l, err := x509.ParseRevocationList(der)
	if err != nil {
		return false, err
	}
	if err = l.CheckSignatureFrom(issuer); err != nil {
		return false, fmt.Errorf("CRL signature: %w", err)
	}
	if l.NextUpdate.IsZero() {
		return false, errors.New("CRL has no nextUpdate")
	}
	if now.Before(l.ThisUpdate) || !now.Before(l.NextUpdate) {
		return false, fmt.Errorf("CRL not current (%s to %s)", l.ThisUpdate.Format(time.DateOnly), l.NextUpdate.Format(time.DateOnly))
	}
	for _, e := range l.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}
	return false, nil
}
