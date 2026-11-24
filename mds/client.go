// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mds

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Client fetches the blob and keeps it in a directory, for as long as its
// nextUpdate allows (3.2: the blob is downloaded again once nextUpdate has
// passed). The cached bytes are verified again on every load, so a cache
// that was tampered with, or whose certificates have since been revoked or
// have expired, is ignored rather than trusted.
type Client struct {
	// Dir holds the cache. It is created with mode 0700; files are 0600.
	Dir string
	// URL is the blob location. Empty means DefaultURL. Only https.
	URL string
	// Options are the verification options (library-level; see Options).
	Options Options
	// Fetch replaces the HTTP download of the blob (tests).
	Fetch func(url string) ([]byte, error)
}

const blobFile = "mds3.jwt"

func (c *Client) url() string {
	if c.URL != "" {
		return c.URL
	}
	return DefaultURL
}

func (c *Client) get(u string) ([]byte, error) {
	if c.Fetch != nil {
		return c.Fetch(u)
	}
	return httpGet(u, MaxBlobBytes, true)
}

// Load returns a verified blob: the cached one while it verifies, else a
// downloaded one, which is stored. refresh forces the download. A download
// whose serial number is lower than the cached blob's is refused (3.2).
func (c *Client) Load(ctx context.Context, refresh bool) (*Blob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o := c.Options
	o.CRL = c.crlSource(o)
	cached := c.readCached(o)
	if cached != nil && !refresh {
		return cached, nil
	}
	raw, err := c.get(c.url())
	if err != nil {
		return nil, fmt.Errorf("mds: downloading the blob: %w", err)
	}
	b, err := Verify(raw, o)
	if err != nil {
		return nil, err
	}
	if cached != nil && b.No < cached.No {
		return nil, fmt.Errorf("%w: no %d < %d", ErrRollback, b.No, cached.No)
	}
	if err := c.store(blobFile, raw); err != nil {
		return nil, err
	}
	return b, nil
}

// readCached returns the cached blob if it verifies now, else nil.
func (c *Client) readCached(o Options) *Blob {
	raw, err := os.ReadFile(filepath.Join(c.Dir, blobFile))
	if err != nil || len(raw) > MaxBlobBytes {
		return nil
	}
	b, err := Verify(raw, o)
	if err != nil {
		return nil
	}
	return b
}

func (c *Client) store(name string, data []byte) error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(c.Dir, name+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(c.Dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// crlSource wraps the CRL fetcher with the cache: a stored CRL is used while
// its nextUpdate has not passed (the caller still verifies its signature),
// else the CRL is downloaded and stored.
func (c *Client) crlSource(o Options) func(string) ([]byte, error) {
	fetch := o.crl()
	return func(u string) ([]byte, error) {
		sum := sha256.Sum256([]byte(u))
		name := "crl-" + hex.EncodeToString(sum[:8]) + ".der"
		if der, err := os.ReadFile(filepath.Join(c.Dir, name)); err == nil && len(der) <= MaxCRLBytes {
			if l, err := x509.ParseRevocationList(der); err == nil && !l.NextUpdate.IsZero() && o.now().Before(l.NextUpdate) {
				return der, nil
			}
		}
		der, err := fetch(u)
		if err != nil {
			return nil, err
		}
		if _, err := x509.ParseRevocationList(der); err == nil {
			_ = c.store(name, der)
		}
		return der, nil
	}
}

// StaleAfter is how long the cached blob stays good: the time left to its
// nextUpdate, or zero.
func (b *Blob) StaleAfter(now time.Time) time.Duration {
	if d := b.next.Sub(now); d > 0 {
		return d
	}
	return 0
}
