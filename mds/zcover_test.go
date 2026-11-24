// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package mds

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultFetchersUseHTTP(t *testing.T) {
	old := transport
	t.Cleanup(func() { transport = old })
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("body")) }))
	defer srv.Close()
	transport = srv.Client().Transport

	c := &Client{URL: srv.URL}
	if b, err := c.get(c.url()); err != nil || string(b) != "body" {
		t.Errorf("Client.get: %q %v", b, err)
	}
	if b, err := (Options{}).crl()(srv.URL); err != nil || string(b) != "body" {
		t.Errorf("Options.crl: %q %v", b, err)
	}
}

func TestOptionsClockAndRoot(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := (Options{Now: func() time.Time { return at }}).now(); !got.Equal(at) {
		t.Errorf("now = %v", got)
	}
	if time.Since((Options{}).now()) > time.Minute {
		t.Error("the default clock is not the wall clock")
	}
	if Root().Subject.CommonName != "GlobalSign Root R46" {
		t.Error("Root is not R46")
	}
	old := rootR46DER
	t.Cleanup(func() { rootR46DER = old })
	rootR46DER = []byte("another root")
	defer func() {
		if recover() == nil {
			t.Error("Root accepted bytes that are not R46")
		}
	}()
	Root()
}
