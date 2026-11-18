// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestCredMgmtModeFollowsTheOptions(t *testing.T) {
	for name, c := range map[string]struct {
		opts map[string]bool
		want CredMgmtMode
	}{
		"none":            {map[string]bool{"rk": true}, CredMgmtUnsupported},
		"credMgmt true":   {map[string]bool{"credMgmt": true}, CredMgmtFinal},
		"credMgmt false":  {map[string]bool{"credMgmt": false}, CredMgmtFinal},
		"preview":         {map[string]bool{"credentialMgmtPreview": true}, CredMgmtPreview},
		"final over both": {map[string]bool{"credMgmt": true, "credentialMgmtPreview": true}, CredMgmtFinal},
	} {
		if got := (Info{Options: c.opts}).CredMgmtMode(); got != c.want {
			t.Errorf("%s: %v want %v", name, got, c.want)
		}
	}
	_, k, info := namedKey(t, "")
	if _, err := k.CredMgmt(info); err == nil || !strings.Contains(err.Error(), "does not declare credential management") {
		t.Errorf("%v", err)
	}
	_, k, info = namedKey(t, "credMgmt")
	cm, err := k.CredMgmt(info)
	if err != nil || cm.Permissions() != PermCredentialManagement {
		t.Errorf("%v %v", cm, err)
	}
	_, k, info = namedKey(t, "credentialMgmtPreview")
	if cm, _ = k.CredMgmt(info); cm.Permissions() != 0 {
		t.Errorf("a prototype key was given permissions")
	}
}

func TestCredentialsAreListedWithTheirUsers(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "credMgmt")
	cm, _ := k.CredMgmt(info)
	tok := cmToken(t, k, info)
	if got, err := cm.Credentials(ctx, tok, NameRP); err != nil || got != nil {
		t.Fatalf("none: %v %v", got, err)
	}
	for _, n := range []string{"a", "b", "c"} {
		v.creds = append(v.creds, vcred([]byte("id-"+n), NameRP, []byte(n), 1))
	}
	got, err := cm.Credentials(ctx, tok, NameRP)
	if err != nil || len(got) != 3 || string(got[0].User.ID) != "a" || string(got[2].ID) != "id-c" || got[1].User.Name != "b" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestCredentialManagementRefusals(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "credMgmt")
	cm, _ := k.CredMgmt(info)
	tok := cmToken(t, k, info)
	var se *StatusError
	// No token, a wrong one, and one bound to a relying party.
	if _, err := cm.Credentials(ctx, Token{}, NameRP); err == nil || !strings.Contains(err.Error(), "needs a token") {
		t.Errorf("no token: %v", err)
	}
	if err := cm.Delete(ctx, Token{}, []byte("x")); err == nil {
		t.Error("delete with no token")
	}
	bound, err := k.PINToken(ctx, "1234", PINProtocolTwo, PermCredentialManagement, NameRP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cm.Credentials(ctx, bound, NameRP); !errors.As(err, &se) || se.Status != 0x33 {
		t.Errorf("a token bound to a relying party: %v", err)
	}
	weak, _ := k.PINToken(ctx, "1234", PINProtocolTwo, PermGetAssertion, "")
	if _, err := cm.Credentials(ctx, weak, NameRP); !errors.As(err, &se) || se.Status != 0x33 {
		t.Errorf("a token without cm: %v", err)
	}
	// Delete: empty id, unknown id.
	tok, _ = k.PINToken(ctx, "1234", PINProtocolTwo, PermCredentialManagement, "")
	if err := cm.Delete(ctx, tok, nil); err == nil || !strings.Contains(err.Error(), "needs an id") {
		t.Errorf("%v", err)
	}
	if err := cm.Delete(ctx, tok, []byte("nope")); !errors.As(err, &se) || se.Status != StatusNoCredentials {
		t.Errorf("unknown id: %v", err)
	}
	// Too many for one relying party.
	for i := 0; i <= maxManagedPerRP; i++ {
		v.creds = append(v.creds, vcred([]byte{byte(i), byte(i >> 8), 1}, NameRP, []byte("n"), 1))
	}
	if _, err := cm.Credentials(ctx, tok, NameRP); err == nil || !strings.Contains(err.Error(), "at most 256") {
		t.Errorf("a flood: %v", err)
	}
	// A key that cannot speak CTAP2.
	dead := &CredMgmt{k: ctap2Key(t, CapWink, func(byte, []byte) []byte { return []byte{0} }), cmd: CmdCredentialManagement}
	if _, err := dead.Credentials(ctx, tok, NameRP); err == nil || !strings.Contains(err.Error(), "does not speak CTAP2") {
		t.Errorf("%v", err)
	}
	// An unencodable parameter is not sent.
	if _, err := cm.call(ctx, tok, cmEnumerateCredentialsBegin, map[int]any{1: make(chan int)}); err == nil || !strings.Contains(err.Error(), "cannot encode") {
		t.Errorf("%v", err)
	}
	// An unknown subcommand, as the key answers it.
	if _, err := cm.call(ctx, tok, 0x42, nil); !errors.As(err, &se) || se.Status != 0x3e {
		t.Errorf("%v", err)
	}
}

func TestManagedCredentialRepliesThatAreNotWhatTheyClaim(t *testing.T) {
	ok := map[uint64]any{
		cmrUser:         map[string]any{"id": []byte("u"), "name": "n"},
		cmrCredentialID: map[string]any{"id": []byte{1}, "type": "public-key"},
		cmrTotalCreds:   2,
	}
	with := func(f func(map[uint64]any)) map[uint64]any {
		m := map[uint64]any{}
		for k, v := range ok {
			m[k] = v
		}
		f(m)
		return m
	}
	for name, c := range map[string]struct {
		m     map[uint64]any
		begin bool
	}{
		"no user":      {with(func(m map[uint64]any) { delete(m, cmrUser) }), true},
		"user too big": {with(func(m map[uint64]any) { m[cmrUser] = map[string]any{"id": make([]byte, 65)} }), true},
		"no cred id":   {with(func(m map[uint64]any) { delete(m, cmrCredentialID) }), true},
		"empty cred id": {with(func(m map[uint64]any) {
			m[cmrCredentialID] = map[string]any{"id": []byte{}}
		}), true},
		"no total":   {with(func(m map[uint64]any) { delete(m, cmrTotalCreds) }), true},
		"zero total": {with(func(m map[uint64]any) { m[cmrTotalCreds] = 0 }), true},
	} {
		if _, _, err := parseManaged(cborOf(t, c.m), c.begin); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := parseManaged(cborOf(t, "x"), true); err == nil {
		t.Error("a non-map accepted")
	}
	// A follow-up reply has no total.
	m, total, err := parseManaged(cborOf(t, with(func(m map[uint64]any) { delete(m, cmrTotalCreds) })), false)
	if err != nil || total != 0 || string(m.User.ID) != "u" || m.User.Name != "n" || m.ID[0] != 1 {
		t.Errorf("%+v %d %v", m, total, err)
	}
}

// wrapped is a key whose credential management answers come from override
// (nil falls through to the virtual key), so a reply can be made wrong.
func wrapped(t *testing.T, v *virtualAuthenticator, override func(cmd byte, params []byte) []byte) *Key {
	t.Helper()
	return ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd == CmdCredentialManagement && override != nil {
			if r := override(cmd, params); r != nil {
				return r
			}
		}
		return v.reply(cmd, params)
	})
}

func TestAnEnumerationThatGoesWrongIsAnError(t *testing.T) {
	ctx := context.Background()
	v := newVirtualAuthenticator(t, "1234")
	v.cmOption = "credMgmt"
	v.creds = append(v.creds, vcred([]byte("1"), NameRP, []byte("a"), 1), vcred([]byte("2"), NameRP, []byte("b"), 1))
	nextCalls := 0
	k := wrapped(t, v, func(cmd byte, params []byte) []byte {
		var req map[uint64]cbor.RawMessage
		_ = cbor.Unmarshal(params, &req)
		var sub int
		_ = cbor.Unmarshal(req[cmSub], &sub)
		switch {
		case sub == cmEnumerateCredentialsBegin && v.breakBegin:
			return append([]byte{0}, cborOf(t, "not a map")...)
		case sub == cmDeleteCredential && v.breakDelete:
			return []byte{0x33}
		case sub == cmEnumerateCredentialsNext && v.breakNext == 1:
			return []byte{0x2E}
		case sub == cmEnumerateCredentialsNext && v.breakNext == 2:
			nextCalls++
			return append([]byte{0}, cborOf(t, "not a map")...)
		}
		return nil
	})
	info, _ := k.GetInfo(ctx)
	cm, _ := k.CredMgmt(info)
	tok, err := k.PINToken(ctx, "1234", PINProtocolTwo, PermCredentialManagement, "")
	if err != nil {
		t.Fatal(err)
	}
	v.breakBegin = true
	if _, err := cm.Credentials(ctx, tok, NameRP); err == nil {
		t.Error("a begin reply that is not a map")
	}
	v.breakBegin = false
	v.breakNext = 1
	if _, err := cm.Credentials(ctx, tok, NameRP); err == nil {
		t.Error("a next call refused")
	}
	v.breakNext = 2
	if _, err := cm.Credentials(ctx, tok, NameRP); err == nil || nextCalls != 1 {
		t.Errorf("a next reply that is not a map: %v", err)
	}
	// deleteAll surfaces the enumeration's failure, as SetName does.
	v.breakNext = 1
	if err := k.RemoveName(ctx, nameTokens(t, k, info)); err == nil {
		t.Error("RemoveName ignored a failing enumeration")
	}
	// ...and a failing delete.
	v.breakNext, v.breakDelete = 0, true
	if err := k.RemoveName(ctx, nameTokens(t, k, info)); err == nil {
		t.Error("RemoveName ignored a failing delete")
	}
}
