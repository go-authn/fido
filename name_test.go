// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// namedKey is a virtual key with credential management and a PIN, and its
// info.
func namedKey(t *testing.T, cm string) (*virtualAuthenticator, *Key, Info) {
	t.Helper()
	v := newVirtualAuthenticator(t, "1234")
	v.cmOption = cm
	k := virtualKey(t, v)
	info, err := k.GetInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v, k, info
}

func nameTokens(t *testing.T, k *Key, info Info) NameTokens {
	t.Helper()
	tok, err := k.NameTokens(context.Background(), "1234", PINProtocolTwo, info)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func nameCreds(v *virtualAuthenticator) (out []*virtualCredential) {
	for _, c := range v.creds {
		if c.rp == NameRP {
			out = append(out, c)
		}
	}
	return out
}

func TestCheckName(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want string
	}{
		"plain":          {"desk key", ""},
		"unicode":        {"clé du bureau — ✓", ""},
		"64 bytes":       {strings.Repeat("a", 64), ""},
		"65 bytes":       {strings.Repeat("a", 65), "the most a key stores is 64"},
		"multibyte long": {strings.Repeat("é", 33), "the most a key stores is 64"},
		"empty":          {"", "cannot be empty"},
		"not utf-8":      {"a\xffb", "valid UTF-8"},
		"newline":        {"a\nb", "control or invisible"},
		"escape":         {"a\x1b[31m", "control or invisible"},
		"zero width":     {"a​b", "control or invisible"},
		"right-to-left":  {"a‮b", "control or invisible"},
	} {
		err := CheckName(c.in)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if n, err := DecodeName([]byte("desk key")); err != nil || n != "desk key" {
		t.Errorf("%q %v", n, err)
	}
	if _, err := DecodeName([]byte("a\x00b")); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Errorf("a stored name with a NUL: %v", err)
	}
}

func TestANameIsSetAndReadWithoutTouchOrPIN(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "credMgmt")
	if _, err := k.ReadName(ctx); !errors.Is(err, ErrNoName) {
		t.Fatalf("before: %v", err)
	}
	if err := k.SetName(ctx, "desk key", nameTokens(t, k, info)); err != nil {
		t.Fatal(err)
	}
	cs := nameCreds(v)
	if len(cs) != 1 || string(cs[0].userID) != "desk key" || !cs[0].discovered || cs[0].protect != 1 {
		t.Fatalf("credential %+v", cs)
	}
	// The read: a getAssertion with no token (no PIN) and "up" false (no touch).
	v.asked = nil
	got, err := k.ReadName(ctx)
	if err != nil || got != "desk key" {
		t.Fatalf("%q %v", got, err)
	}
	if !slices.Equal(v.asked, []string{"getAssertion"}) {
		t.Errorf("the read asked %v", v.asked)
	}
}

func TestRenamingLeavesOneCredential(t *testing.T) {
	ctx := context.Background()
	for _, cm := range []string{"credMgmt", "credentialMgmtPreview"} {
		v, k, info := namedKey(t, cm)
		for _, n := range []string{"first", "second", "third"} {
			if err := k.SetName(ctx, n, nameTokens(t, k, info)); err != nil {
				t.Fatalf("%s %s: %v", cm, n, err)
			}
			if got := nameCreds(v); len(got) != 1 || string(got[0].userID) != n {
				t.Fatalf("%s after %q: %d credentials", cm, n, len(got))
			}
		}
		if got, _ := k.ReadName(ctx); got != "third" {
			t.Errorf("%s: %q", cm, got)
		}
	}
}

func TestAnAlwaysUVKeyStillAnswersTheSilentRead(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "credMgmt")
	v.alwaysUv = true
	info, _ = k.GetInfo(ctx)
	if !info.Has("alwaysUv") {
		t.Fatal("the fake does not say alwaysUv")
	}
	// Making a credential needs verification (7.2.3): with no token it is refused.
	err := k.SetName(ctx, "bio", NameTokens{})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 0x36 {
		t.Fatalf("unverified make: %v", err)
	}
	if err := k.SetName(ctx, "bio", nameTokens(t, k, info)); err != nil {
		t.Fatal(err)
	}
	// An ordinary getAssertion (up true) with no token is refused too...
	if _, err := k.GetAssertion(ctx, GetAssertionRequest{RPID: NameRP, ClientDataHash: make([]byte, 32)}); !errors.As(err, &se) || se.Status != 0x36 {
		t.Fatalf("up=true with no UV: %v", err)
	}
	// ...but the silent read, up=false, is not (6.2.2 step 5).
	if got, err := k.ReadName(ctx); err != nil || got != "bio" {
		t.Fatalf("silent read: %q %v", got, err)
	}
}

func TestAKeyThatRefusesTheSilentReadIsToldApart(t *testing.T) {
	v, k, info := namedKey(t, "credMgmt")
	if err := k.SetName(context.Background(), "x", nameTokens(t, k, info)); err != nil {
		t.Fatal(err)
	}
	v.refuseSilent = true
	_, err := k.ReadName(context.Background())
	var se *StatusError
	if !errors.Is(err, ErrNameRefused) || !errors.As(err, &se) || se.Status != StatusOperationDenied {
		t.Errorf("%v", err)
	}
	// A key with a name it will not show cannot be renamed without credential
	// management either: refused, nothing changed.
	v2, k2, info2 := namedKey(t, "")
	_ = info2
	if err := k2.SetName(context.Background(), "a", nameTokens(t, k2, info2)); err != nil {
		t.Fatal(err)
	}
	v2.refuseSilent = true
	if err := k2.SetName(context.Background(), "b", nameTokens(t, k2, info2)); err == nil || !strings.Contains(err.Error(), "cannot delete credentials") {
		t.Errorf("%v", err)
	}
}

func TestReadNameRefusals(t *testing.T) {
	ctx := context.Background()
	v, k, _ := namedKey(t, "credMgmt")
	add := func(id []byte) {
		v.creds = append(v.creds, vcred([]byte{byte(len(v.creds) + 1)}, NameRP, id, 1))
	}
	// Two names: ambiguous, never one picked.
	add([]byte("a"))
	add([]byte("b"))
	if _, err := k.ReadName(ctx); !errors.Is(err, ErrNameAmbiguous) {
		t.Errorf("ambiguous: %v", err)
	}
	// A stored name that is not a name.
	v.creds = nil
	add([]byte("bad\x00name"))
	if _, err := k.ReadName(ctx); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Errorf("corrupt: %v", err)
	}
	// A status that is neither "none" nor "not silently" passes through.
	other := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0x01} })
	if _, err := other.ReadName(ctx); err == nil || errors.Is(err, ErrNameRefused) || errors.Is(err, ErrNoName) {
		t.Errorf("other: %v", err)
	}
	old := randRead
	t.Cleanup(func() { randRead = old })
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := k.ReadName(ctx); err == nil || !strings.Contains(err.Error(), "challenge") {
		t.Errorf("entropy: %v", err)
	}
	if err := k.SetName(ctx, "x", NameTokens{}); err == nil || !strings.Contains(err.Error(), "challenge") {
		t.Errorf("entropy on set: %v", err)
	}
}

func TestSetNameRefusals(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "credMgmt")
	if err := k.SetName(ctx, "", NameTokens{}); err == nil {
		t.Error("an empty name")
	}
	// A bad token: the key's refusal comes back and nothing was deleted.
	if err := k.SetName(ctx, "one", nameTokens(t, k, info)); err != nil {
		t.Fatal(err)
	}
	stale := nameTokens(t, k, info)
	v.token = nil
	if err := k.SetName(ctx, "two", stale); err == nil {
		t.Error("an unauthorised replace")
	}
	if got := nameCreds(v); len(got) != 1 || string(got[0].userID) != "one" {
		t.Errorf("the old name changed: %d", len(got))
	}
	// Making fails after the old one is gone: the key has no name, never two.
	v.alwaysUv = true
	tok := nameTokens(t, k, info)
	tok.MakeCredential = Token{}
	if err := k.SetName(ctx, "three", tok); err == nil {
		t.Error("an unverified make on an alwaysUv key")
	}
	if got := nameCreds(v); len(got) != 0 {
		t.Errorf("%d credentials left", len(got))
	}
	v.alwaysUv = false
	// A policy other than level 1 stored: reported.
	v.protectOverride = 3
	if err := k.SetName(ctx, "four", nameTokens(t, k, info)); err == nil || !strings.Contains(err.Error(), "credProtect level 1") {
		t.Errorf("%v", err)
	}
	// A key that cannot hold a name.
	weak := ctap2Key(t, CapCBOR, func(cmd byte, _ []byte) []byte {
		b, _ := ctap2.Marshal(map[uint64]any{infoVersions: []string{"FIDO_2_0"}, infoOptions: map[string]bool{}})
		return append([]byte{0}, b...)
	})
	if err := weak.SetName(ctx, "x", NameTokens{}); err == nil || !strings.Contains(err.Error(), "cannot store a name") {
		t.Errorf("%v", err)
	}
	broken := ctap2Key(t, CapCBOR, func(byte, []byte) []byte { return []byte{0x01} })
	if err := broken.SetName(ctx, "x", NameTokens{}); err == nil {
		t.Error("getInfo refused")
	}
	if err := broken.RemoveName(ctx, NameTokens{}); err == nil {
		t.Error("getInfo refused on remove")
	}
}

func TestRemoveName(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "credMgmt")
	if err := k.RemoveName(ctx, nameTokens(t, k, info)); err != nil {
		t.Errorf("a key with no name: %v", err)
	}
	k.SetName(ctx, "x", nameTokens(t, k, info))
	// Two stray name credentials too: all go.
	v.creds = append(v.creds, vcred([]byte("z"), NameRP, []byte("y"), 0))
	if err := k.RemoveName(ctx, nameTokens(t, k, info)); err != nil {
		t.Fatal(err)
	}
	if got := nameCreds(v); len(got) != 0 {
		t.Errorf("%d left", len(got))
	}
	if _, err := k.ReadName(ctx); !errors.Is(err, ErrNoName) {
		t.Errorf("%v", err)
	}
	// Other relying parties' credentials are not touched.
	v.creds = append(v.creds, vcred([]byte("w"), "example.test", []byte("u"), 0))
	k.RemoveName(ctx, nameTokens(t, k, info))
	if len(v.creds) != 1 {
		t.Errorf("%d credentials", len(v.creds))
	}
	// A key with no credential management cannot remove.
	_, k2, info2 := namedKey(t, "")
	if err := k2.RemoveName(ctx, nameTokens(t, k2, info2)); err == nil || !strings.Contains(err.Error(), "does not declare credential management") {
		t.Errorf("%v", err)
	}
	// A refusal while deleting.
	v.token = nil
	if err := k.RemoveName(ctx, NameTokens{}); err == nil {
		t.Error("an unauthorised remove")
	}
}

func TestNameTokensByWhatTheKeyDeclares(t *testing.T) {
	ctx := context.Background()
	// Final credential management: two tokens, the first bound to name.fido and
	// the second to no relying party, with the cm permission.
	v, k, info := namedKey(t, "credMgmt")
	if _, err := k.NameTokens(ctx, "1234", PINProtocolTwo, info); err != nil {
		t.Fatal(err)
	}
	if v.tokenPerms != uint64(PermCredentialManagement) || v.tokenRP != "" {
		t.Errorf("the last token: perms %#x rp %q", v.tokenPerms, v.tokenRP)
	}
	// Preview: the last token is the legacy one (no permissions sent).
	v, k, info = namedKey(t, "credentialMgmtPreview")
	if _, err := k.NameTokens(ctx, "1234", PINProtocolTwo, info); err != nil {
		t.Fatal(err)
	}
	if _, has := v.lastTokenReq[cpPermissions]; has {
		t.Error("a prototype key was asked for permissions")
	}
	// Neither command: only the make token matters, scoped to the name's RP.
	v, k, info = namedKey(t, "")
	if _, err := k.NameTokens(ctx, "1234", PINProtocolTwo, info); err != nil {
		t.Fatal(err)
	}
	if v.tokenPerms != uint64(PermMakeCredential) || v.tokenRP != NameRP {
		t.Errorf("perms %#x rp %q", v.tokenPerms, v.tokenRP)
	}
	// A key with no pinUvAuthToken: one legacy token for both.
	delete(info.Options, "pinUvAuthToken")
	tk, err := k.NameTokens(ctx, "1234", PINProtocolTwo, info)
	if err != nil || !tk.MakeCredential.Valid() || !tk.CredentialManagement.Valid() {
		t.Errorf("%+v %v", tk, err)
	}
	// A wrong PIN fails at whichever token it is first used for.
	_, k, info = namedKey(t, "credMgmt")
	if _, err := k.NameTokens(ctx, "0000", PINProtocolTwo, info); err == nil {
		t.Error("a wrong PIN made a token")
	}
	// The second token failing.
	v, k, info = namedKey(t, "credMgmt")
	calls, failLegacy := 0, false
	wrap := ctap2Key(t, CapCBOR, func(cmd byte, params []byte) []byte {
		if cmd == CmdClientPIN {
			var req map[uint64]cbor.RawMessage
			_ = cbor.Unmarshal(params, &req)
			var sub int
			_ = cbor.Unmarshal(req[cpSubCommand], &sub)
			if sub == subGetTokenUsingPIN {
				calls++
				if calls == 2 {
					return []byte{0x31}
				}
			}
			if sub == subGetPINToken && failLegacy {
				return []byte{0x31}
			}
		}
		return v.reply(cmd, params)
	})
	if _, err := wrap.NameTokens(ctx, "1234", PINProtocolTwo, info); err == nil {
		t.Error("the second token failing was ignored")
	}
	failLegacy = true
	info.Options["credentialMgmtPreview"] = true
	delete(info.Options, "credMgmt")
	if _, err := wrap.NameTokens(ctx, "1234", PINProtocolTwo, info); err == nil {
		t.Error("the preview token failing was ignored")
	}
}

func TestAKeyWithoutCredentialManagementNamesOnceOnly(t *testing.T) {
	ctx := context.Background()
	v, k, info := namedKey(t, "")
	if err := k.SetName(ctx, "first", nameTokens(t, k, info)); err != nil {
		t.Fatal(err)
	}
	if err := k.SetName(ctx, "second", nameTokens(t, k, info)); err == nil || !strings.Contains(err.Error(), "cannot delete credentials") {
		t.Errorf("%v", err)
	}
	if got := nameCreds(v); len(got) != 1 || string(got[0].userID) != "first" {
		t.Errorf("a second name was stored")
	}
}

func TestSilentNameSurvivesAMissingNameThroughANoCredentialsStatus(t *testing.T) {
	// credProtect 3 would hide it; level 1 does not: a level-3 name credential
	// reads as "no name", which is why SetName demands level 1.
	v, k, _ := namedKey(t, "credMgmt")
	v.creds = append(v.creds, vcred([]byte("p"), NameRP, []byte("hidden"), 3))
	if _, err := k.ReadName(context.Background()); !errors.Is(err, ErrNoName) {
		t.Errorf("%v", err)
	}
	v.creds[0].protect = 2
	if _, err := k.ReadName(context.Background()); !errors.Is(err, ErrNoName) {
		t.Errorf("level 2, no allow list: %v", err)
	}
	v.creds[0].protect = 1
	if got, err := k.ReadName(context.Background()); err != nil || got != "hidden" {
		t.Errorf("level 1: %q %v", got, err)
	}
}

// vcred is a discoverable credential made by hand, with a signing key.
func vcred(id []byte, rp string, user []byte, protect uint64) *virtualCredential {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &virtualCredential{id: id, rp: rp, userID: user, key: key, discovered: true, protect: protect}
}
