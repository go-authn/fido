// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"
)

// A name stored ON the key, so it follows the key across ports and machines.
//
// The port a key sits in is not the key (the macOS LocationID and the Linux
// HID_PHYS change with the socket), the AAGUID names a model, and most keys
// publish no USB serial. What does travel with a key is what is stored in it:
// a discoverable credential under a reserved relying party id, whose user
// handle is the name.
//
// Why that can be read with no touch and no PIN (CTAP 2.1, 6.2.2, steps
// 4.5, 5, 7.4-7.5, 9, 12.3):
//
//   - options {"up": false} skips user presence (step 9 runs only when "up" is
//     true or absent), so nothing is asked of the person;
//   - alwaysUv (7.2.3) is applied in step 5 only "if alwaysUv is true and up is
//     true", so a key that always requires verification still answers up=false;
//   - credProtect level 1 is not filtered without verification (7.4 removes
//     level 3, 7.5 level 2 without an allow list);
//   - the response carries the user entity (12.3), and "id" is mandatory for a
//     discoverable credential; only name, displayName and icon are withheld
//     without verification. So the name lives in user.id.
//
// The specification does not promise every key behaves so, which is why the
// silent read can be refused (ErrNameRefused) and a caller needs a fallback.

// NameRP is the reserved relying party id of the name credential. CTAP treats a
// relying party id as an opaque string; WebAuthn's origin rules (not opened
// here) mean no web page can ask for "name.fido".
const NameRP = "name.fido"

// MaxNameBytes is the longest name, in UTF-8 bytes: the 64 bytes CTAP allows a
// user handle.
const MaxNameBytes = 64

var (
	// ErrNoName means the key has no name credential.
	ErrNoName = errors.New("fido: this key has no name")
	// ErrNameRefused means the key would not answer the silent read (no touch,
	// no PIN). It wraps the key's own status.
	ErrNameRefused = errors.New("fido: this key does not answer a read of its name without verification")
	// ErrNameAmbiguous means the key holds more than one name credential.
	ErrNameAmbiguous = errors.New("fido: this key holds more than one name")
)

// CheckName refuses a name that cannot be stored: empty, not UTF-8, longer than
// [MaxNameBytes], or containing a control or format character (a name is shown
// in terminals).
func CheckName(name string) error {
	switch {
	case name == "":
		return errors.New("fido: a name cannot be empty")
	case !utf8.ValidString(name):
		return errors.New("fido: a name must be valid UTF-8")
	case len(name) > MaxNameBytes:
		return fmt.Errorf("fido: the name is %d bytes in UTF-8; the most a key stores is %d", len(name), MaxNameBytes)
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("fido: the name has a control or invisible character (%U)", r)
		}
	}
	return nil
}

// DecodeName reads a name from a user handle a key returned. What a key holds
// is input from a device the program does not control, so it is checked as a
// name is on the way in.
func DecodeName(id []byte) (string, error) {
	name := string(id)
	if err := CheckName(name); err != nil {
		return "", fmt.Errorf("fido: the name on this key is not usable: %w", err)
	}
	return name, nil
}

// statuses that mean "not without verification" rather than "no name".
var refusedSilently = []Status{0x36, StatusOperationDenied, StatusInvalidOption, 0x2b}

// ReadName reads the key's name with NO touch and NO PIN: getAssertion for
// [NameRP] with "up" false and no pinUvAuthParam. [ErrNoName] when there is
// none, [ErrNameRefused] when the key will not answer unverified,
// [ErrNameAmbiguous] when it holds several.
func (k *Key) ReadName(ctx context.Context) (string, error) {
	var cdh [32]byte
	if _, err := randRead(cdh[:]); err != nil {
		return "", fmt.Errorf("fido: cannot make a challenge: %w", err)
	}
	a, err := k.GetAssertion(ctx, GetAssertionRequest{
		RPID: NameRP, ClientDataHash: cdh[:], Options: map[string]bool{"up": false},
	})
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			if se.Status == StatusNoCredentials {
				return "", ErrNoName
			}
			if slices.Contains(refusedSilently, se.Status) {
				return "", fmt.Errorf("%w: %w", ErrNameRefused, err)
			}
		}
		return "", err
	}
	if a.Available > 1 {
		return "", ErrNameAmbiguous
	}
	return DecodeName(a.UserID)
}

// NameTokens authorises naming a key from one PIN.
//
// ⛔ It deliberately holds the PIN, not tokens. An authenticator keeps ONE
// pinUvAuthToken at a time: obtaining a new one replaces the last, so a token
// fetched for credential management is dead by the time makeCredential uses it
// (the authenticator answers CTAP2_ERR_PIN_AUTH_INVALID, 0x33, to the request's
// pinUvAuthParam even though the PIN was accepted). SetName therefore asks for
// each token at the moment it is used: credential management first (no relying
// party bound, 6.8), then makeCredential bound to [NameRP]. The zero value
// carries no verification.
type NameTokens struct {
	k     *Key
	pin   string
	proto PINProtocol
	info  Info
}

// NameTokens checks the PIN with a token (so a wrong PIN fails before anything
// is changed, costing the one retry a wrong PIN always costs) and returns what
// SetName and RemoveName need to ask for tokens as they go. The token used to
// check is discarded.
func (k *Key) NameTokens(ctx context.Context, pin string, proto PINProtocol, info Info) (NameTokens, error) {
	n := NameTokens{k: k, pin: pin, proto: proto, info: info}
	if _, err := n.forMake(ctx); err != nil {
		return NameTokens{}, err
	}
	return n, nil
}

func (n NameTokens) valid() bool { return n.k != nil }

// forCredMgmt asks for a token credential management accepts: the cm
// permission and no relying party on a key with the final command; a plain
// getPinToken token (no permissions) on a prototype or CTAP 2.0 key.
func (n NameTokens) forCredMgmt(ctx context.Context) (Token, error) {
	if n.info.Has("pinUvAuthToken") && n.info.CredMgmtMode() == CredMgmtFinal {
		return n.k.PINToken(ctx, n.pin, n.proto, PermCredentialManagement, "")
	}
	return n.k.PINToken(ctx, n.pin, n.proto, 0, "")
}

// forMake asks for a token makeCredential accepts: the mc permission bound to
// [NameRP], or a plain token on a CTAP 2.0 key.
func (n NameTokens) forMake(ctx context.Context) (Token, error) {
	if n.info.Has("pinUvAuthToken") {
		return n.k.PINToken(ctx, n.pin, n.proto, PermMakeCredential, NameRP)
	}
	return n.k.PINToken(ctx, n.pin, n.proto, 0, "")
}

// SetName gives the key a name, replacing any it had.
//
// The old name credentials are deleted FIRST (credential management, 6.8) and
// the new one made after, so the key never holds two: if making fails, the key
// has no name, which is harmless; two names would not be. A key that already
// has a name and cannot delete credentials is refused before anything changes.
// The credential is discoverable, credProtect level 1, with the name as user
// handle, name and display name.
func (k *Key) SetName(ctx context.Context, name string, tok NameTokens) error {
	if err := CheckName(name); err != nil {
		return err
	}
	info, err := k.GetInfo(ctx)
	if err != nil {
		return err
	}
	if !info.Has("rk") || !slices.Contains(info.Extensions, "credProtect") {
		return errors.New("fido: this key cannot store a name: it needs discoverable credentials and credProtect")
	}
	if cm, cerr := k.CredMgmt(info); cerr == nil && tok.valid() {
		cmTok, err := tok.forCredMgmt(ctx)
		if err != nil {
			return err
		}
		if err := cm.deleteAll(ctx, cmTok); err != nil {
			return err
		}
	} else if _, rerr := k.ReadName(ctx); rerr == nil || errors.Is(rerr, ErrNameRefused) || errors.Is(rerr, ErrNameAmbiguous) {
		return errors.New("fido: this key already has a name, and cannot delete credentials to replace it")
	}
	var cdh [32]byte
	if _, err := randRead(cdh[:]); err != nil {
		return fmt.Errorf("fido: cannot make a challenge: %w", err)
	}
	// The token for makeCredential is asked for NOW, after the deletes: it
	// replaces the credential management token, which is no longer needed.
	var mcTok Token
	if tok.valid() {
		if mcTok, err = tok.forMake(ctx); err != nil {
			return err
		}
	}
	att, err := k.MakeCredential(ctx, MakeCredentialRequest{
		ClientDataHash: cdh[:],
		RP:             RelyingParty{ID: NameRP, Name: "Key name"},
		User:           User{ID: []byte(name), Name: name, DisplayName: name},
		Options:        map[string]bool{"rk": true},
		Token:          mcTok,
		Extensions:     Extensions{CredProtect: CredProtectOptional},
	})
	if err != nil {
		return err
	}
	if att.Extensions.CredProtect != CredProtectOptional {
		return fmt.Errorf("fido: the name was stored without credProtect level 1 (the key reported %d): it may not be readable without a PIN", att.Extensions.CredProtect)
	}
	return nil
}

// RemoveName deletes every name credential. A key with none is not an error.
func (k *Key) RemoveName(ctx context.Context, tok NameTokens) error {
	info, err := k.GetInfo(ctx)
	if err != nil {
		return err
	}
	cm, err := k.CredMgmt(info)
	if err != nil {
		return err
	}
	if !tok.valid() {
		return errors.New("fido: removing a name needs the PIN")
	}
	cmTok, err := tok.forCredMgmt(ctx)
	if err != nil {
		return err
	}
	return cm.deleteAll(ctx, cmTok)
}

// deleteAll deletes every credential of [NameRP].
func (c *CredMgmt) deleteAll(ctx context.Context, tok Token) error {
	creds, err := c.Credentials(ctx, tok, NameRP)
	if err != nil {
		return err
	}
	for _, cr := range creds {
		if err := c.Delete(ctx, tok, cr.ID); err != nil {
			return err
		}
	}
	return nil
}
