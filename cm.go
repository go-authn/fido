// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// authenticatorCredentialManagement (CTAP 2.1 6.8), the part this package
// needs: list the credentials of one relying party and delete one.
//
// Which command byte depends on getInfo (6.4, 6.13): "credMgmt" present means
// the final command 0x0A and a token with the cm permission; otherwise
// "credentialMgmtPreview" present means the prototype, 0x41, which needs no
// permissions and so takes a plain getPinToken token.
const (
	// CmdCredentialManagement is authenticatorCredentialManagement.
	CmdCredentialManagement byte = 0x0A
	// CmdCredentialManagementPreview is the prototype command.
	CmdCredentialManagementPreview byte = 0x41
)

const (
	cmSub    = 0x01
	cmParams = 0x02
	cmProto  = 0x03
	cmAuth   = 0x04

	cmEnumerateCredentialsBegin = 0x04
	cmEnumerateCredentialsNext  = 0x05
	cmDeleteCredential          = 0x06

	cmpRPIDHash      = 0x01
	cmpCredentialID  = 0x02
	cmrUser          = 0x06
	cmrCredentialID  = 0x07
	cmrTotalCreds    = 0x09
	maxManagedPerRP  = 256
	managedUserIDMax = 64
)

// CredMgmtMode says which credential management command a key speaks.
type CredMgmtMode int

// The modes.
const (
	CredMgmtUnsupported CredMgmtMode = iota
	CredMgmtFinal
	CredMgmtPreview
)

// CredMgmtMode reads the options by presence: a false "credMgmt" is "supported,
// nothing to manage", still the final command.
func (i Info) CredMgmtMode() CredMgmtMode {
	if _, ok := i.Options["credMgmt"]; ok {
		return CredMgmtFinal
	}
	if _, ok := i.Options["credentialMgmtPreview"]; ok {
		return CredMgmtPreview
	}
	return CredMgmtUnsupported
}

// CredMgmt manages the credentials of one key.
type CredMgmt struct {
	k    *Key
	cmd  byte
	perm Permissions
}

// CredMgmt returns the interface the key declares in info, or an error when it
// declares none.
func (k *Key) CredMgmt(info Info) (*CredMgmt, error) {
	switch info.CredMgmtMode() {
	case CredMgmtFinal:
		return &CredMgmt{k: k, cmd: CmdCredentialManagement, perm: PermCredentialManagement}, nil
	case CredMgmtPreview:
		return &CredMgmt{k: k, cmd: CmdCredentialManagementPreview}, nil
	}
	return nil, fmt.Errorf("fido: %s does not declare credential management (neither credMgmt nor credentialMgmtPreview)", k.t.Name())
}

// Permissions is what to ask [Key.PINToken] for: cm on a key with the final
// command, zero (the CTAP 2.0 token) on a prototype one. The token must carry
// NO relying party id for the commands here (6.8).
func (c *CredMgmt) Permissions() Permissions { return c.perm }

// ManagedCredential is a credential as credential management lists it.
type ManagedCredential struct {
	// ID is the credential id.
	ID []byte
	// User is the user entity stored with it.
	User User
}

func (c *CredMgmt) call(ctx context.Context, tok Token, sub int, params map[int]any) ([]byte, error) {
	if err := c.k.ctap2Ready(); err != nil {
		return nil, err
	}
	if !tok.Valid() && sub != cmEnumerateCredentialsNext {
		return nil, errors.New("fido: credential management needs a token")
	}
	req := map[int]any{cmSub: sub}
	var pb []byte
	if params != nil {
		var err error
		if pb, err = ctap2.Marshal(params); err != nil {
			return nil, fmt.Errorf("fido: cannot encode the request: %w", err)
		}
		req[cmParams] = cbor.RawMessage(pb)
	}
	if sub != cmEnumerateCredentialsNext {
		// The next call carries no parameter and no pinUvAuthParam: it continues
		// the enumeration the begin call started (6.8).
		req[cmProto] = int(tok.Protocol())
		req[cmAuth] = tok.authParam(append([]byte{byte(sub)}, pb...))
	}
	return c.k.cborCall(ctx, c.cmd, req)
}

// Credentials lists the credentials of rpID: enumerateCredentialsBegin then
// enumerateCredentialsGetNextCredential for the rest (6.8). A relying party
// with none is an empty list. At most 256 are read, whatever the key claims.
func (c *CredMgmt) Credentials(ctx context.Context, tok Token, rpID string) ([]ManagedCredential, error) {
	hash := sha256.Sum256([]byte(rpID))
	body, err := c.call(ctx, tok, cmEnumerateCredentialsBegin, map[int]any{cmpRPIDHash: hash[:]})
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == StatusNoCredentials {
			return nil, nil
		}
		return nil, err
	}
	first, total, err := parseManaged(body, true)
	if err != nil {
		return nil, err
	}
	if total > maxManagedPerRP {
		return nil, fmt.Errorf("fido: the key lists %d credentials for one relying party; at most %d are read", total, maxManagedPerRP)
	}
	out := []ManagedCredential{first}
	for len(out) < total {
		body, err := c.call(ctx, tok, cmEnumerateCredentialsNext, nil)
		if err != nil {
			return nil, err
		}
		next, _, err := parseManaged(body, false)
		if err != nil {
			return nil, err
		}
		out = append(out, next)
	}
	return out, nil
}

// parseManaged reads one enumerateCredentials reply. begin replies carry the
// total.
func parseManaged(body []byte, begin bool) (ManagedCredential, int, error) {
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return ManagedCredential{}, 0, fmt.Errorf("fido: the credential is not a CBOR map: %w", err)
	}
	var m ManagedCredential
	var u struct {
		ID          []byte `cbor:"id"`
		Name        string `cbor:"name"`
		DisplayName string `cbor:"displayName"`
	}
	if err := field(raw, cmrUser, &u, "user"); err != nil {
		return ManagedCredential{}, 0, err
	}
	if len(u.ID) > managedUserIDMax {
		return ManagedCredential{}, 0, fmt.Errorf("fido: a user handle of %d bytes; CTAP allows %d", len(u.ID), managedUserIDMax)
	}
	var d struct {
		ID []byte `cbor:"id"`
	}
	if err := field(raw, cmrCredentialID, &d, "credential id"); err != nil {
		return ManagedCredential{}, 0, err
	}
	if len(d.ID) == 0 {
		return ManagedCredential{}, 0, errors.New("fido: the key listed a credential with no id")
	}
	m.ID, m.User = d.ID, User{ID: u.ID, Name: u.Name, DisplayName: u.DisplayName}
	total := 0
	if begin {
		if err := field(raw, cmrTotalCreds, &total, "credential count"); err != nil {
			return ManagedCredential{}, 0, err
		}
		if total < 1 {
			return ManagedCredential{}, 0, fmt.Errorf("fido: the key counts %d credentials after listing one", total)
		}
	}
	return m, total, nil
}

// Delete removes one credential by id: deleteCredential (6.8).
func (c *CredMgmt) Delete(ctx context.Context, tok Token, credentialID []byte) error {
	if len(credentialID) == 0 {
		return errors.New("fido: a credential to delete needs an id")
	}
	_, err := c.call(ctx, tok, cmDeleteCredential, map[int]any{
		cmpCredentialID: map[string]any{"id": credentialID, "type": "public-key"},
	})
	return err
}
