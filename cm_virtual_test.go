// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

// credMgmt is the virtual authenticator's authenticatorCredentialManagement,
// from CTAP 2.1 6.8: enumerateCredentialsBegin / GetNextCredential and
// deleteCredential, MACing sub || subCommandParams as sent, and checking the
// token's permission and relying-party binding as 6.8 says.
func (v *virtualAuthenticator) credMgmt(cmd byte, params []byte) []byte {
	v.t.Helper()
	wantCmd := CmdCredentialManagement
	if v.cmOption == "credentialMgmtPreview" {
		wantCmd = CmdCredentialManagementPreview
	}
	if v.cmOption == "" || cmd != wantCmd {
		return v.fail(0x01)
	}
	req := v.decode(params)
	var sub int
	_ = cbor.Unmarshal(req[cmSub], &sub)

	if sub == cmEnumerateCredentialsNext {
		if len(v.pendingCM) == 0 {
			return v.fail(0x2E)
		}
		c := v.pendingCM[0]
		v.pendingCM = v.pendingCM[1:]
		return v.ok(cmEntry(c, false, 0))
	}
	if sub != cmEnumerateCredentialsBegin && sub != cmDeleteCredential {
		return v.fail(0x3e)
	}

	raw := req[cmParams]
	ar, has := req[cmAuth]
	if !has {
		return v.fail(0x36)
	}
	var param []byte
	var proto int
	_ = cbor.Unmarshal(ar, &param)
	_ = cbor.Unmarshal(req[cmProto], &proto)
	msg := append([]byte{byte(sub)}, raw...)
	perms, trp, ok := v.matchToken(proto, msg, param)
	if !ok {
		return v.fail(0x33)
	}
	if v.cmOption == "credMgmt" && perms&uint64(PermCredentialManagement) == 0 {
		return v.fail(0x33)
	}
	if trp != "" {
		return v.fail(0x33) // the commands here want a token bound to no relying party
	}

	var p map[uint64]cbor.RawMessage
	_ = cbor.Unmarshal(raw, &p)
	switch sub {
	case cmEnumerateCredentialsBegin:
		var h []byte
		_ = cbor.Unmarshal(p[cmpRPIDHash], &h)
		var found []*virtualCredential
		for _, c := range v.creds {
			sum := sha256.Sum256([]byte(c.rp))
			if c.discovered && bytes.Equal(sum[:], h) {
				found = append(found, c)
			}
		}
		if len(found) == 0 {
			return v.fail(0x2E)
		}
		v.pendingCM = found[1:]
		return v.ok(cmEntry(found[0], true, len(found)))
	default: // delete
		var d struct {
			ID []byte `cbor:"id"`
		}
		_ = cbor.Unmarshal(p[cmpCredentialID], &d)
		for i, c := range v.creds {
			if bytes.Equal(c.id, d.ID) {
				v.creds = append(v.creds[:i], v.creds[i+1:]...)
				return []byte{0}
			}
		}
		return v.fail(0x2E)
	}
}

func cmEntry(c *virtualCredential, begin bool, total int) map[uint64]any {
	m := map[uint64]any{
		cmrUser:         map[string]any{"id": c.userID, "name": string(c.userID), "displayName": string(c.userID)},
		cmrCredentialID: map[string]any{"id": c.id, "type": "public-key"},
		0x08:            map[int64]any{1: 2, 3: -7, -1: 1}, // publicKey: shape only
	}
	if begin {
		m[cmrTotalCreds] = total
	}
	return m
}
