// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// The virtual authenticator's PIN management and bio enrollment, written from
// CTAP 2.1 6.5.5.5, 6.5.5.6 and 6.7 and checked at the byte level: it MACs the
// exact bytes the specification names (newPinEnc || pinHashEnc, and
// modality || subCommand || the raw subCommandParams as sent), not what this
// package computes.

type bioTemplate struct {
	id   []byte
	name string
}

type bioState struct {
	templates []*bioTemplate
	// enrolling is the template id of the enrollment under way, or nil.
	enrolling []byte
	remaining int
	// needed is the good samples an enrollment takes (default 4), capacity the
	// database size (default 5), maxName the friendly-name limit (default 16).
	needed, capacity, maxName int
	// script is the status of each sample in turn; past its end every sample is
	// good.
	script []SampleStatus
	// lastParams is the last subCommandParams as sent, lastTimeout its timeout
	// (0 when absent), and lastSub the last subcommand.
	lastParams  map[uint64]cbor.RawMessage
	lastTimeout uint64
	lastSub     int
	// lastReq is the whole last request.
	lastReq map[uint64]cbor.RawMessage
}

func (v *virtualAuthenticator) withBio(option string) *virtualAuthenticator {
	v.bioOption = option
	v.bio.needed, v.bio.capacity, v.bio.maxName = 4, 5, 16
	return v
}

func (v *virtualAuthenticator) setOrChangePIN(sub, proto int, req map[uint64]cbor.RawMessage) []byte {
	v.t.Helper()
	v.lastPINReq = req
	aesKey, macKey, ok := v.shared(proto, req[cpKeyAgreement])
	if !ok {
		return v.fail(0x02)
	}
	var enc, hashEnc, param []byte
	for k, into := range map[uint64]*[]byte{cpNewPinEnc: &enc, cpPinHashEnc: &hashEnc, cpPinUvAuthParam: &param} {
		if raw, has := req[k]; has {
			_ = cbor.Unmarshal(raw, into)
		}
	}
	if len(enc) == 0 || len(param) == 0 {
		return v.fail(0x14) // CTAP2_ERR_MISSING_PARAMETER
	}
	msg := enc
	if sub == subSetPIN {
		if v.pin != "" {
			return v.fail(0x33) // a PIN is already set
		}
		if _, has := req[cpPinHashEnc]; has {
			return v.fail(0x02) // setPIN has no pinHashEnc
		}
	} else {
		if v.pin == "" {
			return v.fail(0x35)
		}
		msg = append(append([]byte(nil), enc...), hashEnc...)
	}
	if !verify(proto, macKey, msg, param) {
		return v.fail(0x33)
	}
	if sub == subChangePIN {
		if v.pinTries == 0 {
			return v.fail(0x32)
		}
		want := sha256.Sum256([]byte(v.pin))
		if !bytes.Equal(pinCrypt(v.t, proto, aesKey, hashEnc, false), want[:16]) {
			v.pinTries--
			return v.fail(0x31)
		}
		v.pinTries = 8
	}
	block := pinCrypt(v.t, proto, aesKey, enc, false)
	if len(block) != 64 {
		return v.fail(0x02)
	}
	pin := string(bytes.TrimRight(block, "\x00"))
	min := v.minPIN
	if min == 0 {
		min = 4
	}
	if utf8.RuneCountInString(pin) < min {
		return v.fail(0x37)
	}
	if sub == subChangePIN && v.forceChange && pin == v.pin {
		return v.fail(0x37)
	}
	v.pin, v.forceChange = pin, false
	return []byte{0}
}

// bioCmd is authenticatorBioEnrollment.
func (v *virtualAuthenticator) bioCmd(cmd byte, params []byte) []byte {
	v.t.Helper()
	wantCmd := CmdBioEnrollment
	if v.bioOption == "userVerificationMgmtPreview" {
		wantCmd = CmdBioEnrollmentPreview
	}
	if v.bioOption == "" || cmd != wantCmd {
		return v.fail(0x01) // CTAP1_ERR_INVALID_COMMAND
	}
	req := v.decode(params)
	b := &v.bio
	b.lastReq = req
	var modality, sub int
	_ = cbor.Unmarshal(req[bioModality], &modality)
	_ = cbor.Unmarshal(req[bioSub], &sub)
	b.lastSub = sub
	if modality != modalityFingerprint {
		return v.fail(0x02)
	}
	raw, hasParams := req[bioParams]
	b.lastParams, b.lastTimeout = nil, 0
	if hasParams {
		_ = cbor.Unmarshal(raw, &b.lastParams)
		if t, ok := b.lastParams[bpTimeout]; ok {
			_ = cbor.Unmarshal(t, &b.lastTimeout)
		}
	}
	var id []byte
	if r, ok := b.lastParams[bpTemplateID]; ok {
		_ = cbor.Unmarshal(r, &id)
	}

	switch sub {
	case subSensorInfo, subEnrollCancel:
		// 6.7.3 and 6.7.5 carry no pinUvAuthParam.
		if _, has := req[bioAuthParam]; has {
			return v.fail(0x02)
		}
		if sub == subEnrollCancel {
			b.enrolling = nil
			return []byte{0}
		}
		return v.ok(map[uint64]any{brKind: 1, brMaxSamples: b.needed, brMaxName: b.maxName})
	case subEnrollBegin, subEnrollNext, subEnumerate, subSetName, subRemove:
	default:
		return v.fail(0x3e)
	}

	// Everything else needs a pinUvAuthParam over 0x01 || sub || params-as-sent.
	var param []byte
	var proto int
	pr, has := req[bioAuthParam]
	if !has {
		return v.fail(0x36) // CTAP2_ERR_PUAT_REQUIRED
	}
	_ = cbor.Unmarshal(pr, &param)
	_ = cbor.Unmarshal(req[bioProtocol], &proto)
	msg := append([]byte{0x01, byte(sub)}, raw...)
	if v.token == nil || proto != v.tokenProto || !verify(proto, v.token, msg, param) {
		return v.fail(0x33)
	}
	if v.bioOption == "bioEnroll" && v.tokenPerms&uint64(PermBioEnrollment) == 0 {
		return v.fail(0x33) // the token lacks the be permission
	}

	switch sub {
	case subEnrollBegin:
		if len(b.templates) >= b.capacity {
			return v.fail(0x17)
		}
		b.enrolling = make([]byte, 8)
		_, _ = rand.Read(b.enrolling)
		b.remaining = b.needed
		st := b.sample()
		return v.ok(map[uint64]any{brTemplateID: b.enrolling, brLastStatus: uint(st), brRemaining: b.remaining})
	case subEnrollNext:
		if b.enrolling == nil || !bytes.Equal(id, b.enrolling) {
			return v.fail(0x2c)
		}
		st := b.sample()
		return v.ok(map[uint64]any{brLastStatus: uint(st), brRemaining: b.remaining})
	case subEnumerate:
		if len(b.templates) == 0 {
			return v.fail(0x2c)
		}
		var infos []map[uint64]any
		for _, t := range b.templates {
			m := map[uint64]any{bpTemplateID: t.id}
			if t.name != "" {
				m[bpName] = t.name
			}
			infos = append(infos, m)
		}
		return v.ok(map[uint64]any{brTemplateInfos: infos})
	case subSetName:
		t := b.find(id)
		if t == nil {
			return v.fail(0x2c)
		}
		var name string
		_ = cbor.Unmarshal(b.lastParams[bpName], &name)
		if len(name) > b.maxName {
			return v.fail(0x03)
		}
		t.name = name
		return []byte{0}
	default: // subRemove
		for i, t := range b.templates {
			if bytes.Equal(t.id, id) {
				b.templates = append(b.templates[:i], b.templates[i+1:]...)
				return []byte{0}
			}
		}
		return v.fail(0x2c)
	}
}

func (b *bioState) find(id []byte) *bioTemplate {
	for _, t := range b.templates {
		if bytes.Equal(t.id, id) {
			return t
		}
	}
	return nil
}

// sample consumes one scripted status; a good one counts, and the last good
// one completes the enrollment.
func (b *bioState) sample() SampleStatus {
	st := SampleGood
	if len(b.script) > 0 {
		st, b.script = b.script[0], b.script[1:]
	}
	if st == SampleGood {
		b.remaining--
		if b.remaining == 0 {
			b.templates = append(b.templates, &bioTemplate{id: b.enrolling})
			b.enrolling = nil
		}
	}
	return st
}
