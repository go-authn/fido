// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// virtualAuthenticator is a software CTAP 2.1 authenticator: getInfo, clientPIN
// (PIN and built-in UV, both PIN/UV auth protocols, permissions), and
// makeCredential/getAssertion with hmac-secret and credProtect.
//
// It is written from the specification (CTAP 2.1: 6.1, 6.2, 6.5, 12.1, 12.5),
// NOT from this package's code: its token check, salt MAC, HKDF and secret
// derivation use crypto primitives directly, so a mistake there cannot be
// echoed back by a fake that shares it. What it DOES share is the AES-256-CBC
// step (pinCrypt) and the CTAP2 CBOR encoder, and the parameter-number
// constants; those are covered by the existing tests and by the real-key test.
// The two behaviours that silently
// ruin a disk unlock are reproduced on purpose:
//
//   - hmac-secret derives from CredRandomWithUV when the request was verified
//     and from CredRandomWithoutUV when it was not (12.5);
//   - a credential with credProtect 3 does not exist to an unverified request
//     (12.1): CTAP2_ERR_NO_CREDENTIALS, even for the right credential id.
type virtualAuthenticator struct {
	t         *testing.T
	priv      *ecdh.PrivateKey
	pin       string
	protocols []uint
	// finger is whether a registered finger is on the sensor when UV is asked.
	finger    bool
	uvRetries int
	pinTries  int

	token      []byte
	tokenProto int
	tokenPerms uint64
	tokenRP    string

	creds []*virtualCredential
	// asked lists the commands received, as "cmd" or "cmd/sub".
	asked []string
	// lastGAExt holds the extensions map of the last getAssertion, as sent.
	lastGAExt map[string]cbor.RawMessage
	lastMCExt map[string]cbor.RawMessage
	// lastTokenReq is the last token request, every key of it.
	lastTokenReq map[uint64]cbor.RawMessage
	// tamper, when set, rewrites the encrypted hmac-secret output.
	tamper func(proto int, aesKey, enc []byte) []byte

	// The list kept by the last discoverable getAssertion (§6.3).
	pending    []*virtualCredential
	pendingRP  string
	pendingCDH []byte
	pendingUV  bool
	pendingHS  cbor.RawMessage
	// nextHMAC: whether getNextAssertion carries the hmac-secret output
	// (the specification is silent, so both are tested).
	nextHMAC bool
	// announce, when > 0, overrides numberOfCredentials (a lying key).
	announce int
}

type virtualCredential struct {
	id         []byte
	rp         string
	userID     []byte
	key        *ecdsa.PrivateKey
	hmac       bool
	protect    uint64
	withUV     [32]byte
	withoutUV  [32]byte
	discovered bool
}

func newVirtualAuthenticator(t *testing.T, pin string, protocols ...uint) *virtualAuthenticator {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(protocols) == 0 {
		protocols = []uint{2, 1}
	}
	return &virtualAuthenticator{t: t, priv: priv, pin: pin, protocols: protocols, finger: true, uvRetries: 5, pinTries: 8}
}

func (v *virtualAuthenticator) fail(code byte) []byte { return []byte{code} }

func (v *virtualAuthenticator) ok(body any) []byte {
	v.t.Helper()
	b, err := ctap2.Marshal(body)
	if err != nil {
		v.t.Fatal(err)
	}
	return append([]byte{0}, b...)
}

// reply is the transport callback.
func (v *virtualAuthenticator) reply(cmd byte, params []byte) []byte {
	v.t.Helper()
	switch cmd {
	case CmdGetInfo:
		v.asked = append(v.asked, "getInfo")
		return v.ok(map[uint64]any{
			infoVersions:     []string{"FIDO_2_0", "FIDO_2_1"},
			infoExtensions:   []string{"hmac-secret", "credProtect"},
			infoAAGUID:       make([]byte, 16),
			infoOptions:      map[string]bool{"rk": true, "clientPin": true, "uv": true, "pinUvAuthToken": true},
			infoPINProtocols: v.protocols,
		})
	case CmdClientPIN:
		return v.clientPIN(params)
	case CmdMakeCredential:
		v.asked = append(v.asked, "makeCredential")
		return v.makeCredential(params)
	case CmdGetAssertion:
		v.asked = append(v.asked, "getAssertion")
		return v.getAssertion(params)
	case CmdGetNextAssertion:
		v.asked = append(v.asked, "getNextAssertion")
		return v.getNextAssertion()
	}
	return v.fail(0x01)
}

func (v *virtualAuthenticator) decode(params []byte) map[uint64]cbor.RawMessage {
	v.t.Helper()
	var m map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(params, &m); err != nil {
		v.t.Fatalf("a request that is not a CBOR map: %v", err)
	}
	return m
}

// shared derives the PIN/UV auth protocol's keys from the platform's COSE key,
// straight from CTAP 2.1 6.5.6 and 6.5.7.
func (v *virtualAuthenticator) shared(proto int, cose cbor.RawMessage) (aesKey, macKey []byte, ok bool) {
	var m map[int64]cbor.RawMessage
	if cbor.Unmarshal(cose, &m) != nil {
		return nil, nil, false
	}
	var x, y []byte
	if cbor.Unmarshal(m[-2], &x) != nil || cbor.Unmarshal(m[-3], &y) != nil {
		return nil, nil, false
	}
	pub, err := ecdh.P256().NewPublicKey(append([]byte{4}, append(x, y...)...))
	if err != nil {
		return nil, nil, false
	}
	z, err := v.priv.ECDH(pub)
	if err != nil {
		return nil, nil, false
	}
	switch proto {
	case 1:
		h := sha256.Sum256(z)
		return h[:], h[:], true
	case 2:
		return hkdfSHA256(z, "CTAP2 AES key"), hkdfSHA256(z, "CTAP2 HMAC key"), true
	}
	return nil, nil, false
}

// hkdfSHA256 is RFC 5869 with a 32-byte zero salt and a 32-byte output, written
// out by hand: Extract is one HMAC and Expand's first block is one more.
func hkdfSHA256(ikm []byte, info string) []byte {
	ext := hmac.New(sha256.New, make([]byte, 32))
	ext.Write(ikm)
	exp := hmac.New(sha256.New, ext.Sum(nil))
	exp.Write([]byte(info))
	exp.Write([]byte{1})
	return exp.Sum(nil)
}

// pinEncrypt and pinDecrypt are the AES-256-CBC of 6.5.6 / 6.5.7.
func pinCrypt(t *testing.T, proto int, key, data []byte, encrypt bool) []byte {
	t.Helper()
	k := pinKeys{proto: PINProtocol(proto), aes: key}
	var out []byte
	var err error
	if encrypt {
		out, err = k.encrypt(data)
	} else {
		out, err = k.decrypt(data)
	}
	if err != nil {
		return nil
	}
	return out
}

// verify is the pinUvAuthParam check of 6.5.6.1 / 6.5.7.1.
func verify(proto int, key, msg, param []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	if proto == 1 {
		sum = sum[:16]
	}
	return hmac.Equal(sum, param)
}

func (v *virtualAuthenticator) clientPIN(params []byte) []byte {
	v.t.Helper()
	req := v.decode(params)
	var sub, proto int
	_ = cbor.Unmarshal(req[cpSubCommand], &sub)
	_ = cbor.Unmarshal(req[cpProtocol], &proto)
	v.asked = append(v.asked, "clientPIN/"+string(rune('0'+sub)))

	switch sub {
	case subGetPINRetries:
		return v.ok(map[uint64]any{cpRespPINRetries: v.pinTries})
	case subGetUVRetries:
		return v.ok(map[uint64]any{cpRespUVRetries: v.uvRetries})
	case subGetKeyAgreement:
		if !slices.Contains(v.protocols, uint(proto)) {
			return v.fail(0x02)
		}
		pub := v.priv.PublicKey().Bytes()
		return v.ok(map[uint64]any{cpRespKeyAgreement: map[int64]any{
			1: 2, 3: -25, -1: 1, -2: pub[1:33], -3: pub[33:],
		}})
	case subGetPINToken, subGetTokenUsingPIN, subGetTokenUsingUV:
		v.lastTokenReq = req
		aesKey, _, ok := v.shared(proto, req[cpKeyAgreement])
		if !ok {
			return v.fail(0x02)
		}
		var perms uint64 = 0x03 // the legacy token: makeCredential and getAssertion
		if sub != subGetPINToken {
			if cbor.Unmarshal(req[cpPermissions], &perms) != nil || perms == 0 {
				return v.fail(0x14) // CTAP2_ERR_MISSING_PARAMETER
			}
		}
		rp := ""
		if raw, has := req[cpRPID]; has {
			_ = cbor.Unmarshal(raw, &rp)
		}
		if sub == subGetTokenUsingUV {
			if v.uvRetries == 0 {
				return v.fail(0x3C) // CTAP2_ERR_UV_BLOCKED (0x3E is INVALID_SUBCOMMAND)
			}
			if !v.finger {
				v.uvRetries--
				return v.fail(0x3F) // CTAP2_ERR_UV_INVALID
			}
		} else {
			var enc []byte
			_ = cbor.Unmarshal(req[cpPinHashEnc], &enc)
			got := pinCrypt(v.t, proto, aesKey, enc, false)
			want := sha256.Sum256([]byte(v.pin))
			if !bytes.Equal(got, want[:16]) {
				v.pinTries--
				return v.fail(0x31)
			}
		}
		v.token = make([]byte, 32)
		_, _ = rand.Read(v.token)
		v.tokenProto, v.tokenPerms, v.tokenRP = proto, perms, rp
		return v.ok(map[uint64]any{cpRespToken: pinCrypt(v.t, proto, aesKey, v.token, true)})
	}
	return v.fail(0x01)
}

// authorise reads the pinUvAuthParam of a makeCredential or getAssertion. It
// returns whether the user was verified, and a status when the request is
// refused (0 when it is not).
func (v *virtualAuthenticator) authorise(param, protoRaw cbor.RawMessage, hasParam bool, cdh []byte, perm uint64, rp string) (uv bool, status byte) {
	if !hasParam {
		return false, 0
	}
	var p []byte
	var proto int
	_ = cbor.Unmarshal(param, &p)
	_ = cbor.Unmarshal(protoRaw, &proto)
	if v.token == nil || proto != v.tokenProto || !verify(proto, v.token, cdh, p) {
		return false, 0x33
	}
	if v.tokenPerms&perm == 0 || (v.tokenRP != "" && v.tokenRP != rp) {
		return false, 0x33
	}
	return true, 0
}

func coseES256(k *ecdsa.PrivateKey) map[int64]any {
	pub, _ := k.PublicKey.ECDH()
	b := pub.Bytes()
	return map[int64]any{1: 2, 3: -7, -1: 1, -2: b[1:33], -3: b[33:]}
}

func (v *virtualAuthenticator) authData(rp string, flags byte, ext map[string]any) []byte {
	h := sha256.Sum256([]byte(rp))
	out := append([]byte(nil), h[:]...)
	flags |= 0x01
	if ext != nil {
		flags |= 0x80
	}
	return append(out, flags, 0, 0, 0, 1)
}

func (v *virtualAuthenticator) makeCredential(params []byte) []byte {
	v.t.Helper()
	req := v.decode(params)
	var cdh []byte
	var rp struct {
		ID string `cbor:"id"`
	}
	var user struct {
		ID []byte `cbor:"id"`
	}
	_ = cbor.Unmarshal(req[mcClientDataHash], &cdh)
	_ = cbor.Unmarshal(req[mcRP], &rp)
	_ = cbor.Unmarshal(req[mcUser], &user)
	pp, hasPP := req[mcPinUvAuthParam]
	uv, status := v.authorise(pp, req[mcPinUvAuthProtocol], hasPP, cdh, 0x01, rp.ID)
	if status != 0 {
		return v.fail(status)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		v.t.Fatal(err)
	}
	c := &virtualCredential{id: make([]byte, 32), rp: rp.ID, userID: user.ID, key: key}
	_, _ = rand.Read(c.id)
	_, _ = rand.Read(c.withUV[:])
	_, _ = rand.Read(c.withoutUV[:])
	var opts map[string]bool
	if raw, ok := req[mcOptions]; ok {
		_ = cbor.Unmarshal(raw, &opts)
	}
	c.discovered = opts["rk"]

	var ext map[string]any
	if raw, ok := req[mcExtensions]; ok {
		var in map[string]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &in); err != nil {
			return v.fail(0x11)
		}
		v.lastMCExt = in
		ext = map[string]any{}
		if r, ok := in["hmac-secret"]; ok {
			var on bool
			if cbor.Unmarshal(r, &on) != nil {
				return v.fail(0x11)
			}
			c.hmac = on
			ext["hmac-secret"] = on
		}
		if r, ok := in["credProtect"]; ok {
			if cbor.Unmarshal(r, &c.protect) != nil || c.protect < 1 || c.protect > 3 {
				return v.fail(0x02)
			}
			ext["credProtect"] = c.protect
		}
	}
	v.creds = append(v.creds, c)

	var flags byte = 0x40
	if uv {
		flags |= 0x04
	}
	ad := v.authData(rp.ID, flags, ext)
	ck, _ := ctap2.Marshal(coseES256(key))
	var attested []byte
	attested = append(attested, make([]byte, 16)...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(c.id)))
	attested = append(attested, c.id...)
	attested = append(attested, ck...)
	ad = append(ad, attested...)
	if ext != nil {
		eb, _ := ctap2.Marshal(ext)
		ad = append(ad, eb...)
	}
	return v.ok(map[uint64]any{mcRespFmt: "none", mcRespAuthData: ad, mcRespAttStmt: map[string]any{}})
}

func (v *virtualAuthenticator) getAssertion(params []byte) []byte {
	v.t.Helper()
	req := v.decode(params)
	var rp string
	var cdh []byte
	var allow []struct {
		ID []byte `cbor:"id"`
	}
	_ = cbor.Unmarshal(req[gaRPID], &rp)
	_ = cbor.Unmarshal(req[gaClientDataHash], &cdh)
	_ = cbor.Unmarshal(req[gaAllowList], &allow)
	pp, hasPP := req[gaPinUvAuthParam]
	uv, status := v.authorise(pp, req[gaPinUvAuthProtocol], hasPP, cdh, 0x02, rp)
	if status != 0 {
		return v.fail(status)
	}

	// 12.1: a credential is used only as its protection policy allows. The
	// refusal is the same status as for a credential that does not exist.
	// §6.2.2 step 12.2.1: the applicable credentials, newest first.
	var matches []*virtualCredential
	for i := len(v.creds) - 1; i >= 0; i-- {
		c := v.creds[i]
		if c.rp != rp {
			continue
		}
		named := slices.ContainsFunc(allow, func(a struct {
			ID []byte `cbor:"id"`
		}) bool {
			return bytes.Equal(a.ID, c.id)
		})
		if len(allow) > 0 && !named {
			continue
		}
		if len(allow) == 0 && !c.discovered {
			continue
		}
		switch {
		case c.protect == 3 && !uv:
			continue
		case c.protect == 2 && !uv && !named:
			continue
		}
		matches = append(matches, c)
	}
	if len(matches) == 0 {
		return v.fail(0x2E)
	}

	var hs cbor.RawMessage
	if raw, ok := req[gaExtensions]; ok {
		var in map[string]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &in); err != nil {
			return v.fail(0x11)
		}
		v.lastGAExt = in
		hs = in["hmac-secret"]
	}
	resp, status := v.assertion(matches[0], rp, cdh, uv, hs, len(allow) == 0)
	if status != 0 {
		return v.fail(status)
	}
	// Only a discoverable request walks the list (§6.2.2 step 12.2).
	v.pending, v.pendingRP, v.pendingCDH, v.pendingUV, v.pendingHS = nil, rp, cdh, uv, hs
	if len(allow) == 0 && len(matches) > 1 {
		v.pending = matches[1:]
		resp[gaRespAvailable] = len(matches)
	}
	if v.announce > 0 {
		resp[gaRespAvailable] = v.announce
	}
	return v.ok(resp)
}

// getNextAssertion is §6.3: the next credential of the list kept by the last
// getAssertion, with no gesture of its own. Whether it carries the
// hmac-secret output is not said by the specification: nextHMAC chooses.
func (v *virtualAuthenticator) getNextAssertion() []byte {
	v.t.Helper()
	if len(v.pending) == 0 {
		return v.fail(0x30) // CTAP2_ERR_NOT_ALLOWED
	}
	c := v.pending[0]
	v.pending = v.pending[1:]
	var hs cbor.RawMessage
	if v.nextHMAC {
		hs = v.pendingHS
	}
	resp, status := v.assertion(c, v.pendingRP, v.pendingCDH, v.pendingUV, hs, true)
	if status != 0 {
		return v.fail(status)
	}
	return v.ok(resp)
}

// assertion builds one assertion reply for credential c.
func (v *virtualAuthenticator) assertion(c *virtualCredential, rp string, cdh []byte, uv bool, hs cbor.RawMessage, withUser bool) (map[uint64]any, byte) {
	var ext map[string]any
	if hs != nil && c.hmac {
		out, status := v.hmacSecret(hs, c, uv)
		if status != 0 {
			return nil, status
		}
		ext = map[string]any{"hmac-secret": out}
	}
	var flags byte
	if uv {
		flags |= 0x04
	}
	ad := v.authData(rp, flags, ext)
	if ext != nil {
		eb, _ := ctap2.Marshal(ext)
		ad = append(ad, eb...)
	}
	digest := sha256.Sum256(append(append([]byte(nil), ad...), cdh...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		v.t.Fatal(err)
	}
	resp := map[uint64]any{
		gaRespCredential: map[string]any{"type": "public-key", "id": c.id},
		gaRespAuthData:   ad,
		gaRespSignature:  sig,
	}
	if withUser {
		resp[gaRespUser] = map[string]any{"id": c.userID}
	}
	return resp, 0
}

// hmacSecret is CTAP 2.1 12.5, "authenticatorGetAssertion additional
// behaviors".
func (v *virtualAuthenticator) hmacSecret(raw cbor.RawMessage, c *virtualCredential, uv bool) ([]byte, byte) {
	var in map[uint64]cbor.RawMessage
	if cbor.Unmarshal(raw, &in) != nil {
		return nil, 0x11
	}
	proto := 1
	if p, ok := in[hsProtocol]; ok {
		_ = cbor.Unmarshal(p, &proto)
	}
	aesKey, macKey, ok := v.shared(proto, in[hsKeyAgreement])
	if !ok {
		return nil, 0x02
	}
	var enc, auth []byte
	_ = cbor.Unmarshal(in[hsSaltEnc], &enc)
	_ = cbor.Unmarshal(in[hsSaltAuth], &auth)
	if !verify(proto, macKey, enc, auth) {
		return nil, 0x33
	}
	salts := pinCrypt(v.t, proto, aesKey, enc, false)
	if len(salts) != 32 && len(salts) != 64 {
		return nil, 0x02
	}
	random := c.withoutUV
	if uv {
		random = c.withUV
	}
	var out []byte
	for i := 0; i < len(salts); i += 32 {
		m := hmac.New(sha256.New, random[:])
		m.Write(salts[i : i+32])
		out = append(out, m.Sum(nil)...)
	}
	enc = pinCrypt(v.t, proto, aesKey, out, true)
	if v.tamper != nil {
		enc = v.tamper(proto, aesKey, enc)
	}
	return enc, 0
}

// expected is the secret the specification says a salt yields for the
// credential, computed without the package.
func (c *virtualCredential) expected(uv bool, salt []byte) []byte {
	random := c.withoutUV
	if uv {
		random = c.withUV
	}
	m := hmac.New(sha256.New, random[:])
	m.Write(salt)
	return m.Sum(nil)
}
