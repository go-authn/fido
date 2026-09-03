// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// The CTAP2 commands. Only the ones this package sends are named; a constant
// for something unsent would be a claim about behaviour nothing here has.
const (
	// CmdGetInfo asks the authenticator to describe itself. It takes no
	// parameters at all -- the message is the command byte and nothing else --
	// which is why it is the first CTAP2 command worth having: it needs a CBOR
	// DECODER and no encoder.
	CmdGetInfo byte = 0x04
)

// Status is the byte a CTAP2 reply begins with. Zero is success.
type Status byte

// StatusOK means the authenticator did what was asked.
const StatusOK Status = 0x00

// The status codes worth naming: the ones a caller can act on. The rest are
// rendered as their number, because inventing a name for a code this package
// has never seen would be a guess dressed as documentation.
var statusNames = map[Status]string{
	0x01: "the command is not one this authenticator knows",
	0x02: "a parameter was wrong",
	0x11: "the CBOR was invalid",
	0x12: "the CBOR was not what the command expects",
	0x19: "an operation is already in progress",
	0x22: "no credential the authenticator holds matches",
	0x2B: "a PIN is required and none was given",
	0x2F: "the PIN is not set on this authenticator",
	0x31: "the PIN was wrong",
	0x32: "too many wrong PINs; unplug the key and try again",
	0x34: "too many wrong PINs; the authenticator is locked",
	0x36: "the PIN is blocked until the key is unplugged",
	0x3A: "the person did not touch the key in time",
	0x3B: "the person refused",
}

// Error reports whether the status is a refusal.
func (s Status) Error() bool { return s != StatusOK }

// String names the status, or gives its number when it has no name here.
func (s Status) String() string {
	if s == StatusOK {
		return "ok"
	}
	if name, ok := statusNames[s]; ok {
		return fmt.Sprintf("%s (%#02x)", name, byte(s))
	}
	return fmt.Sprintf("CTAP2 status %#02x", byte(s))
}

// Info is what an authenticator says about itself, from authenticatorGetInfo.
//
// Only the fields with a caller are decoded. The rest of the reply is left
// alone rather than half-read: a struct field that is always the zero value
// because nothing fills it is worse than no field, since it reads as "this
// authenticator does not have one".
type Info struct {
	// Versions are the protocols it speaks, such as "U2F_V2", "FIDO_2_0" and
	// "FIDO_2_1".
	Versions []string
	// Extensions it supports, such as "hmac-secret".
	Extensions []string
	// AAGUID identifies the MODEL of authenticator, not the individual one.
	AAGUID [16]byte
	// Options are the capabilities it declares, such as "rk" (it can store
	// credentials), "up" (it can test for a person's presence), "uv" (it can
	// verify who they are) and "clientPin".
	Options map[string]bool
	// MaxMsgSize is the largest message it will accept, or zero when it did
	// not say.
	MaxMsgSize uint
	// PINProtocols are the PIN protocol versions it supports.
	PINProtocols []uint
	// Transports it can be reached over, such as "usb" or "nfc".
	Transports []string
}

// Has reports whether the authenticator declares an option AND says it is
// true. An option a key does not mention is not the same as one it sets to
// false -- the first means "not applicable", the second "supported but off" --
// and both answer no here, which is what a caller deciding whether to try
// something needs.
func (i Info) Has(option string) bool { return i.Options[option] }

// String renders the authenticator the way a listing reads.
func (i Info) String() string {
	var on []string
	for k, v := range i.Options {
		if v {
			on = append(on, k)
		}
	}
	sort.Strings(on)
	versions := strings.Join(i.Versions, ", ")
	if versions == "" {
		versions = "no version stated"
	}
	if len(on) == 0 {
		return versions
	}
	return versions + "; " + strings.Join(on, ", ")
}

// The keys of the getInfo reply map, as the specification numbers them.
const (
	infoVersions     = 0x01
	infoExtensions   = 0x02
	infoAAGUID       = 0x03
	infoOptions      = 0x04
	infoMaxMsgSize   = 0x05
	infoPINProtocols = 0x06
	infoTransports   = 0x09
)

// GetInfo asks the authenticator to describe itself.
//
// A key that does not declare [CapCBOR] is not asked: it would answer
// CTAPHID_ERROR, and the caller would have to tell that refusal from a real
// fault.
func (k *Key) GetInfo(ctx context.Context) (Info, error) {
	if !k.caps.Has(CapCBOR) {
		return Info{}, fmt.Errorf("fido: %s does not speak CTAP2", k.t.Name())
	}
	body, err := k.CBOR(ctx, CmdGetInfo, nil)
	if err != nil {
		return Info{}, err
	}
	return parseInfo(body)
}

// CBOR sends one CTAP2 command and returns the reply's body, with the status
// byte already checked.
//
// params is the command's CBOR-encoded parameters, or nil for a command that
// takes none. The command byte is prepended here, because the CTAPHID payload
// of a CBOR message is the command followed by the parameters and getting that
// join wrong is the sort of thing each caller should not repeat.
func (k *Key) CBOR(ctx context.Context, cmd byte, params []byte) ([]byte, error) {
	reply, err := k.roundTrip(ctx, CmdCBOR, append([]byte{cmd}, params...))
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, fmt.Errorf("fido: %s answered a CTAP2 command with nothing at all", k.t.Name())
	}
	if s := Status(reply[0]); s.Error() {
		return nil, fmt.Errorf("fido: %s: %s", k.t.Name(), s)
	}
	return reply[1:], nil
}

// parseInfo decodes the getInfo reply.
//
// It is separate from GetInfo so a reply captured from a real key can be
// decoded in a test without a key, which is the only way the field numbering
// gets checked against something other than itself.
func parseInfo(body []byte) (Info, error) {
	if len(body) == 0 {
		return Info{}, fmt.Errorf("fido: the authenticator described itself with no bytes")
	}
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return Info{}, fmt.Errorf("fido: the authenticator's description is not a CBOR map: %w", err)
	}
	var i Info
	// Each field is optional: a key that does not mention transports has not
	// said it has none. An undecodable field IS an error, though -- a present
	// field this package cannot read means the reply is not what it claims.
	get := func(key uint64, into any) error {
		r, ok := raw[key]
		if !ok {
			return nil
		}
		if err := cbor.Unmarshal(r, into); err != nil {
			return fmt.Errorf("fido: field %#02x of the description: %w", key, err)
		}
		return nil
	}
	var aaguid []byte
	for _, f := range []struct {
		key  uint64
		into any
	}{
		{infoVersions, &i.Versions},
		{infoExtensions, &i.Extensions},
		{infoAAGUID, &aaguid},
		{infoOptions, &i.Options},
		{infoMaxMsgSize, &i.MaxMsgSize},
		{infoPINProtocols, &i.PINProtocols},
		{infoTransports, &i.Transports},
	} {
		if err := get(f.key, f.into); err != nil {
			return Info{}, err
		}
	}
	if n := len(aaguid); n != 0 && n != len(i.AAGUID) {
		return Info{}, fmt.Errorf("fido: the authenticator's identifier is %d bytes, not %d", n, len(i.AAGUID))
	}
	copy(i.AAGUID[:], aaguid)
	if len(i.Versions) == 0 {
		return Info{}, fmt.Errorf("fido: the authenticator named no protocol version, which every reply must")
	}
	return i, nil
}
