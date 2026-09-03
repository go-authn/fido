// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Flags are the authenticator data's flag byte: what the authenticator did
// before it signed.
type Flags byte

// The flag bits, as the specification numbers them.
const (
	// FlagUP means a person was PRESENT: something touched the key. It says
	// nothing about who.
	FlagUP Flags = 1 << 0
	// FlagUV means the person was VERIFIED -- a PIN, a fingerprint on the key
	// itself. This is the bit that makes an assertion worth more than
	// possession.
	FlagUV Flags = 1 << 2
	// FlagBE means the credential may be backed up, and FlagBS that it
	// currently is. A backed-up credential is not confined to this one device,
	// which matters to anyone counting it as "something you have".
	FlagBE Flags = 1 << 3
	FlagBS Flags = 1 << 4
	// FlagAT means attested credential data follows, which a registration has
	// and an assertion does not.
	FlagAT Flags = 1 << 6
	// FlagED means extension data follows.
	FlagED Flags = 1 << 7
)

// Has reports whether every bit in want is set.
func (f Flags) Has(want Flags) bool { return f&want == want }

// String lists the flags that are set, in bit order.
func (f Flags) String() string {
	var on []string
	for _, b := range []struct {
		bit  Flags
		name string
	}{
		{FlagUP, "present"}, {FlagUV, "verified"}, {FlagBE, "backup-eligible"},
		{FlagBS, "backed-up"}, {FlagAT, "attested"}, {FlagED, "extensions"},
	} {
		if f.Has(b.bit) {
			on = append(on, b.name)
		}
	}
	if len(on) == 0 {
		return fmt.Sprintf("none (%#02x)", byte(f))
	}
	return strings.Join(on, ", ")
}

// AuthData is the authenticator data an authenticator signs over.
//
// It is the part of a FIDO answer that says what happened: which relying party
// it was for, whether a person was present and whether they were verified. The
// signature covers it, so reading it is how a caller learns anything at all
// beyond "the key answered".
type AuthData struct {
	// RPIDHash is SHA-256 of the relying party id. It is a hash, not a name:
	// the authenticator never learns the name.
	RPIDHash [32]byte
	Flags    Flags
	// SignCount rises with use on authenticators that keep one. A count that
	// goes BACKWARDS is the classic sign of a cloned credential -- and a count
	// that stays at zero means this authenticator does not keep one, which is
	// allowed and is not evidence of anything.
	SignCount uint32

	// The rest is present only when [FlagAT] is set, which is a registration.
	AAGUID       [16]byte
	CredentialID []byte
	// PublicKey is the credential's public key, as COSE_Key CBOR. It is left
	// encoded: turning it into a Go key means choosing a curve library, and
	// that choice belongs to whoever verifies signatures rather than to the
	// package that reads the bytes.
	PublicKey cbor.RawMessage

	// Extensions is present only when [FlagED] is set.
	Extensions cbor.RawMessage
}

// String renders the authenticator data the way a log line reads.
func (a AuthData) String() string {
	s := fmt.Sprintf("rp %x…, %s, count %d", a.RPIDHash[:4], a.Flags, a.SignCount)
	if len(a.CredentialID) > 0 {
		s += fmt.Sprintf(", credential %x… (%d bytes)", a.CredentialID[:min(4, len(a.CredentialID))], len(a.CredentialID))
	}
	return s
}

// The fixed sizes the layout is built from.
const (
	authDataHeader   = 32 + 1 + 4 // rp id hash, flags, sign count
	aaguidLen        = 16
	credentialIDSize = 2 // a big-endian length
)

// ParseAuthData reads authenticator data.
//
// The layout is fixed-width up to the flag byte and then conditional on it,
// which is where the mistakes live: a parser that assumes attested data is
// present reads a credential id out of an assertion's extensions, and one that
// assumes it is absent silently ignores a registration. Both flags are obeyed
// here, and a length that does not add up is an error rather than a slice.
func ParseAuthData(b []byte) (AuthData, error) {
	if len(b) < authDataHeader {
		return AuthData{}, fmt.Errorf("fido: authenticator data is %d bytes, and the header alone is %d",
			len(b), authDataHeader)
	}
	var a AuthData
	copy(a.RPIDHash[:], b[:32])
	a.Flags = Flags(b[32])
	a.SignCount = binary.BigEndian.Uint32(b[33:37])
	rest := b[authDataHeader:]

	if a.Flags.Has(FlagAT) {
		if len(rest) < aaguidLen+credentialIDSize {
			return AuthData{}, fmt.Errorf("fido: the attested credential data is %d bytes, too few for its own header", len(rest))
		}
		copy(a.AAGUID[:], rest[:aaguidLen])
		n := int(binary.BigEndian.Uint16(rest[aaguidLen : aaguidLen+credentialIDSize]))
		rest = rest[aaguidLen+credentialIDSize:]
		if len(rest) < n {
			return AuthData{}, fmt.Errorf("fido: the credential id says %d bytes and %d follow", n, len(rest))
		}
		a.CredentialID = rest[:n]
		rest = rest[n:]
		// The public key is CBOR of unstated length, so the only way to know
		// where it ends is to decode it. cbor.RawMessage's decoder stops at the
		// end of the first complete item, which is what leaves the extensions
		// -- if any -- in what remains.
		var key cbor.RawMessage
		dec := cbor.NewDecoder(bytesReader(rest))
		if err := dec.Decode(&key); err != nil {
			return AuthData{}, fmt.Errorf("fido: the credential's public key is not CBOR: %w", err)
		}
		a.PublicKey = key
		rest = rest[dec.NumBytesRead():]
	}

	if a.Flags.Has(FlagED) {
		var ext cbor.RawMessage
		if err := cbor.Unmarshal(rest, &ext); err != nil {
			return AuthData{}, fmt.Errorf("fido: the extension data is not CBOR: %w", err)
		}
		a.Extensions = ext
		return a, nil
	}
	if len(rest) != 0 {
		return AuthData{}, fmt.Errorf("fido: %d bytes follow the authenticator data that no flag accounts for", len(rest))
	}
	return a, nil
}
