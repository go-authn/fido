package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fxamacker/cbor/v2"

	authn "github.com/go-authn/fido"
)

// The attestation envelope is what `fido attest --save-to` writes and
// `fido attest --verify-file` reads: one CTAP2-canonical CBOR map, so the whole
// verification (statement signature, certificate rules, MDS chain) can be
// redone offline. The attestation object alone cannot be: the signature covers
// authData || clientDataHash, and the hash is not in the object.
//
//	{
//	  "v":              1,                 // envelope version (uint); unknown versions are refused
//	  "rpId":           text,              // the relying party id the credential was made for
//	  "clientDataJSON": bytes,             // the exact bytes that were hashed
//	  "clientDataHash": bytes (32),        // SHA-256 of clientDataJSON, as sent to the key
//	  "attestationObject": bytes           // the WebAuthn attestationObject (CBOR)
//	}
//
// Unknown members, duplicate keys and trailing bytes are refused.
const (
	envelopeVersion = 1
	maxEnvelopeSize = 256 << 10
	maxRPIDLen      = 255
)

type envelope struct {
	V                 uint64 `cbor:"v"`
	RPID              string `cbor:"rpId"`
	ClientDataJSON    []byte `cbor:"clientDataJSON"`
	ClientDataHash    []byte `cbor:"clientDataHash"`
	AttestationObject []byte `cbor:"attestationObject"`
}

// encodeEnvelope never fails: a struct of one uint, one string and byte strings
// is always encodable.
func encodeEnvelope(e envelope) []byte {
	e.V = envelopeVersion
	b, _ := ctap2Enc.Marshal(e)
	return b
}

var envelopeDec, _ = cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	MaxNestedLevels:   4,
	MaxMapPairs:       16,
	MaxArrayElements:  16,
}.DecMode()

// decodeEnvelope reads an envelope from untrusted bytes. It checks structure
// only; the cryptography is the verifier's.
func decodeEnvelope(b []byte) (envelope, error) {
	var e envelope
	if len(b) > maxEnvelopeSize {
		return e, fmt.Errorf("the file is %d bytes, more than the %d accepted", len(b), maxEnvelopeSize)
	}
	rest, err := envelopeDec.UnmarshalFirst(b, &e)
	if err != nil {
		return envelope{}, fmt.Errorf("not an attestation envelope: %w", err)
	}
	if len(rest) != 0 {
		return envelope{}, errors.New("not an attestation envelope: trailing bytes")
	}
	if e.V != envelopeVersion {
		return envelope{}, fmt.Errorf("envelope version %d is not supported (this fido reads version %d)", e.V, envelopeVersion)
	}
	switch {
	case e.RPID == "" || len(e.RPID) > maxRPIDLen:
		return envelope{}, errors.New("envelope: rpId is empty or too long")
	case len(e.AttestationObject) == 0:
		return envelope{}, errors.New("envelope: attestationObject is empty")
	case len(e.ClientDataJSON) == 0:
		return envelope{}, errors.New("envelope: clientDataJSON is empty")
	case len(e.ClientDataHash) != sha256.Size:
		return envelope{}, fmt.Errorf("envelope: clientDataHash is %d bytes, not %d", len(e.ClientDataHash), sha256.Size)
	}
	return e, nil
}

// readEnvelopeFile reads at most maxEnvelopeSize+1 bytes of a regular file.
func readEnvelopeFile(path string) (envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return envelope{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxEnvelopeSize+1))
	if err != nil {
		return envelope{}, err
	}
	return decodeEnvelope(b)
}

// clientData is the part of clientDataJSON the offline check reads.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// verifyInputs derives what VerifyRegistrationAttested needs from an envelope:
// the challenge and origin written in clientDataJSON, and the attestation as
// attestationObject says it. The hash the key signed over must be the hash of
// the clientDataJSON the verifier will recompute.
func (e envelope) verifyInputs() (challenge []byte, origin string, att *authn.Attestation, err error) {
	if sum := sha256.Sum256(e.ClientDataJSON); !bytes.Equal(sum[:], e.ClientDataHash) {
		return nil, "", &authn.Attestation{}, errors.New("clientDataHash is not the SHA-256 of clientDataJSON: the attestation signature cannot verify over it")
	}
	var cd clientData
	if err := json.Unmarshal(e.ClientDataJSON, &cd); err != nil {
		return nil, "", &authn.Attestation{}, fmt.Errorf("clientDataJSON is not JSON: %w", err)
	}
	challenge, err = base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(challenge) == 0 {
		return nil, "", &authn.Attestation{}, errors.New("clientDataJSON has no base64url challenge")
	}
	var ao struct {
		Fmt      string          `cbor:"fmt"`
		AttStmt  cbor.RawMessage `cbor:"attStmt"`
		AuthData []byte          `cbor:"authData"`
	}
	if err := cbor.Unmarshal(e.AttestationObject, &ao); err != nil {
		return nil, "", &authn.Attestation{}, fmt.Errorf("attestationObject is not CBOR: %w", err)
	}
	parsed, err := authn.ParseAuthData(ao.AuthData)
	if err != nil {
		return nil, "", &authn.Attestation{}, fmt.Errorf("attestationObject authData: %w", err)
	}
	return challenge, cd.Origin, &authn.Attestation{Format: ao.Fmt, AuthData: ao.AuthData, Parsed: parsed, Statement: []byte(ao.AttStmt)}, nil
}
