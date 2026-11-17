// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// authenticatorBioEnrollment (CTAP 2.1 6.7), fingerprint modality.
//
// Which command byte depends on what getInfo declares (6.4): the option
// "bioEnroll" present (true: enrollments exist, false: none yet) means the
// final command 0x09 and a token with the be permission; "bioEnroll" absent but
// "userVerificationMgmtPreview" present means the prototype command, 0x40 in
// libfido2 (src/fido/param.h, CTAP_CBOR_BIO_ENROLL_PRE; the CTAP 2.1 PS text
// printed 0x41 for both prototype commands), and a token from the CTAP 2.0
// getPinToken, which has no permissions.
const (
	// CmdBioEnrollment is authenticatorBioEnrollment.
	CmdBioEnrollment byte = 0x09
	// CmdBioEnrollmentPreview is the prototype command of CTAP 2.1 PS keys that
	// declare userVerificationMgmtPreview instead of bioEnroll.
	CmdBioEnrollmentPreview byte = 0x40
)

// The request keys, subcommands and parameter keys of 6.7.
const (
	bioModality  = 0x01
	bioSub       = 0x02
	bioParams    = 0x03
	bioProtocol  = 0x04
	bioAuthParam = 0x05

	modalityFingerprint = 0x01

	subEnrollBegin  = 0x01
	subEnrollNext   = 0x02
	subEnrollCancel = 0x03
	subEnumerate    = 0x04
	subSetName      = 0x05
	subRemove       = 0x06
	subSensorInfo   = 0x07

	bpTemplateID = 0x01
	bpName       = 0x02
	bpTimeout    = 0x03

	brKind          = 0x02
	brMaxSamples    = 0x03
	brTemplateID    = 0x04
	brLastStatus    = 0x05
	brRemaining     = 0x06
	brTemplateInfos = 0x07
	brMaxName       = 0x08
)

// maxEnrollRounds bounds one enrollment, whatever the key claims it still
// needs: a counterfeit that always answers "one more sample" would otherwise
// keep a program waiting for a finger for ever.
const maxEnrollRounds = 256

// BioMode says which bio enrollment command a key speaks.
type BioMode int

// The modes.
const (
	// BioUnsupported: getInfo mentions neither option.
	BioUnsupported BioMode = iota
	// BioFinal is authenticatorBioEnrollment 0x09 ("bioEnroll" declared).
	BioFinal
	// BioPreview is the prototype command ("userVerificationMgmtPreview").
	BioPreview
)

// BioMode reads the options. The options are three-valued (6.4): false means
// "supported, nothing enrolled", so presence, not truth, decides.
func (i Info) BioMode() BioMode {
	if _, ok := i.Options["bioEnroll"]; ok {
		return BioFinal
	}
	if _, ok := i.Options["userVerificationMgmtPreview"]; ok {
		return BioPreview
	}
	return BioUnsupported
}

// Bio drives the fingerprint enrollment of one key.
type Bio struct {
	k    *Key
	cmd  byte
	perm Permissions
}

// Bio returns the enrollment interface the key declares in info, or an error
// when it declares none.
func (k *Key) Bio(info Info) (*Bio, error) {
	switch info.BioMode() {
	case BioFinal:
		return &Bio{k: k, cmd: CmdBioEnrollment, perm: PermBioEnrollment}, nil
	case BioPreview:
		return &Bio{k: k, cmd: CmdBioEnrollmentPreview}, nil
	}
	return nil, fmt.Errorf("fido: %s does not declare bio enrollment (neither bioEnroll nor userVerificationMgmtPreview)", k.t.Name())
}

// Permissions is what to ask [Key.PINToken] for: the be permission on a key
// with the final command, and zero (the CTAP 2.0 token, which has none) on a
// prototype one.
func (b *Bio) Permissions() Permissions { return b.perm }

// SampleStatus is lastEnrollSampleStatus (6.7).
type SampleStatus uint

// The sample statuses of 6.7.
const (
	SampleGood           SampleStatus = 0x00
	SampleTooHigh        SampleStatus = 0x01
	SampleTooLow         SampleStatus = 0x02
	SampleTooLeft        SampleStatus = 0x03
	SampleTooRight       SampleStatus = 0x04
	SampleTooFast        SampleStatus = 0x05
	SampleTooSlow        SampleStatus = 0x06
	SamplePoorQuality    SampleStatus = 0x07
	SampleTooSkewed      SampleStatus = 0x08
	SampleTooShort       SampleStatus = 0x09
	SampleMergeFailure   SampleStatus = 0x0A
	SampleAlreadyExists  SampleStatus = 0x0B
	SampleNoUserActivity SampleStatus = 0x0D
	SampleNoPresence     SampleStatus = 0x0E
)

var sampleNames = map[SampleStatus]string{
	SampleGood:           "good capture",
	SampleTooHigh:        "finger too high on the sensor",
	SampleTooLow:         "finger too low on the sensor",
	SampleTooLeft:        "finger too far left",
	SampleTooRight:       "finger too far right",
	SampleTooFast:        "moved too fast",
	SampleTooSlow:        "moved too slow",
	SamplePoorQuality:    "poor quality; clean the sensor and the finger",
	SampleTooSkewed:      "finger too skewed",
	SampleTooShort:       "touch too short",
	SampleMergeFailure:   "this sample could not be merged with the earlier ones",
	SampleAlreadyExists:  "this fingerprint is already enrolled",
	SampleNoUserActivity: "nothing touched the sensor",
	SampleNoPresence:     "lift the finger off the sensor between touches",
}

// String says what the status means to a person.
func (s SampleStatus) String() string {
	if n, ok := sampleNames[s]; ok {
		return n
	}
	return fmt.Sprintf("sample status %#02x", uint(s))
}

// EnrollStep is what the key reports after a sample.
type EnrollStep struct {
	// TemplateID names the enrollment under way; only enrollBegin returns it.
	TemplateID []byte
	// Status is how the last sample went.
	Status SampleStatus
	// Remaining is how many more good samples the key wants.
	Remaining int
}

// SensorInfo is getFingerprintSensorInfo.
type SensorInfo struct {
	// Touch is true for a touch sensor, false for a swipe sensor.
	Touch bool
	// MaxSamples is the good samples an enrollment needs, at most.
	MaxSamples int
	// MaxNameLength is the longest friendly name in bytes, or zero when unsaid.
	MaxNameLength int
}

// Enrollment is one enrolled fingerprint.
type Enrollment struct {
	ID   []byte
	Name string
}

// call sends one subcommand. params are CBOR-encoded ONCE and the same bytes
// are MACed and sent: the pinUvAuthParam covers modality || subCommand ||
// subCommandParams (6.7.4 and following), so re-encoding between the MAC and
// the wire would break the check.
func (b *Bio) call(ctx context.Context, tok *Token, sub int, params map[int]any) ([]byte, error) {
	if err := b.k.ctap2Ready(); err != nil {
		return nil, err
	}
	req := map[int]any{bioModality: modalityFingerprint, bioSub: sub}
	var pb []byte
	if len(params) > 0 {
		var err error
		if pb, err = ctap2.Marshal(params); err != nil {
			return nil, fmt.Errorf("fido: cannot encode the request: %w", err)
		}
		req[bioParams] = cbor.RawMessage(pb)
	}
	if tok != nil {
		if !tok.Valid() {
			return nil, fmt.Errorf("fido: bio enrollment needs a token (%s)", permHint(b.perm))
		}
		req[bioProtocol] = int(tok.Protocol())
		req[bioAuthParam] = tok.authParam(append([]byte{modalityFingerprint, byte(sub)}, pb...))
	}
	return b.k.cborCall(ctx, b.cmd, req)
}

func permHint(p Permissions) string {
	if p == 0 {
		return "from getPinToken"
	}
	return "from a PIN with the bio-enrollment permission"
}

// SensorInfo asks about the sensor. It needs no token.
func (b *Bio) SensorInfo(ctx context.Context) (SensorInfo, error) {
	body, err := b.call(ctx, nil, subSensorInfo, nil)
	if err != nil {
		return SensorInfo{}, err
	}
	return parseSensorInfo(body)
}

func parseSensorInfo(body []byte) (SensorInfo, error) {
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return SensorInfo{}, fmt.Errorf("fido: the sensor description is not a CBOR map: %w", err)
	}
	var kind uint
	if err := field(raw, brKind, &kind, "fingerprint kind"); err != nil {
		return SensorInfo{}, err
	}
	if kind != 1 && kind != 2 {
		return SensorInfo{}, fmt.Errorf("fido: the fingerprint kind is %d; 1 is touch and 2 is swipe", kind)
	}
	var s SensorInfo
	s.Touch = kind == 1
	if err := field(raw, brMaxSamples, &s.MaxSamples, "sample count"); err != nil {
		return SensorInfo{}, err
	}
	if m, ok := raw[brMaxName]; ok {
		if err := cbor.Unmarshal(m, &s.MaxNameLength); err != nil {
			return SensorInfo{}, fmt.Errorf("fido: the reply's name length: %w", err)
		}
	}
	if s.MaxSamples < 0 || s.MaxNameLength < 0 {
		return SensorInfo{}, fmt.Errorf("fido: the sensor reported a negative count")
	}
	return s, nil
}

func timeoutParams(base map[int]any, timeout time.Duration) map[int]any {
	if timeout > 0 {
		base[bpTimeout] = uint64(timeout / time.Millisecond)
	}
	return base
}

// EnrollBegin starts an enrollment and takes its first sample: enrollBegin
// (6.7.4). It cancels any enrollment the key had under way. timeout is the
// key's per-sample wait; zero leaves it to the key.
func (b *Bio) EnrollBegin(ctx context.Context, tok Token, timeout time.Duration) (EnrollStep, error) {
	body, err := b.call(ctx, &tok, subEnrollBegin, timeoutParams(map[int]any{}, timeout))
	if err != nil {
		return EnrollStep{}, err
	}
	return parseEnrollStep(body, true)
}

// EnrollNext takes the next sample of the enrollment id: enrollCaptureNextSample.
func (b *Bio) EnrollNext(ctx context.Context, tok Token, id []byte, timeout time.Duration) (EnrollStep, error) {
	body, err := b.call(ctx, &tok, subEnrollNext, timeoutParams(map[int]any{bpTemplateID: id}, timeout))
	if err != nil {
		return EnrollStep{}, err
	}
	step, err := parseEnrollStep(body, false)
	step.TemplateID = id
	return step, err
}

// EnrollCancel abandons the enrollment under way (6.7.5). It takes no token.
func (b *Bio) EnrollCancel(ctx context.Context) error {
	_, err := b.call(ctx, nil, subEnrollCancel, nil)
	return err
}

func parseEnrollStep(body []byte, wantID bool) (EnrollStep, error) {
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return EnrollStep{}, fmt.Errorf("fido: the enrollment reply is not a CBOR map: %w", err)
	}
	var s EnrollStep
	if wantID {
		if err := field(raw, brTemplateID, &s.TemplateID, "template id"); err != nil {
			return EnrollStep{}, err
		}
		if len(s.TemplateID) == 0 {
			return EnrollStep{}, fmt.Errorf("fido: the key began an enrollment with an empty template id")
		}
	}
	if err := field(raw, brLastStatus, &s.Status, "sample status"); err != nil {
		return EnrollStep{}, err
	}
	if err := field(raw, brRemaining, &s.Remaining, "remaining samples"); err != nil {
		return EnrollStep{}, err
	}
	if s.Remaining < 0 {
		return EnrollStep{}, fmt.Errorf("fido: the key wants %d more samples", s.Remaining)
	}
	return s, nil
}

// Enroll enrols a fingerprint: enrollBegin, then enrollCaptureNextSample until
// the key wants no more, calling progress after each sample (nil is allowed).
// It returns the new template id. If the context ends or a call fails midway,
// the enrollment is cancelled on the key, so none is left half-made.
//
// A sample that is not good (a finger too fast, off-centre, or not lifted) does
// not count: Remaining stays and the loop asks again. At most 256 rounds are
// made, whatever the key says.
func (b *Bio) Enroll(ctx context.Context, tok Token, timeout time.Duration, progress func(EnrollStep)) (id []byte, err error) {
	step, err := b.EnrollBegin(ctx, tok, timeout)
	if err != nil {
		return nil, err
	}
	id = step.TemplateID
	defer func() {
		if err != nil {
			// The caller's context may be the thing that ended; cancelling needs
			// its own, short, one.
			cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = b.EnrollCancel(cctx)
		}
	}()
	say := func(s EnrollStep) {
		if progress != nil {
			progress(s)
		}
	}
	say(step)
	for round := 1; step.Remaining > 0; round++ {
		if round > maxEnrollRounds {
			return nil, errors.New("fido: the key still wanted samples after 256 rounds; the enrollment was cancelled")
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if step, err = b.EnrollNext(ctx, tok, id, timeout); err != nil {
			return nil, err
		}
		say(step)
	}
	return id, nil
}

// Enumerate lists the enrolled fingerprints (6.7.6). A key with none answers
// CTAP2_ERR_INVALID_OPTION, which is an empty list here, not an error.
func (b *Bio) Enumerate(ctx context.Context, tok Token) ([]Enrollment, error) {
	body, err := b.call(ctx, &tok, subEnumerate, nil)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == StatusInvalidOption {
			return nil, nil
		}
		return nil, err
	}
	return parseEnrollments(body)
}

func parseEnrollments(body []byte) ([]Enrollment, error) {
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("fido: the enrollment list is not a CBOR map: %w", err)
	}
	var infos []map[uint64]cbor.RawMessage
	if err := field(raw, brTemplateInfos, &infos, "template list"); err != nil {
		return nil, err
	}
	out := make([]Enrollment, 0, len(infos))
	for i, m := range infos {
		var e Enrollment
		if err := field(m, bpTemplateID, &e.ID, "template id"); err != nil {
			return nil, fmt.Errorf("fido: template %d: %w", i, err)
		}
		if r, ok := m[bpName]; ok {
			if err := cbor.Unmarshal(r, &e.Name); err != nil {
				return nil, fmt.Errorf("fido: template %d's name: %w", i, err)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// Rename gives an enrollment a friendly name (6.7.7). A name longer than
// [SensorInfo.MaxNameLength] is refused by the key (CTAP1_ERR_INVALID_LENGTH).
func (b *Bio) Rename(ctx context.Context, tok Token, id []byte, name string) error {
	_, err := b.call(ctx, &tok, subSetName, map[int]any{bpTemplateID: id, bpName: name})
	return err
}

// Remove deletes an enrollment (6.7.8).
func (b *Bio) Remove(ctx context.Context, tok Token, id []byte) error {
	_, err := b.call(ctx, &tok, subRemove, map[int]any{bpTemplateID: id})
	return err
}
