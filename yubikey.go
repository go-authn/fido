// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// This file reads a YubiKey's device information -- serial number, firmware,
// form factor, and which applications are supported and enabled -- the way
// `ykman info` does, over the FIDO HID interface alone.
//
// # Where this comes from
//
// A port of Yubico's yubikey-manager 5.8.0 (tag "5.8.0", Apache-2.0 / BSD
// licensed Python), read as documentation:
//
//   - yubikit/management.py: CAPABILITY (l.66-79, 208-234 for the TLV tags),
//     FORM_FACTOR.from_code (l.180-185), DeviceInfo.parse_tlvs (l.340-418),
//     ManagementSession._do_read_device_info (l.647-661, the paging loop),
//     _ManagementCtapBackend (l.567-596: CTAP_VENDOR_FIRST = 0x40,
//     CTAP_READ_CONFIG = 0x42, the page number is one byte).
//   - yubikit/core/__init__.py: _tlv_parse (l.277-305), Tlv.parse_dict
//     (l.368-369), Version.from_bytes (l.64-65), bytes2int (l.273-274).
//
// Only the READ side is here. The write side (CTAP_WRITE_CONFIG, 0x43) changes
// what the key exposes and is deliberately absent.

// CmdYubiKeyReadConfig is Yubico's vendor CTAPHID command that returns one page
// of the management "device info" (CTAP_READ_CONFIG = CTAP_VENDOR_FIRST + 2 in
// yubikit/management.py l.567-570). The CTAPHID vendor range is 0x40-0x7F.
//
// Only a YubiKey knows it: another vendor may give the same number a meaning of
// its own, so [Key.YubiKeyInfo] must be called on a key known to be Yubico's
// (USB vendor id 0x1050), never to probe an unknown one.
const CmdYubiKeyReadConfig byte = 0x42

// maxYubiKeyPages bounds the paging loop. A YubiKey 5 uses two pages at most; a
// key that keeps saying "more data" is not a YubiKey.
const maxYubiKeyPages = 16

// YubiKeyCapability is a bit set of the applications a YubiKey carries
// (CAPABILITY in yubikit/management.py l.66-75).
type YubiKeyCapability uint32

// The application bits.
const (
	YubiKeyOTP     YubiKeyCapability = 0x01
	YubiKeyU2F     YubiKeyCapability = 0x02
	YubiKeyOpenPGP YubiKeyCapability = 0x08
	YubiKeyPIV     YubiKeyCapability = 0x10
	YubiKeyOATH    YubiKeyCapability = 0x20
	YubiKeyHSMAuth YubiKeyCapability = 0x100
	YubiKeyFIDO2   YubiKeyCapability = 0x200
)

// yubiKeyApps lists the named bits in display order.
var yubiKeyApps = []struct {
	Bit  YubiKeyCapability
	Name string
}{
	{YubiKeyOTP, "Yubico OTP"},
	{YubiKeyU2F, "FIDO U2F"},
	{YubiKeyFIDO2, "FIDO2"},
	{YubiKeyOATH, "OATH"},
	{YubiKeyPIV, "PIV"},
	{YubiKeyOpenPGP, "OpenPGP"},
	{YubiKeyHSMAuth, "YubiHSM Auth"},
}

// Applications returns the named applications in c in a fixed order,
// then one "Unknown(0x...)" entry for any bit this version does not name (the
// CCID bits 0x4 and 0x400 among them: yubikit/management.py l.126-134).
func (c YubiKeyCapability) Applications() []string {
	var out []string
	rest := c
	for _, a := range yubiKeyApps {
		if c&a.Bit != 0 {
			out = append(out, a.Name)
			rest &^= a.Bit
		}
	}
	if rest != 0 {
		out = append(out, fmt.Sprintf("Unknown(%#x)", uint32(rest)))
	}
	return out
}

// Has reports whether every bit in want is set.
func (c YubiKeyCapability) Has(want YubiKeyCapability) bool { return c&want == want }

// String lists the applications, or "none".
func (c YubiKeyCapability) String() string {
	if c == 0 {
		return "none"
	}
	return strings.Join(c.Applications(), ", ")
}

// UsesCCID reports whether c needs the smart-card (CCID) USB interface: the
// general CCID bit 0x4, management over CCID 0x400, or OATH, PIV, OpenPGP or
// YubiHSM Auth (CAPABILITY.usb_interfaces, yubikit/management.py l.130-135).
func (c YubiKeyCapability) UsesCCID() bool {
	return c&(0x4|0x400|YubiKeyOATH|YubiKeyPIV|YubiKeyOpenPGP|YubiKeyHSMAuth) != 0
}

// fromFIPS maps the FIPS bit field to applications (CAPABILITY._from_fips,
// yubikit/management.py l.81-94).
func fromFIPS(fips uint64) YubiKeyCapability {
	var c YubiKeyCapability
	for bit, app := range [...]YubiKeyCapability{YubiKeyFIDO2, YubiKeyPIV, YubiKeyOpenPGP, YubiKeyOATH, YubiKeyHSMAuth} {
		if fips&(1<<uint(bit)) != 0 {
			c |= app
		}
	}
	return c
}

// YubiKeyFormFactor is the physical form of the key (FORM_FACTOR,
// yubikit/management.py l.150-178).
type YubiKeyFormFactor uint8

// The form factors.
const (
	FormFactorUnknown      YubiKeyFormFactor = 0x00
	FormFactorUSBAKeychain YubiKeyFormFactor = 0x01
	FormFactorUSBANano     YubiKeyFormFactor = 0x02
	FormFactorUSBCKeychain YubiKeyFormFactor = 0x03
	FormFactorUSBCNano     YubiKeyFormFactor = 0x04
	FormFactorUSBCLightn   YubiKeyFormFactor = 0x05
	FormFactorUSBABio      YubiKeyFormFactor = 0x06
	FormFactorUSBCBio      YubiKeyFormFactor = 0x07
)

// String renders the form factor the way ykman does.
func (f YubiKeyFormFactor) String() string {
	switch f {
	case FormFactorUSBAKeychain:
		return "Keychain (USB-A)"
	case FormFactorUSBANano:
		return "Nano (USB-A)"
	case FormFactorUSBCKeychain:
		return "Keychain (USB-C)"
	case FormFactorUSBCNano:
		return "Nano (USB-C)"
	case FormFactorUSBCLightn:
		return "Keychain (USB-C, Lightning)"
	case FormFactorUSBABio:
		return "Bio (USB-A)"
	case FormFactorUSBCBio:
		return "Bio (USB-C)"
	}
	return "Unknown"
}

// YubiKeyVersion is a three-part firmware version.
type YubiKeyVersion struct{ Major, Minor, Patch uint8 }

// String renders "5.8.0".
func (v YubiKeyVersion) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// IsZero reports 0.0.0, which the firmware uses for "not reported".
func (v YubiKeyVersion) IsZero() bool { return v == YubiKeyVersion{} }

// less orders versions.
func (v YubiKeyVersion) less(w YubiKeyVersion) bool {
	if v.Major != w.Major {
		return v.Major < w.Major
	}
	if v.Minor != w.Minor {
		return v.Minor < w.Minor
	}
	return v.Patch < w.Patch
}

// YubiKeyReleaseType is the release channel of a firmware (RELEASE_TYPE,
// yubikit/management.py l.197-205).
type YubiKeyReleaseType uint8

// The release types.
const (
	ReleaseAlpha YubiKeyReleaseType = 0
	ReleaseBeta  YubiKeyReleaseType = 1
	ReleaseFinal YubiKeyReleaseType = 2
)

// String renders "alpha", "beta" or "final".
func (r YubiKeyReleaseType) String() string {
	switch r {
	case ReleaseAlpha:
		return "alpha"
	case ReleaseBeta:
		return "beta"
	case ReleaseFinal:
		return "final"
	}
	return fmt.Sprintf("unknown(%d)", uint8(r))
}

// YubiKeyVersionQualifier is the fully qualified firmware version.
type YubiKeyVersionQualifier struct {
	Version   YubiKeyVersion
	Type      YubiKeyReleaseType
	Iteration uint64
}

// String renders "5.8.0.final.0" (VersionQualifier.__str__, l.287-288).
func (q YubiKeyVersionQualifier) String() string {
	return fmt.Sprintf("%s.%s.%d", q.Version, q.Type, q.Iteration)
}

// YubiKeyInfo is what `ykman info` reads from a key (DeviceInfo,
// yubikit/management.py l.295-313).
type YubiKeyInfo struct {
	// Serial is the serial number; 0 when the key reports none (or hides it).
	Serial uint32
	// Version is the firmware version; for a pre-release it is the version the
	// key behaves as (l.391-395).
	Version YubiKeyVersion
	// VersionQualifier is the release channel and iteration.
	VersionQualifier YubiKeyVersionQualifier
	FormFactor       YubiKeyFormFactor
	// FIPS and SKY are the FIPS-series and Security Key-series flags carried in
	// the form-factor byte (0x80 and 0x40, l.347-348).
	FIPS, SKY bool

	// USBSupported and USBEnabled are the applications the key CAN carry over
	// USB, and those switched on now. NFC* are the same over NFC and are valid
	// only when HasNFC. On a YubiKey 4 USBEnabled is not reported (l.364-366)
	// and HasUSBEnabled is false.
	USBSupported, USBEnabled YubiKeyCapability
	HasUSBEnabled            bool
	NFCSupported, NFCEnabled YubiKeyCapability
	HasNFC                   bool

	// Locked is true when the configuration is protected by a lock code.
	Locked bool
	// AutoEjectTimeout, ChallengeResponseTimeout and DeviceFlags are the user
	// settings (l.353-355).
	AutoEjectTimeout         uint64
	ChallengeResponseTimeout uint64
	DeviceFlags              uint64
	NFCRestricted            bool
	// PartNumber is the part number; "" when absent or not UTF-8.
	PartNumber string
	// FIPSCapable and FIPSApproved are the applications that can be, and are,
	// in FIPS-approved mode (l.375-380).
	FIPSCapable, FIPSApproved YubiKeyCapability
	PINComplexity             bool
	// ResetBlocked is the applications whose reset is blocked.
	ResetBlocked YubiKeyCapability
	// FPSVersion and STMVersion are the fingerprint-sensor and STM firmware
	// versions of a Bio; nil when not reported or 0.0.0.
	FPSVersion, STMVersion *YubiKeyVersion
}

// The device-info TLV tags (yubikit/management.py l.208-234).
const (
	ykTagUSBSupported    = 0x01
	ykTagSerial          = 0x02
	ykTagUSBEnabled      = 0x03
	ykTagFormFactor      = 0x04
	ykTagVersion         = 0x05
	ykTagAutoEject       = 0x06
	ykTagChalRespTimeout = 0x07
	ykTagDeviceFlags     = 0x08
	ykTagConfigLock      = 0x0A
	ykTagNFCSupported    = 0x0D
	ykTagNFCEnabled      = 0x0E
	ykTagMoreData        = 0x10
	ykTagPartNumber      = 0x13
	ykTagFIPSCapable     = 0x14
	ykTagFIPSApproved    = 0x15
	ykTagPINComplexity   = 0x16
	ykTagNFCRestricted   = 0x17
	ykTagResetBlocked    = 0x18
	ykTagVersionQual     = 0x19
	ykTagFPSVersion      = 0x20
	ykTagSTMVersion      = 0x21
)

// ErrYubiKeyData means a YubiKey's device information is not well formed.
var ErrYubiKeyData = errors.New("fido: the YubiKey's device information is malformed")

func ykErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrYubiKeyData, fmt.Sprintf(format, a...))
}

// maxTLVDepth bounds the recursion of an indefinite-length TLV, which
// _tlv_parse (l.290-295) follows without a limit.
const maxTLVDepth = 8

// tlvParse is _tlv_parse (yubikit/core/__init__.py l.277-305): it returns the
// tag, the value's offset and length, and the end of the element. Where Python
// would raise IndexError (input too short) or build a Tlv whose length is not
// its end (a value cut short), this returns an error.
func tlvParse(data []byte, offset, depth int) (tag uint64, valOff, valLen, end int, err error) {
	if depth > maxTLVDepth {
		return 0, 0, 0, 0, ykErr("TLV nested more than %d deep", maxTLVDepth)
	}
	// Reading past the data yields 0 and sets short, which is checked once at
	// the end: a zero byte ends every loop below, so a truncated element
	// cannot make one run on.
	short := false
	at := func(i int) byte {
		if i >= len(data) {
			short = true
			return 0
		}
		return data[i]
	}
	b := at(offset)
	tag = uint64(b)
	offset++
	if b&0x1F == 0x1F { // long form
		b = at(offset)
		tag = tag<<8 | uint64(b)
		offset++
		for n := 0; b&0x80 == 0x80; n++ { // additional bytes
			if n >= 6 { // a tag wider than 8 bytes is not a tag
				return 0, 0, 0, 0, ykErr("TLV tag wider than 8 bytes")
			}
			b = at(offset)
			tag = tag<<8 | uint64(b)
			offset++
		}
	}
	ln := at(offset)
	offset++
	var length int
	if ln == 0x80 { // indefinite length: run until 0x0000
		e := offset
		for !(at(e) == 0 && at(e+1) == 0) {
			if _, _, _, e, err = tlvParse(data, e, depth+1); err != nil {
				return 0, 0, 0, 0, err
			}
		}
		length = e - offset
		end = e + 2
	} else {
		length = int(ln)
		if ln > 0x80 { // the length spans several bytes
			n := int(ln) - 0x80
			if n > 3 { // more than 24 bits: no int overflow on a 32-bit build, and no HID reply is that long
				return 0, 0, 0, 0, ykErr("TLV length of %d bytes", n)
			}
			length = 0
			for i := 0; i < n; i++ {
				length = length<<8 | int(at(offset+i))
			}
			offset += n
		}
		end = offset + length
	}
	if short || end > len(data) {
		// Python's Tlv.__init__ (l.347-349) raises "Incorrect TLV length" here.
		return 0, 0, 0, 0, ykErr("TLV runs past the data (%d bytes)", len(data))
	}
	return tag, offset, length, end, nil
}

// tlvDict is Tlv.parse_dict (l.367-369): the elements of data by tag, a later
// duplicate replacing an earlier one.
func tlvDict(data []byte) (map[uint64][]byte, error) {
	m := map[uint64][]byte{}
	for len(data) > 0 {
		tag, off, ln, end, err := tlvParse(data, 0, 0)
		if err != nil {
			return nil, err
		}
		m[tag] = data[off : off+ln]
		data = data[end:]
	}
	return m, nil
}

// bytesToInt is bytes2int (big endian). Python's integers are unbounded; a
// value wider than 8 bytes is refused here.
func bytesToInt(b []byte) (uint64, error) {
	if len(b) > 8 {
		return 0, ykErr("a %d-byte integer", len(b))
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// fields reads typed values out of the TLVs of a device-info reply and keeps
// the FIRST error, so the parser checks once, at the end, instead of after
// every field. A field that is absent reads as zero (data.get(tag, b"\0")).
type fields struct {
	d   map[uint64][]byte
	err error
}

func (f *fields) fail(err error) {
	if f.err == nil {
		f.err = err
	}
}

// int reads tag as a big-endian integer.
func (f *fields) int(tag uint64) uint64 {
	v, err := bytesToInt(f.d[tag])
	f.fail(err)
	return v
}

// version is Version.from_bytes: exactly three bytes.
func (f *fields) version(b []byte) YubiKeyVersion {
	if len(b) != 3 {
		f.fail(ykErr("a version of %d bytes, not 3", len(b)))
		return YubiKeyVersion{}
	}
	return YubiKeyVersion{b[0], b[1], b[2]}
}

// caps reads a capability field, which is at most 32 bits wide.
func (f *fields) caps(tag uint64) YubiKeyCapability {
	v := f.int(tag)
	if v > 0xFFFFFFFF {
		f.fail(ykErr("capabilities %#x are wider than 32 bits", v))
	}
	return YubiKeyCapability(v)
}

// flag is `d.get(tag) == b"\x01"`.
func (f *fields) flag(tag uint64) bool { return string(f.d[tag]) == "\x01" }

// parseYubiKeyTLVs is DeviceInfo.parse_tlvs (yubikit/management.py l.340-418)
// applied to the TLVs of every page already joined by tag (a later page
// replacing an earlier one, as ManagementSession._do_read_device_info does).
// defaultVersion is the firmware version the transport reported, used when the
// key sends none.
func parseYubiKeyTLVs(d map[uint64][]byte, defaultVersion YubiKeyVersion) (YubiKeyInfo, error) {
	f := &fields{d: d}
	var in YubiKeyInfo
	in.Locked = f.flag(ykTagConfigLock)
	serial := f.int(ykTagSerial)
	if serial > 0xFFFFFFFF {
		f.fail(ykErr("serial %d is wider than 32 bits", serial))
	}
	in.Serial = uint32(serial)
	ff := f.int(ykTagFormFactor)
	// FORM_FACTOR.from_code: the low nibble; a code that is not a member is
	// Unknown (l.180-185).
	if code := ff & 0xF; code <= uint64(FormFactorUSBCBio) {
		in.FormFactor = YubiKeyFormFactor(code)
	}
	in.FIPS, in.SKY = ff&0x80 != 0, ff&0x40 != 0
	version := defaultVersion
	if v, ok := d[ykTagVersion]; ok {
		version = f.version(v)
	}
	in.AutoEjectTimeout = f.int(ykTagAutoEject)
	in.ChallengeResponseTimeout = f.int(ykTagChalRespTimeout)
	in.DeviceFlags = f.int(ykTagDeviceFlags)

	if version == (YubiKeyVersion{4, 2, 4}) { // doesn't report correctly (l.360)
		in.USBSupported = 0x3F
	} else {
		if _, ok := d[ykTagUSBSupported]; !ok {
			f.fail(ykErr("no supported-USB-applications field"))
		}
		in.USBSupported = f.caps(ykTagUSBSupported)
	}
	// From YubiKey 5.0.0; broken on YubiKey 4: 4.0.0 <= version < 5.0.0 (l.365).
	if _, ok := d[ykTagUSBEnabled]; ok && version.Major != 4 {
		in.USBEnabled = f.caps(ykTagUSBEnabled)
		in.HasUSBEnabled = true
	}
	if _, ok := d[ykTagNFCSupported]; ok { // a YubiKey with NFC
		in.NFCSupported = f.caps(ykTagNFCSupported)
		if _, ok := d[ykTagNFCEnabled]; !ok {
			f.fail(ykErr("NFC supported but no NFC-enabled field"))
		}
		in.NFCEnabled = f.caps(ykTagNFCEnabled)
		in.HasNFC = true
	}
	in.NFCRestricted = f.flag(ykTagNFCRestricted)
	if pn := d[ykTagPartNumber]; utf8.Valid(pn) {
		in.PartNumber = string(pn)
	}
	in.FIPSCapable = fromFIPS(f.int(ykTagFIPSCapable))
	in.FIPSApproved = fromFIPS(f.int(ykTagFIPSApproved))
	in.PINComplexity = f.flag(ykTagPINComplexity)
	in.ResetBlocked = f.caps(ykTagResetBlocked)
	if vq := d[ykTagVersionQual]; len(vq) > 0 {
		qd, err := tlvDict(vq)
		f.fail(err)
		q := fields{d: qd}
		for _, t := range [...]uint64{1, 2, 3} {
			if _, ok := qd[t]; !ok {
				f.fail(ykErr("version qualifier lacks field %d", t))
			}
		}
		rt := q.int(2)
		in.VersionQualifier = YubiKeyVersionQualifier{
			Version: q.version(qd[1]), Type: YubiKeyReleaseType(rt), Iteration: q.int(3),
		}
		f.fail(q.err)
		if rt > uint64(ReleaseFinal) {
			f.fail(ykErr("release type %d", rt)) // RELEASE_TYPE(n) raises (l.388)
		}
		if in.VersionQualifier.Type != ReleaseFinal { // the behavioural version (l.391-395)
			version = in.VersionQualifier.Version
		}
	} else {
		in.VersionQualifier = YubiKeyVersionQualifier{Version: version, Type: ReleaseFinal}
	}
	in.Version = version
	for _, p := range [...]struct {
		tag uint64
		to  **YubiKeyVersion
	}{{ykTagFPSVersion, &in.FPSVersion}, {ykTagSTMVersion, &in.STMVersion}} {
		raw, ok := d[p.tag]
		if !ok {
			continue // default b"\0\0\0": zero, so None
		}
		if fv := f.version(raw); !fv.IsZero() {
			*p.to = &fv
		}
	}
	return in, f.err
}

// ParseYubiKeyPages is ManagementSession._do_read_device_info (l.647-661) over
// pages already read: each is a length byte then TLVs, the length equal to the
// rest. It joins pages while the more-data flag (tag 0x10) is set, and refuses
// a last page that still asks for more.
func ParseYubiKeyPages(pages [][]byte, defaultVersion YubiKeyVersion) (YubiKeyInfo, error) {
	j := pageJoiner{}
	for _, p := range pages {
		more, err := j.add(p)
		if err != nil {
			return YubiKeyInfo{}, err
		}
		if !more {
			return parseYubiKeyTLVs(j.all, defaultVersion)
		}
	}
	return YubiKeyInfo{}, ykErr("the last page asks for more")
}

// pageJoiner merges the TLVs of successive pages by tag.
type pageJoiner struct {
	all   map[uint64][]byte
	pages int
}

// add reads one page and says whether the key has more to send.
func (j *pageJoiner) add(p []byte) (more bool, err error) {
	j.pages++
	if len(p) == 0 || len(p)-1 != int(p[0]) {
		return false, ykErr("page %d: the length byte does not match the %d bytes", j.pages-1, len(p))
	}
	d, err := tlvDict(p[1:])
	if err != nil {
		return false, err
	}
	if j.all == nil {
		j.all = map[uint64][]byte{}
	}
	more = string(d[ykTagMoreData]) == "\x01"
	delete(d, ykTagMoreData)
	for k, v := range d {
		j.all[k] = v
	}
	return more, nil
}

// ParseYubiKeyInfo parses ONE page of device information, the whole of it for
// every YubiKey 5.
func ParseYubiKeyInfo(page []byte, defaultVersion YubiKeyVersion) (YubiKeyInfo, error) {
	return ParseYubiKeyPages([][]byte{page}, defaultVersion)
}

// yubiKeyBase is _ManagementCtapBackend.__init__ (l.573-583): before the
// YubiKey 4 the CTAPHID version was not the firmware's, so a key that says
// major < 4 is guessed to be a NEO (3.0.0) unless it is a 0.x with CTAP2.
func yubiKeyBase(v Version, caps Capabilities) YubiKeyVersion {
	fw := YubiKeyVersion{v.Major, v.Minor, v.Build}
	if fw.Major < 4 && fw != (YubiKeyVersion{0, 0, 1}) {
		if !(fw.Major == 0 && caps.Has(CapCBOR)) {
			fw = YubiKeyVersion{3, 0, 0}
		}
	}
	return fw
}

// YubiKeyInfo reads the key's device information over CTAPHID, the way
// `ykman info` does. It only READS: nothing on the key changes.
//
// The key must be a YubiKey (USB vendor id 0x1050): the command is a vendor
// one, and another vendor's key may give number [CmdYubiKeyReadConfig] a
// meaning of its own. A key of another make answers with an error at best.
//
// Firmware before 4.1.0 cannot be asked (require_version, l.644) and is
// refused.
func (k *Key) YubiKeyInfo(ctx context.Context) (YubiKeyInfo, error) {
	return readYubiKeyInfo(ctx, k.roundTrip, k.version, k.caps)
}

// readYubiKeyInfo is YubiKeyInfo with its transport injected.
func readYubiKeyInfo(ctx context.Context, call func(context.Context, byte, []byte) ([]byte, error), v Version, caps Capabilities) (YubiKeyInfo, error) {
	fw := yubiKeyBase(v, caps)
	read := func() (YubiKeyInfo, error) {
		j := pageJoiner{}
		for page := 0; page < maxYubiKeyPages; page++ {
			p, err := call(ctx, CmdYubiKeyReadConfig, []byte{byte(page)})
			if err != nil {
				return YubiKeyInfo{}, err
			}
			more, err := j.add(p)
			if err != nil {
				return YubiKeyInfo{}, err
			}
			if !more {
				return parseYubiKeyTLVs(j.all, fw)
			}
		}
		return YubiKeyInfo{}, ykErr("more than %d pages", maxYubiKeyPages)
	}
	if fw == (YubiKeyVersion{0, 0, 1}) { // a development build: ask the key (l.617-619)
		in, err := read()
		if err != nil {
			return YubiKeyInfo{}, err
		}
		fw = in.VersionQualifier.Version
		if fw.less(YubiKeyVersion{4, 1, 0}) {
			return YubiKeyInfo{}, fmt.Errorf("fido: firmware %s is older than 4.1.0, which cannot report device information", fw)
		}
		return in, nil
	}
	if fw.less(YubiKeyVersion{4, 1, 0}) {
		return YubiKeyInfo{}, fmt.Errorf("fido: firmware %s is older than 4.1.0, which cannot report device information", fw)
	}
	return read()
}
