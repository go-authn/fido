// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

// tlv encodes one element the way Tlv.__new__ does (yubikit/core/__init__.py
// l.321-337): a length under 0x80 in one byte, else 0x80|n and n bytes.
func tlv(tag byte, val ...byte) []byte {
	out := []byte{tag}
	switch n := len(val); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, val...)
}

// page is one device-info page: a length byte, then the elements.
func page(elems ...[]byte) []byte {
	body := bytes.Join(elems, nil)
	return append([]byte{byte(len(body))}, body...)
}

// bioPage is what a YubiKey Bio - FIDO Edition 5.8.0 reports, as far as the
// fields go: USB FIDO2+U2F supported and enabled, no NFC, form factor 6.
func bioPage() []byte {
	return page(
		tlv(ykTagUSBSupported, 0x02, 0x02),
		tlv(ykTagSerial, 0x00, 0x12, 0xD6, 0x87), // 1234567
		tlv(ykTagUSBEnabled, 0x02, 0x02),
		tlv(ykTagFormFactor, 0x06),
		tlv(ykTagVersion, 5, 8, 0),
		tlv(ykTagAutoEject, 0, 0),
		tlv(ykTagChalRespTimeout, 0),
		tlv(ykTagDeviceFlags, 0),
		tlv(ykTagConfigLock, 0),
		tlv(ykTagPartNumber, []byte("YK5-BIO")...),
		tlv(ykTagFIPSCapable, 0),
		tlv(ykTagFIPSApproved, 0),
		tlv(ykTagPINComplexity, 0),
		tlv(ykTagResetBlocked, 0),
		tlv(ykTagFPSVersion, 1, 2, 3),
		tlv(ykTagSTMVersion, 0, 0, 0),
	)
}

func TestAYubiKeyBioIsRead(t *testing.T) {
	in, err := ParseYubiKeyInfo(bioPage(), YubiKeyVersion{5, 8, 0})
	if err != nil {
		t.Fatal(err)
	}
	if in.Serial != 1234567 || in.Version != (YubiKeyVersion{5, 8, 0}) || in.FormFactor != FormFactorUSBABio {
		t.Fatalf("%+v", in)
	}
	if in.USBSupported != YubiKeyFIDO2|YubiKeyU2F || in.USBEnabled != in.USBSupported || !in.HasUSBEnabled || in.HasNFC {
		t.Fatalf("%+v", in)
	}
	if in.USBEnabled.Has(YubiKeyPIV) || in.USBEnabled.UsesCCID() {
		t.Fatalf("PIV or CCID reported on a FIDO-only key: %+v", in)
	}
	if in.PartNumber != "YK5-BIO" || in.Locked || in.FIPS || in.SKY || in.PINComplexity {
		t.Fatalf("%+v", in)
	}
	if in.FPSVersion == nil || *in.FPSVersion != (YubiKeyVersion{1, 2, 3}) || in.STMVersion != nil {
		t.Fatalf("fps %v stm %v", in.FPSVersion, in.STMVersion)
	}
	if got := in.VersionQualifier.String(); got != "5.8.0.final.0" {
		t.Fatal(got)
	}
	if got := in.USBEnabled.String(); got != "FIDO U2F, FIDO2" {
		t.Fatal(got)
	}
}

func TestACCIDKeyReportsItsApplications(t *testing.T) {
	// A YubiKey 5 NFC: everything over USB, everything but OTP... enabled.
	p := page(
		tlv(ykTagUSBSupported, 0x03, 0x39), // OTP U2F OPENPGP PIV OATH HSMAUTH FIDO2
		tlv(ykTagUSBEnabled, 0x02, 0x23),   // U2F FIDO2 OTP OATH
		tlv(ykTagNFCSupported, 0x03, 0x39),
		tlv(ykTagNFCEnabled, 0x00, 0x00),
		tlv(ykTagFormFactor, 0x43), // SKY, USB-C keychain
		tlv(ykTagVersion, 5, 4, 3),
	)
	in, err := ParseYubiKeyInfo(p, YubiKeyVersion{5, 4, 3})
	if err != nil {
		t.Fatal(err)
	}
	if !in.HasNFC || in.NFCSupported != 0x339 || in.NFCEnabled != 0 || !in.SKY || in.FIPS || in.FormFactor != FormFactorUSBCKeychain {
		t.Fatalf("%+v", in)
	}
	if !in.USBEnabled.UsesCCID() || in.USBEnabled.Has(YubiKeyPIV) || !in.USBSupported.Has(YubiKeyPIV) {
		t.Fatalf("PIV supported but not enabled expected: %+v", in)
	}
	if in.Serial != 0 {
		t.Fatalf("serial %d", in.Serial)
	}
}

func TestPagesAreJoinedWhileMoreDataIsSet(t *testing.T) {
	p0 := page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagMoreData, 1), tlv(ykTagFormFactor, 0x01))
	p1 := page(tlv(ykTagSerial, 0x00, 0x00, 0x01, 0x00), tlv(ykTagVersion, 5, 7, 4))
	in, err := ParseYubiKeyPages([][]byte{p0, p1}, YubiKeyVersion{})
	if err != nil {
		t.Fatal(err)
	}
	if in.Serial != 256 || in.FormFactor != FormFactorUSBAKeychain || in.Version != (YubiKeyVersion{5, 7, 4}) {
		t.Fatalf("%+v", in)
	}
	if _, err := ParseYubiKeyPages([][]byte{p0}, YubiKeyVersion{}); !errors.Is(err, ErrYubiKeyData) {
		t.Fatalf("a last page that asks for more: %v", err)
	}
	if _, err := ParseYubiKeyPages(nil, YubiKeyVersion{}); !errors.Is(err, ErrYubiKeyData) {
		t.Fatalf("no pages: %v", err)
	}
}

func TestVersionRulesOfDeviceInfo(t *testing.T) {
	// YubiKey 4: USB-enabled is "broken", so it is not reported (l.365).
	p4 := page(tlv(ykTagUSBSupported, 0x00, 0x3F), tlv(ykTagUSBEnabled, 0x00, 0x01), tlv(ykTagVersion, 4, 3, 7))
	in, err := ParseYubiKeyInfo(p4, YubiKeyVersion{})
	if err != nil || in.HasUSBEnabled || in.USBEnabled != 0 {
		t.Fatalf("%+v %v", in, err)
	}
	// 4.2.4 does not report its supported applications: 0x3F (l.360), so a
	// page without the tag is fine.
	if in, err = ParseYubiKeyInfo(page(tlv(ykTagVersion, 4, 2, 4)), YubiKeyVersion{}); err != nil || in.USBSupported != 0x3F {
		t.Fatalf("%+v %v", in, err)
	}
	// Elsewhere a page without it is refused (KeyError in Python).
	if _, err = ParseYubiKeyInfo(page(tlv(ykTagVersion, 5, 2, 4)), YubiKeyVersion{}); !errors.Is(err, ErrYubiKeyData) {
		t.Fatal(err)
	}
	// With no version tag the transport's is used.
	in, err = ParseYubiKeyInfo(page(tlv(ykTagUSBSupported, 0x02, 0x03)), YubiKeyVersion{5, 1, 2})
	if err != nil || in.Version != (YubiKeyVersion{5, 1, 2}) || in.VersionQualifier.Version != in.Version || in.VersionQualifier.Type != ReleaseFinal {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestAPreReleaseOverridesTheBehaviouralVersion(t *testing.T) {
	q := append(append(tlv(1, 5, 8, 1), tlv(2, 1)...), tlv(3, 4)...)
	p := page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagVersion, 5, 8, 0), tlv(ykTagVersionQual, q...))
	in, err := ParseYubiKeyInfo(p, YubiKeyVersion{})
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != (YubiKeyVersion{5, 8, 1}) || in.VersionQualifier.String() != "5.8.1.beta.4" {
		t.Fatalf("%+v", in)
	}
	// A final release keeps the version tag's value.
	q = append(append(tlv(1, 5, 8, 1), tlv(2, 2)...), tlv(3, 0)...)
	p = page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagVersion, 5, 8, 0), tlv(ykTagVersionQual, q...))
	if in, err = ParseYubiKeyInfo(p, YubiKeyVersion{}); err != nil || in.Version != (YubiKeyVersion{5, 8, 0}) {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestFIPSFlagsAndFormFactorCodes(t *testing.T) {
	p := page(
		tlv(ykTagUSBSupported, 0x02, 0x3B), tlv(ykTagVersion, 5, 4, 2),
		tlv(ykTagFormFactor, 0xC3), tlv(ykTagFIPSCapable, 0x1F), tlv(ykTagFIPSApproved, 0x03),
		tlv(ykTagPartNumber, 0xFF, 0xFE), // not UTF-8: no part number, not an error
		tlv(ykTagNFCRestricted, 1), tlv(ykTagConfigLock, 1),
	)
	in, err := ParseYubiKeyInfo(p, YubiKeyVersion{})
	if err != nil {
		t.Fatal(err)
	}
	if !in.FIPS || !in.SKY || in.FormFactor != FormFactorUSBCKeychain {
		t.Fatalf("%+v", in)
	}
	if want := YubiKeyFIDO2 | YubiKeyPIV | YubiKeyOpenPGP | YubiKeyOATH | YubiKeyHSMAuth; in.FIPSCapable != want {
		t.Fatalf("capable %v", in.FIPSCapable)
	}
	if in.FIPSApproved != YubiKeyFIDO2|YubiKeyPIV || in.PartNumber != "" || !in.NFCRestricted || !in.Locked {
		t.Fatalf("%+v", in)
	}
	// A form factor code that is no member is Unknown (l.185).
	if in, _ = ParseYubiKeyInfo(page(tlv(ykTagUSBSupported, 2), tlv(ykTagFormFactor, 0x0F)), YubiKeyVersion{}); in.FormFactor != FormFactorUnknown {
		t.Fatalf("%v", in.FormFactor)
	}
}

func TestDeviceInfoNamesTheBitsItDoesNotKnow(t *testing.T) {
	c := YubiKeyCapability(0x4 | 0x400 | YubiKeyPIV)
	if got := c.String(); got != "PIV, Unknown(0x404)" {
		t.Fatal(got)
	}
	if YubiKeyCapability(0).String() != "none" || !YubiKeyCapability(0x4).UsesCCID() || YubiKeyCapability(0x203).UsesCCID() {
		t.Fatal("none or CCID wrong")
	}
	if FormFactorUSBCLightn.String() != "Keychain (USB-C, Lightning)" || YubiKeyFormFactor(9).String() != "Unknown" {
		t.Fatal("form factor names")
	}
	if ReleaseBeta.String() != "beta" || YubiKeyReleaseType(9).String() != "unknown(9)" {
		t.Fatal("release names")
	}
}

func TestMalformedDeviceInfoIsRefused(t *testing.T) {
	good := bioPage()
	nine := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	usb := tlv(ykTagUSBSupported, 2)
	qual := func(elems ...[]byte) []byte { return page(usb, tlv(ykTagVersionQual, slices.Concat(elems...)...)) }
	// Ordered: a refusal that a mutant would turn into a crash comes after
	// the ones that it would turn into a wrong answer, so a failing run
	// prints an assertion before it dies.
	cases := []struct {
		name string
		page []byte
		want string // a piece of the error, which says WHICH guard refused
	}{
		{"length byte too big", append([]byte{byte(len(good) + 5)}, good[1:]...), "length byte"},
		{"length byte too small", []byte{0, ykTagSerial, 1, 1}, "length byte"},
		{"value runs past", []byte{2, ykTagSerial, 5}, "runs past"},
		{"truncated element", []byte{3, ykTagSerial, 4, 1}, "runs past"},
		{"no length", []byte{1, ykTagSerial}, "runs past"},
		{"a 4-byte version", page(usb, tlv(ykTagVersion, 5, 8, 0, 1)), "a version of 4 bytes"},
		{"a 2-byte version", page(usb, tlv(ykTagVersion, 5, 8)), "a version of 2 bytes"},
		{"9-byte serial", page(usb, tlv(ykTagSerial, nine...)), "9-byte integer"},
		{"9-byte auto-eject", page(usb, tlv(ykTagAutoEject, nine...)), "9-byte integer"},
		{"9-byte timeout", page(usb, tlv(ykTagChalRespTimeout, nine...)), "9-byte integer"},
		{"9-byte flags", page(usb, tlv(ykTagDeviceFlags, nine...)), "9-byte integer"},
		{"9-byte form factor", page(usb, tlv(ykTagFormFactor, nine...)), "9-byte integer"},
		{"9-byte FIPS capable", page(usb, tlv(ykTagFIPSCapable, nine...)), "9-byte integer"},
		{"9-byte FIPS approved", page(usb, tlv(ykTagFIPSApproved, nine...)), "9-byte integer"},
		{"serial over 32 bits", page(usb, tlv(ykTagSerial, 1, 0, 0, 0, 0)), "serial"},
		{"USB supported over 32 bits", page(tlv(ykTagUSBSupported, 1, 0, 0, 0, 0)), "wider than 32 bits"},
		{"USB enabled over 32 bits", page(usb, tlv(ykTagUSBEnabled, 1, 0, 0, 0, 0)), "wider than 32 bits"},
		{"NFC supported over 32 bits", page(usb, tlv(ykTagNFCSupported, 1, 0, 0, 0, 0), tlv(ykTagNFCEnabled, 0)), "wider than 32 bits"},
		{"NFC enabled over 32 bits", page(usb, tlv(ykTagNFCSupported, 0), tlv(ykTagNFCEnabled, 1, 0, 0, 0, 0)), "wider than 32 bits"},
		{"reset blocked over 32 bits", page(usb, tlv(ykTagResetBlocked, 1, 0, 0, 0, 0)), "wider than 32 bits"},
		{"no supported-USB field", page(tlv(ykTagVersion, 5, 8, 0)), "no supported-USB"},
		{"NFC without enabled", page(usb, tlv(ykTagNFCSupported, 2)), "NFC-enabled"},
		{"qualifier lacks type", qual(tlv(1, 5, 8, 0)), "lacks field"},
		{"qualifier lacks version", qual(tlv(2, 0), tlv(3, 0)), "lacks field"},
		{"qualifier lacks iteration", qual(tlv(1, 5, 8, 0), tlv(2, 0)), "lacks field"},
		{"qualifier unknown release type", qual(tlv(1, 5, 8, 0), tlv(2, 3), tlv(3, 0)), "release type"},
		{"qualifier 9-byte iteration", qual(tlv(1, 5, 8, 0), tlv(2, 0), tlv(3, nine...)), "9-byte integer"},
		{"qualifier 9-byte release type", qual(tlv(1, 5, 8, 0), tlv(2, nine...), tlv(3, 0)), "9-byte integer"},
		{"qualifier 2-byte version", qual(tlv(1, 5, 8), tlv(2, 0), tlv(3, 0)), "a version of 2 bytes"},
		{"qualifier is not TLV", page(usb, tlv(ykTagVersionQual, 1, 9)), "runs past"},
		{"FPS version of 4 bytes", page(usb, tlv(ykTagFPSVersion, 1, 2, 3, 4)), "a version of 4 bytes"},
		{"STM version of 2 bytes", page(usb, tlv(ykTagSTMVersion, 1, 2)), "a version of 2 bytes"},
		{"indefinite length unfinished", []byte{4, 0x30, 0x80, 0x01, 0x00}, "runs past"},
		{"empty", []byte{}, "length byte"},
	}
	for _, c := range cases {
		_, err := ParseYubiKeyInfo(c.page, YubiKeyVersion{5, 8, 0})
		if !errors.Is(err, ErrYubiKeyData) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want ...%q...)", c.name, err, c.want)
		}
	}
}

// tlvParse is called with data cut short and must answer with an error, never
// a crash and never an end past the data. A crash is reported as a failure
// here, so a guard that is gone fails by an assertion before anything slices.
func TestATruncatedTLVIsRefusedByTheParserItself(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"value cut short", []byte{0x01, 0x05, 1}, "runs past"},
		{"a 3-byte length past the data", []byte{0x01, 0x83, 0x01, 0x00, 0x00, 7}, "runs past"},
		{"no length", []byte{0x01}, "runs past"},
		{"empty", []byte{}, "runs past"},
		{"a long tag cut short", []byte{0x1F}, "runs past"},
		{"a long tag whose last byte is missing", []byte{0x1F, 0x80}, "runs past"},
		{"an unfinished indefinite length", []byte{0x30, 0x80, 0x01, 0x00}, "runs past"},
		{"a failing element inside an indefinite one", []byte{0x30, 0x80, 0x01, 0x84, 0, 0, 0, 1, 7}, "4 bytes"},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", c.name, r)
				}
			}()
			_, _, _, end, err := tlvParse(c.data, 0, 0)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: end %d, %v (want ...%q...)", c.name, end, err, c.want)
			}
		}()
	}
}

func TestATLVThatIsNotATLVIsRefused(t *testing.T) {
	// nest(n) is n indefinite-length elements inside one another, finished.
	nest := func(n int) []byte {
		d := []byte{}
		for i := 0; i < n; i++ {
			d = slices.Concat([]byte{0x30, 0x80}, d, []byte{0, 0})
		}
		return d
	}
	if _, err := tlvDict(nest(maxTLVDepth + 1)); err != nil {
		t.Fatalf("the deepest allowed nesting: %v", err)
	}
	if _, err := tlvDict(nest(maxTLVDepth + 2)); err == nil || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("one level too deep: %v", err)
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"a tag of 10 bytes", slices.Concat([]byte{0x1F}, bytes.Repeat([]byte{0xFF}, 9), []byte{0x00, 0x00}), "wider than 8"},
		{"a tag of 9 bytes, well finished", slices.Concat([]byte{0x1F}, bytes.Repeat([]byte{0xFF}, 7), []byte{0x7F, 0x01, 0x05}), "wider than 8"},
		{"a 4-byte length", []byte{0x01, 0x84, 0, 0, 0, 1, 7}, "4 bytes"},
		{"a 3-byte length past the data", []byte{0x01, 0x83, 0x01, 0x00, 0x00, 7}, "runs past"},
		{"a 2-byte length past the data", []byte{0x01, 0x82, 0x00}, "runs past"},
		{"a long tag cut short", []byte{0x1F}, "runs past"},
		{"a long tag whose last byte is missing", []byte{0x1F, 0x80}, "runs past"},
		{"an empty element list is no element", []byte{0x01}, "runs past"},
	}
	for _, c := range cases {
		if _, err := tlvDict(c.data); !errors.Is(err, ErrYubiKeyData) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want ...%q...)", c.name, err, c.want)
		}
	}
	// 8 continuation bytes after the first is the widest tag that fits.
	d, err := tlvDict(slices.Concat([]byte{0x1F}, bytes.Repeat([]byte{0xFF}, 6), []byte{0x7F, 0x01, 0x05}))
	if err != nil || len(d) != 1 {
		t.Fatalf("%v %v", d, err)
	}
	// A 3-byte length that is within the data is read.
	d, err = tlvDict(slices.Concat([]byte{0x05, 0x83, 0x00, 0x01, 0x00}, bytes.Repeat([]byte{9}, 256)))
	if err != nil || len(d[5]) != 256 {
		t.Fatalf("%v %v", len(d[5]), err)
	}
}

// The TLV reader is _tlv_parse: long tags, multi-byte lengths, indefinite
// length ending at 0x0000.
func TestTLVForms(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 300)
	d, err := tlvDict(slices.Concat(tlv(0x21, long...), tlv(0x22, 1), []byte{0x5F, 0x2D, 0x02, 0xAA, 0xBB}, []byte{0x30, 0x80, 0x01, 0x01, 0x07, 0x00, 0x00}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d[0x21], long) || !bytes.Equal(d[0x22], []byte{1}) {
		t.Fatal("definite lengths")
	}
	if !bytes.Equal(d[0x5F2D], []byte{0xAA, 0xBB}) {
		t.Fatalf("long-form tag: %x", d[0x5F2D])
	}
	if !bytes.Equal(d[0x30], []byte{0x01, 0x01, 0x07}) {
		t.Fatalf("indefinite length: %x", d[0x30])
	}
	// A later duplicate replaces an earlier one (dict()).
	d, err = tlvDict(slices.Concat(tlv(9, 1), tlv(9, 2)))
	if err != nil || !bytes.Equal(d[9], []byte{2}) {
		t.Fatalf("%v %v", d, err)
	}
	// Nesting without end is bounded rather than followed forever.
	deep := bytes.Repeat([]byte{0x30, 0x80}, 100)
	if _, err = tlvDict(deep); !errors.Is(err, ErrYubiKeyData) {
		t.Fatal(err)
	}
}

// scripted answers CTAPHID calls for readYubiKeyInfo.
type scripted struct {
	pages [][]byte
	asked [][]byte
	err   error
}

func (s *scripted) call(_ context.Context, cmd byte, data []byte) ([]byte, error) {
	if cmd != CmdYubiKeyReadConfig {
		panic("only the read-config command may be sent")
	}
	s.asked = append(s.asked, slices.Clone(data))
	if s.err != nil {
		return nil, s.err
	}
	i := len(s.asked) - 1
	if i >= len(s.pages) {
		return s.pages[len(s.pages)-1], nil
	}
	return s.pages[i], nil
}

func TestReadingAsksForEachPageByNumber(t *testing.T) {
	s := &scripted{pages: [][]byte{
		page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagMoreData, 1)),
		page(tlv(ykTagVersion, 5, 8, 0)),
	}}
	in, err := readYubiKeyInfo(context.Background(), s.call, Version{CTAPHID: 2, Major: 5, Minor: 8}, CapCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != (YubiKeyVersion{5, 8, 0}) || len(s.asked) != 2 || s.asked[0][0] != 0 || s.asked[1][0] != 1 || len(s.asked[0]) != 1 {
		t.Fatalf("%+v asked %x", in, s.asked)
	}
}

func TestReadingStopsAtTheBound(t *testing.T) {
	s := &scripted{pages: [][]byte{page(tlv(ykTagMoreData, 1))}}
	if _, err := readYubiKeyInfo(context.Background(), s.call, Version{Major: 5, Minor: 8}, CapCBOR); !errors.Is(err, ErrYubiKeyData) {
		t.Fatal(err)
	}
	if len(s.asked) != maxYubiKeyPages {
		t.Fatalf("asked %d pages", len(s.asked))
	}
}

func TestOldFirmwareIsNotAsked(t *testing.T) {
	// Before the YubiKey 4 the version is not the firmware's: a major under 4
	// is guessed to be a NEO (3.0.0), and under 4.1.0 nothing is sent.
	for _, v := range []Version{{Major: 3, Minor: 4}, {Major: 2}, {Major: 4, Minor: 0, Build: 9}} {
		s := &scripted{pages: [][]byte{bioPage()}}
		if _, err := readYubiKeyInfo(context.Background(), s.call, v, 0); err == nil || len(s.asked) != 0 {
			t.Errorf("%v: %v, asked %d", v, err, len(s.asked))
		}
	}
	// 0.x with CTAP2 keeps its number (l.578-581) and so is under 4.1.0 too.
	s := &scripted{pages: [][]byte{bioPage()}}
	if _, err := readYubiKeyInfo(context.Background(), s.call, Version{Major: 0, Minor: 5}, CapCBOR); err == nil || len(s.asked) != 0 {
		t.Fatal(err)
	}
}

func TestADevelopmentBuildIsAskedForItsVersion(t *testing.T) {
	q := slices.Concat(tlv(1, 5, 7, 0), tlv(2, 0), tlv(3, 1))
	s := &scripted{pages: [][]byte{page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagVersionQual, q...))}}
	in, err := readYubiKeyInfo(context.Background(), s.call, Version{Major: 0, Minor: 0, Build: 1}, CapCBOR)
	if err != nil || in.Version != (YubiKeyVersion{5, 7, 0}) || len(s.asked) != 1 {
		t.Fatalf("%+v %v", in, err)
	}
	// A development build that turns out to be old is refused.
	q = slices.Concat(tlv(1, 3, 0, 0), tlv(2, 0), tlv(3, 1))
	s = &scripted{pages: [][]byte{page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagVersionQual, q...))}}
	if _, err = readYubiKeyInfo(context.Background(), s.call, Version{Major: 0, Minor: 0, Build: 1}, CapCBOR); err == nil {
		t.Fatal("accepted")
	}
}

func TestATransportErrorIsReturned(t *testing.T) {
	boom := errors.New("boom")
	s := &scripted{err: boom}
	if _, err := readYubiKeyInfo(context.Background(), s.call, Version{Major: 5, Minor: 8}, CapCBOR); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	// Also when the version has to be asked of the key first.
	s = &scripted{err: boom}
	if _, err := readYubiKeyInfo(context.Background(), s.call, Version{Build: 1}, CapCBOR); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	// And a page that is not well formed is the key's fault, not a success.
	s = &scripted{pages: [][]byte{{9, 1}}}
	if _, err := readYubiKeyInfo(context.Background(), s.call, Version{Major: 5, Minor: 8}, CapCBOR); !errors.Is(err, ErrYubiKeyData) {
		t.Fatal(err)
	}
	s = &scripted{pages: [][]byte{{3, ykTagSerial, 4, 1}}}
	if _, err := readYubiKeyInfo(context.Background(), s.call, Version{Major: 5, Minor: 8}, CapCBOR); err == nil || !strings.Contains(err.Error(), "runs past") {
		t.Fatal(err)
	}
}

// Over a real Key and framing: the command byte on the wire is 0xC2.
func TestKeyYubiKeyInfoOverTheWire(t *testing.T) {
	nonce := withNonce(t)
	tr := answering(nonce, 0x01020304, byte(CapCBOR))
	base := tr.reply
	own := NewReassembler(0x01020304)
	tr.reply = func(sent []byte) [][]byte {
		if binary.BigEndian.Uint32(sent[0:4]) == 0x01020304 {
			if msg, done, _ := own.Feed(sent); done && msg.Cmd == CmdYubiKeyReadConfig {
				p, _ := Split(0x01020304, CmdYubiKeyReadConfig, bioPage())
				return p
			}
		}
		return base(sent)
	}
	k, err := Open(context.Background(), tr)
	if err != nil {
		t.Fatal(err)
	}
	in, err := k.YubiKeyInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if in.Serial != 1234567 {
		t.Fatalf("%+v", in)
	}
	last := tr.sent[len(tr.sent)-1]
	if last[4] != 0x80|CmdYubiKeyReadConfig || last[7] != 0 {
		t.Fatalf("sent %x", last[:8])
	}
}

func FuzzYubiKeyInfo(f *testing.F) {
	f.Add(bioPage(), uint8(5), uint8(8), uint8(0))
	f.Add(page(tlv(ykTagUSBSupported, 0x02, 0x03), tlv(ykTagMoreData, 1)), uint8(4), uint8(3), uint8(0))
	f.Add([]byte{4, 0x30, 0x80, 0x00, 0x00}, uint8(0), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, p []byte, a, b, c uint8) {
		in, err := ParseYubiKeyInfo(p, YubiKeyVersion{a, b, c})
		if err != nil {
			if !errors.Is(err, ErrYubiKeyData) {
				t.Fatalf("an error that is not ErrYubiKeyData: %v", err)
			}
			return
		}
		// What is accepted has the shape the format promises.
		if len(p) == 0 || len(p)-1 != int(p[0]) {
			t.Fatalf("accepted a page whose length byte is wrong: %x", p)
		}
		if in.FormFactor > FormFactorUSBCBio || in.VersionQualifier.Type > ReleaseFinal {
			t.Fatalf("%+v", in)
		}
		if in.HasNFC == (in.NFCSupported == 0 && in.NFCEnabled == 0 && !bytes.Contains(p, []byte{ykTagNFCSupported})) && in.HasNFC {
			t.Fatalf("%+v", in)
		}
		_ = in.USBEnabled.String()
		_ = in.VersionQualifier.String()
	})
}
