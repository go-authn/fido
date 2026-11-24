package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	authn "github.com/go-authn/fido"
	"github.com/go-authn/fido/mds"
)

const bioAAGUID = "9dd8d593-2213-438a-97f8-d6b813d51c27"

// bioInfo is what the real YubiKey Bio (5.8.0) reports.
func bioInfo() authn.YubiKeyInfo {
	return authn.YubiKeyInfo{
		Serial: 12345678, Version: authn.YubiKeyVersion{Major: 5, Minor: 8},
		VersionQualifier: authn.YubiKeyVersionQualifier{Version: authn.YubiKeyVersion{Major: 5, Minor: 8}, Type: authn.ReleaseFinal},
		FormFactor:       authn.FormFactorUSBABio, PartNumber: "YK-Bio",
		USBSupported: authn.YubiKeyU2F | authn.YubiKeyFIDO2, USBEnabled: authn.YubiKeyU2F | authn.YubiKeyFIDO2, HasUSBEnabled: true,
		FPSVersion: &authn.YubiKeyVersion{Major: 1, Minor: 2, Patch: 3},
	}
}

func yubikeyFake(yi authn.YubiKeyInfo) *fake {
	f := newFake()
	f.dev = device{Vendor: 0x1050}
	f.ykInfo = yi
	return f
}

func TestYubiKeyInfoOfABio(t *testing.T) {
	f := yubikeyFake(bioInfo())
	use(t, f, nil)
	out, _, err := run("yubikey", "info")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"firmware:       5.8.0\n", "serial:         12345678\n", "form factor:    Bio (USB-A)\n", "part number:    YK-Bio\n",
		"USB supported:  FIDO U2F, FIDO2\n", "USB enabled:    FIDO U2F, FIDO2\n", "configuration:  not locked\n",
		"FPS version:    1.2.3\n",
		"PIV:            PIV is not present on this key\n",
		"CCID:           smart-card interface (CCID) is not present on this key\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, not := range []string{"series:", "NFC", "PIN complexity", "STM version"} {
		if strings.Contains(out, not) {
			t.Errorf("unexpected %q in\n%s", not, out)
		}
	}
	if f.writes != 0 || !f.closed {
		t.Errorf("writes %d closed %v: the command must be read-only and close the key", f.writes, f.closed)
	}
}

func TestYubiKeyInfoStatesPIVAndCCIDPlainly(t *testing.T) {
	all := authn.YubiKeyU2F | authn.YubiKeyFIDO2 | authn.YubiKeyPIV | authn.YubiKeyOATH
	for _, c := range []struct {
		name         string
		supported    authn.YubiKeyCapability
		enabled      authn.YubiKeyCapability
		hasEnabled   bool
		wantPIV      string
		wantCCID     string
		wantEnabled  string
		wantSupports string
	}{
		{"enabled", all, all, true, "PIV is enabled over USB", "smart-card interface (CCID) is enabled over USB", "USB enabled:    ", ""},
		{"disabled", all, authn.YubiKeyFIDO2, true, "PIV is supported but disabled over USB", "smart-card interface (CCID) is supported but disabled over USB", "USB enabled:    FIDO2", ""},
		{"not reported", all, 0, false, "PIV is enabled over USB", "smart-card interface (CCID) is enabled over USB", "USB enabled:    not reported by this firmware", ""},
		{"ccid bit alone", 0x4, 0x4, true, "PIV is not present on this key", "smart-card interface (CCID) is enabled over USB", "", ""},
	} {
		yi := bioInfo()
		yi.USBSupported, yi.USBEnabled, yi.HasUSBEnabled = c.supported, c.enabled, c.hasEnabled
		use(t, yubikeyFake(yi), nil)
		out, _, err := run("yubikey", "info")
		if err != nil {
			t.Fatal(c.name, err)
		}
		if !strings.Contains(out, "PIV:            "+c.wantPIV+"\n") || !strings.Contains(out, "CCID:           "+c.wantCCID+"\n") || !strings.Contains(out, c.wantEnabled) {
			t.Errorf("%s:\n%s", c.name, out)
		}
	}
}

func TestYubiKeyInfoShowsEveryField(t *testing.T) {
	yi := bioInfo()
	yi.Serial = 0
	yi.VersionQualifier.Type = authn.ReleaseBeta
	yi.VersionQualifier.Iteration = 3
	yi.FIPS, yi.SKY, yi.Locked, yi.PINComplexity = true, true, true, true
	yi.PartNumber = "bad\x1b[2Jpart"
	yi.HasNFC = true
	yi.NFCSupported, yi.NFCEnabled = authn.YubiKeyFIDO2, authn.YubiKeyU2F
	yi.STMVersion = &authn.YubiKeyVersion{Major: 9}
	use(t, yubikeyFake(yi), nil)
	out, _, err := run("yubikey", "info")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"firmware:       5.8.0 (5.8.0.beta.3)\n", "serial:         not reported\n", "series:         FIPS\n", "series:         Security Key\n",
		"NFC supported:  FIDO2\n", "NFC enabled:    FIDO U2F\n", "configuration:  locked by a lock code\n",
		"PIN complexity: required\n", "STM version:    9.0.0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("a control sequence from the key reached the terminal:\n%q", out)
	}
}

func TestYubiKeyInfoRefusesAKeyThatIsNotYubicos(t *testing.T) {
	f := yubikeyFake(bioInfo())
	f.dev = device{Vendor: 0x1209}
	f.ykErr = boom // would be returned if the key were asked
	use(t, f, nil)
	_, _, err := run("yubikey", "info")
	if err == nil || !strings.Contains(err.Error(), "not a YubiKey (USB vendor id 0x1209, not 0x1050)") {
		t.Fatalf("%v", err)
	}
	if !f.closed {
		t.Error("the key was left open")
	}
}

func TestYubiKeyInfoErrors(t *testing.T) {
	use(t, newFake(), boom)
	if _, _, err := run("yubikey", "info"); err != boom {
		t.Errorf("open: %v", err)
	}
	f := yubikeyFake(bioInfo())
	f.ykErr = boom
	use(t, f, nil)
	if _, _, err := run("yubikey", "info"); err != boom {
		t.Errorf("read: %v", err)
	}
	if _, _, err := run("yubikey", "info", "extra"); err == nil {
		t.Error("arguments accepted")
	}
}

// entryWith is a blob entry whose attestation root is the pinned GlobalSign
// root, which is a real certificate and needs no other fixture.
func entryWith(aaguid, description string) mds.Entry {
	return mds.Entry{
		AAGUID: aaguid,
		MetadataStatement: &mds.Statement{
			Description: description, ProtocolFamily: "fido2",
			KeyProtection: []string{"hardware", "secure_element"}, AttestationTypes: []string{"basic_full"},
			AttestationRootCertificates: []string{base64.StdEncoding.EncodeToString(mds.Root().Raw)},
		},
		StatusReports: []mds.StatusReport{{Status: "FIDO_CERTIFIED_L1", EffectiveDate: "2025-01-02"}},
	}
}

func useBlob(t *testing.T, b *mds.Blob, err error) *bool {
	t.Helper()
	old := loadMDS
	t.Cleanup(func() { loadMDS = old })
	refreshed := new(bool)
	loadMDS = func(_ context.Context, refresh bool) (*mds.Blob, error) {
		*refreshed = refresh
		return b, err
	}
	return refreshed
}

func theBlob() *mds.Blob {
	return &mds.Blob{No: 77, NextUpdateDate: "2026-12-01", Entries: []mds.Entry{
		entryWith(bioAAGUID, "YubiKey Bio Fido Edition (Consumer Profile)"),
		entryWith("00000000-0000-0000-0000-000000000001", "Other key"),
		{AAGUID: "not an aaguid"},
	}}
}

func TestMDSLookup(t *testing.T) {
	refreshed := useBlob(t, theBlob(), nil)
	for _, arg := range []string{bioAAGUID, strings.ToUpper(strings.ReplaceAll(bioAAGUID, "-", ""))} {
		out, _, err := run("mds", "lookup", arg)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"aaguid:         " + bioAAGUID + "\n", "description:    YubiKey Bio Fido Edition (Consumer Profile)\n",
			"protocol:       fido2\n", "key protection: hardware, secure_element\n", "attestation:    basic_full\n",
			"status:         FIDO_CERTIFIED_L1 (from 2025-01-02)\n", "attestation root certificates: 1\n",
			"GlobalSign Root R46", "sha-256 " + mds.RootSHA256 + "\n", "blob:           no 77, verified against GlobalSign Root R46, next update 2026-12-01\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q in\n%s", arg, want, out)
			}
		}
	}
	if *refreshed {
		t.Error("refresh without --refresh")
	}
	if _, _, err := run("mds", "lookup", "--refresh", bioAAGUID); err != nil || !*refreshed {
		t.Errorf("--refresh not passed: %v %v", err, *refreshed)
	}
}

func TestMDSLookupRefusals(t *testing.T) {
	useBlob(t, theBlob(), nil)
	if _, _, err := run("mds", "lookup", "xyz\x1b[2J"); err == nil || !strings.Contains(err.Error(), "is not an AAGUID") || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("bad aaguid: %q", err)
	}
	if _, _, err := run("mds", "lookup", "11111111-1111-1111-1111-111111111111"); err == nil || !strings.Contains(err.Error(), "is not listed in the FIDO MDS (blob no 77)") {
		t.Errorf("unlisted: %v", err)
	}
	if _, _, err := run("mds", "lookup"); err == nil {
		t.Error("no argument accepted")
	}
	useBlob(t, nil, boom)
	if _, _, err := run("mds", "lookup", bioAAGUID); err != boom {
		t.Errorf("load: %v", err)
	}
	b := theBlob()
	b.Entries[0].MetadataStatement.AttestationRootCertificates = []string{"!!"}
	useBlob(t, b, nil)
	if _, _, err := run("mds", "lookup", bioAAGUID); err == nil || !strings.Contains(err.Error(), "attestationRootCertificates") {
		t.Errorf("bad certificate: %v", err)
	}
}

func TestMDSLookupOfAnEntryWithoutAStatement(t *testing.T) {
	useBlob(t, &mds.Blob{No: 1, Entries: []mds.Entry{{AAGUID: bioAAGUID}}}, nil)
	out, _, err := run("mds", "lookup", bioAAGUID)
	if err != nil || strings.Contains(out, "protocol:") || !strings.Contains(out, "attestation root certificates: 0\n") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestMDSSearch(t *testing.T) {
	refreshed := useBlob(t, theBlob(), nil)
	out, _, err := run("mds", "search", "BIO")
	if err != nil || out != bioAAGUID+"  YubiKey Bio Fido Edition (Consumer Profile)\n" {
		t.Errorf("%v %q", err, out)
	}
	if _, _, err := run("mds", "search", "--refresh", "bio"); err != nil || !*refreshed {
		t.Errorf("--refresh not passed: %v", err)
	}
	if _, _, err := run("mds", "search", "nomatchatall"); err == nil || !strings.Contains(err.Error(), `matches "nomatchatall"`) {
		t.Errorf("no match: %v", err)
	}
	b := &mds.Blob{No: 2}
	for i := range maxSearchLines + 7 {
		b.Entries = append(b.Entries, entryWith(fmt.Sprintf("00000000-0000-0000-0000-%012d", i), "Many"))
	}
	useBlob(t, b, nil)
	out, _, err = run("mds", "search", "many")
	if err != nil || strings.Count(out, "\n") != maxSearchLines+1 || !strings.HasSuffix(out, "... and 7 more\n") {
		t.Errorf("%v\n%s", err, out)
	}
	b.Entries = b.Entries[:maxSearchLines]
	out, _, err = run("mds", "search", "many")
	if err != nil || strings.Contains(out, "more") || strings.Count(out, "\n") != maxSearchLines {
		t.Errorf("exactly the bound must print everything: %v\n%s", err, out)
	}
	useBlob(t, nil, boom)
	if _, _, err := run("mds", "search", "x"); err != boom {
		t.Errorf("load: %v", err)
	}
}

func TestIdentifyNamesTheModelAndSaysTheAAGUIDIsSelfDeclared(t *testing.T) {
	f := newFake()
	f.info.AAGUID = [16]byte{0x9d, 0xd8, 0xd5, 0x93, 0x22, 0x13, 0x43, 0x8a, 0x97, 0xf8, 0xd6, 0xb8, 0x13, 0xd5, 0x1c, 0x27}
	use(t, f, nil)
	refreshed := useBlob(t, theBlob(), nil)
	out, _, err := run("identify", "--refresh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"reported aaguid: " + bioAAGUID + " (self-declared)\n", "description:    YubiKey Bio Fido Edition (Consumer Profile)\n",
		"attestation root certificates: 1\n", selfDeclared + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, selfDeclared+"\n") {
		t.Error("the self-declared note must come after the attestation roots it refers to")
	}
	if !*refreshed || !f.closed || f.writes != 0 {
		t.Errorf("refreshed %v closed %v writes %d", *refreshed, f.closed, f.writes)
	}
}

func TestIdentifyOfAModelTheMDSDoesNotList(t *testing.T) {
	use(t, newFake(), nil)
	useBlob(t, theBlob(), nil)
	out, _, err := run("identify")
	if err != nil || !strings.Contains(out, "reported aaguid: 00000000-0000-0000-0000-000000000000 (self-declared)\n") ||
		!strings.Contains(out, "not listed in the FIDO MDS (blob no 77)\n") || !strings.HasSuffix(out, selfDeclared+"\n") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestIdentifyErrors(t *testing.T) {
	use(t, newFake(), boom)
	if _, _, err := run("identify"); err != boom {
		t.Errorf("open: %v", err)
	}
	f := newFake()
	f.infoErr = boom
	use(t, f, nil)
	if _, _, err := run("identify"); err != boom {
		t.Errorf("getInfo: %v", err)
	}
	use(t, newFake(), nil)
	useBlob(t, nil, boom)
	if _, _, err := run("identify"); err != boom {
		t.Errorf("load: %v", err)
	}
	f = newFake()
	f.info.AAGUID = [16]byte{15: 1}
	use(t, f, nil)
	b := theBlob()
	b.Entries[1].MetadataStatement.AttestationRootCertificates = []string{"!!"}
	useBlob(t, b, nil)
	if _, _, err := run("identify"); err == nil || !strings.Contains(err.Error(), "attestationRootCertificates") {
		t.Errorf("bad certificate: %v", err)
	}
}

// The client is built with no verification option and no URL of its own, in
// the user cache directory.
func TestTheMDSClientIsTheVerifyingOne(t *testing.T) {
	dir := t.TempDir()
	for _, k := range []string{"HOME", "XDG_CACHE_HOME", "LocalAppData"} {
		t.Setenv(k, dir)
	}
	c, err := newMDSClient()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Dir, dir) || !strings.HasSuffix(c.Dir, "mds") {
		t.Errorf("cache dir %q", c.Dir)
	}
	if c.URL != "" || c.Fetch != nil || c.Options.Roots != nil || c.Options.Hostname != "" || c.Options.Now != nil || c.Options.CRL != nil {
		t.Errorf("the client carries a setting: %+v", c)
	}
	// loadMDS reaches the library: a cancelled context is its first refusal.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loadMDS(ctx, false); err != context.Canceled {
		t.Errorf("loadMDS: %v", err)
	}
	for _, k := range []string{"HOME", "XDG_CACHE_HOME", "LocalAppData"} {
		t.Setenv(k, "")
	}
	if _, err := newMDSClient(); err == nil {
		t.Error("no cache directory, no error")
	}
	if _, err := loadMDS(context.Background(), false); err == nil {
		t.Error("loadMDS without a cache directory")
	}
}

// Verification cannot be turned off from the command line: the only flags of
// the mds commands are --refresh and the global --device.
func TestNoFlagTurnsVerificationOff(t *testing.T) {
	allowed := map[string]bool{"refresh": true, "device": true, "help": true}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if !allowed[f.Name] {
				t.Errorf("%s has --%s", c.CommandPath(), f.Name)
			}
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	root := RootCmd()
	for _, name := range []string{"mds", "identify"} {
		c, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		walk(c)
	}
}
