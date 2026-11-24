package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	authn "github.com/go-authn/fido"
)

// yubicoVendorID is Yubico's USB vendor id. The management read is Yubico's
// own CTAPHID vendor command: another vendor may give that number a meaning
// of its own, so it is never sent to a key that is not a YubiKey.
const yubicoVendorID = 0x1050

func yubikeyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "yubikey",
		Short: "Yubico-specific, read-only commands",
	}
	c.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Describe a YubiKey like `ykman info` (read-only): firmware, serial, applications, PIV/CCID",
		Long: "Reads the device info a YubiKey reports (Yubico's management read, " +
			"CTAPHID vendor command 0x42) and prints it. Nothing is written: the " +
			"key's configuration, PIN and fingerprints are not touched. A key that " +
			"is not a YubiKey (USB vendor id 0x1050) is refused before anything " +
			"is sent to it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := openKey(cmd, false)
			if err != nil {
				return err
			}
			defer k.Close()
			if v := k.Device().Vendor; v != yubicoVendorID {
				return fmt.Errorf("this key is not a YubiKey (USB vendor id %#04x, not %#04x): Yubico's device info is not asked of another vendor's key", v, yubicoVendorID)
			}
			yi, err := k.YubiKeyInfo(ctxOf(cmd))
			if err != nil {
				return err
			}
			printYubiKey(cmd.OutOrStdout(), yi)
			return nil
		},
	})
	return c
}

// printYubiKey renders the device info the way `ykman info` lays it out, then
// states plainly whether PIV and the smart-card (CCID) interface are there.
func printYubiKey(out io.Writer, yi authn.YubiKeyInfo) {
	fw := yi.Version.String()
	if yi.VersionQualifier.Type != authn.ReleaseFinal {
		fw += " (" + yi.VersionQualifier.String() + ")"
	}
	fmt.Fprintf(out, "firmware:       %s\n", fw)
	if yi.Serial == 0 {
		fmt.Fprintln(out, "serial:         not reported")
	} else {
		fmt.Fprintf(out, "serial:         %d\n", yi.Serial)
	}
	fmt.Fprintf(out, "form factor:    %s\n", yi.FormFactor)
	if yi.PartNumber != "" {
		fmt.Fprintf(out, "part number:    %s\n", safe(yi.PartNumber))
	}
	if yi.FIPS {
		fmt.Fprintln(out, "series:         FIPS")
	}
	if yi.SKY {
		fmt.Fprintln(out, "series:         Security Key")
	}
	fmt.Fprintf(out, "USB supported:  %s\n", yi.USBSupported)
	enabled := yi.USBSupported
	if yi.HasUSBEnabled {
		enabled = yi.USBEnabled
		fmt.Fprintf(out, "USB enabled:    %s\n", yi.USBEnabled)
	} else {
		fmt.Fprintln(out, "USB enabled:    not reported by this firmware")
	}
	if yi.HasNFC {
		fmt.Fprintf(out, "NFC supported:  %s\n", yi.NFCSupported)
		fmt.Fprintf(out, "NFC enabled:    %s\n", yi.NFCEnabled)
	}
	fmt.Fprintf(out, "configuration:  %s\n", map[bool]string{true: "locked by a lock code", false: "not locked"}[yi.Locked])
	if yi.PINComplexity {
		fmt.Fprintln(out, "PIN complexity: required")
	}
	if yi.FPSVersion != nil {
		fmt.Fprintf(out, "FPS version:    %s\n", yi.FPSVersion)
	}
	if yi.STMVersion != nil {
		fmt.Fprintf(out, "STM version:    %s\n", yi.STMVersion)
	}
	fmt.Fprintf(out, "PIV:            %s\n", over("PIV", yi.USBSupported.Has(authn.YubiKeyPIV), enabled.Has(authn.YubiKeyPIV)))
	fmt.Fprintf(out, "CCID:           %s\n", over("smart-card interface (CCID)", yi.USBSupported.UsesCCID(), enabled.UsesCCID()))
}

// over says whether something is on a key, over USB: absent, there but
// switched off, or on.
func over(what string, supported, enabled bool) string {
	switch {
	case enabled:
		return what + " is enabled over USB"
	case supported:
		return what + " is supported but disabled over USB"
	}
	return what + " is not present on this key"
}
