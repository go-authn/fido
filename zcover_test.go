// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import "testing"

func TestYubiKeyNamesAndVersionOrder(t *testing.T) {
	for f, want := range map[YubiKeyFormFactor]string{
		FormFactorUnknown: "Unknown", FormFactorUSBAKeychain: "Keychain (USB-A)", FormFactorUSBANano: "Nano (USB-A)",
		FormFactorUSBCKeychain: "Keychain (USB-C)", FormFactorUSBCNano: "Nano (USB-C)",
		FormFactorUSBCLightn: "Keychain (USB-C, Lightning)", FormFactorUSBABio: "Bio (USB-A)", FormFactorUSBCBio: "Bio (USB-C)",
		YubiKeyFormFactor(99): "Unknown",
	} {
		if got := f.String(); got != want {
			t.Errorf("form factor %d = %q, want %q", f, got, want)
		}
	}
	for r, want := range map[YubiKeyReleaseType]string{
		ReleaseAlpha: "alpha", ReleaseBeta: "beta", ReleaseFinal: "final", 7: "unknown(7)",
	} {
		if got := r.String(); got != want {
			t.Errorf("release %d = %q, want %q", r, got, want)
		}
	}
	for _, c := range []struct {
		v, w YubiKeyVersion
		less bool
	}{
		{YubiKeyVersion{4, 0, 0}, YubiKeyVersion{5, 0, 0}, true},
		{YubiKeyVersion{5, 0, 0}, YubiKeyVersion{4, 9, 9}, false},
		{YubiKeyVersion{5, 1, 0}, YubiKeyVersion{5, 2, 0}, true},
		{YubiKeyVersion{5, 2, 0}, YubiKeyVersion{5, 1, 9}, false},
		{YubiKeyVersion{5, 1, 1}, YubiKeyVersion{5, 1, 2}, true},
		{YubiKeyVersion{5, 1, 2}, YubiKeyVersion{5, 1, 1}, false},
		{YubiKeyVersion{5, 1, 1}, YubiKeyVersion{5, 1, 1}, false},
	} {
		if got := c.v.less(c.w); got != c.less {
			t.Errorf("%v < %v = %v", c.v, c.w, got)
		}
	}
}
