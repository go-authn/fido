package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	authn "github.com/go-authn/fido"
)

// Security audit 2026-11-21, proof F2. A fingerprint template's name is a
// string the KEY returns; `fido fingerprint list` writes it to the terminal
// as it came. A key (or anything speaking CTAPHID on the bus) that names a
// template with escape sequences drives the terminal of whoever lists it.
// Key NAMES go through CheckName for exactly this reason; these do not.
func TestSecAudit5FingerprintNameFromTheKeyReachesTheTerminalRaw(t *testing.T) {
	pf := secretFile(t, "1234", 0o600)
	f := newFake()
	f.enrollList = []authn.Enrollment{{ID: []byte{1}, Name: "thumb\x1b[2J\x1b]0;owned\x07\r\nPIN accepted"}}
	use(t, f, nil)
	out, _, err := run("fingerprint", "list", "--pin-file", pf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out, "\x1b\x07\r") {
		t.Errorf("control characters from the key reach stdout: %q", out)
	}
	if !strings.Contains(out, `\x1b`) || !strings.Contains(out, "thumb") {
		t.Errorf("the name should survive, escaped: %q", out)
	}
}

// hostile carries ESC, BEL, CR, a right-to-left override and a zero-width space.
var hostile = "x\x1b[2J\x1b]0;owned\x07\r" + string(rune(0x202e)) + string(rune(0x200b)) + "end"

func noControl(t *testing.T, what, s string) {
	t.Helper()
	if strings.ContainsAny(s, "\x1b\x07\r"+string(rune(0x202e))+string(rune(0x200b))) {
		t.Errorf("%s: a control or format character reaches the terminal: %q", what, s)
	}
}

// The other call sites of key-supplied text: name show, info, list, errors.
func TestSecAudit5EveryKeySuppliedStringIsEscapedBeforePrinting(t *testing.T) {
	t.Run("name show", func(t *testing.T) {
		f := newFake()
		f.stored = hostile
		use(t, f, nil)
		out, _, err := run("name", "show")
		if err != nil {
			t.Fatal(err)
		}
		noControl(t, "name show", out)
	})
	t.Run("info", func(t *testing.T) {
		f := newFake()
		f.info.Versions = []string{hostile}
		f.info.Options = map[string]bool{hostile: true}
		use(t, f, nil)
		out, _, err := run("info")
		if err != nil {
			t.Fatal(err)
		}
		noControl(t, "info", out)
	})
	t.Run("list", func(t *testing.T) {
		k := newAnswerKey(hostile, map[string]bool{})
		k.stored = hostile
		d := k.device(hostile)
		d.Serial = hostile
		withDevices(t, []device{d}, nil)
		out, _, err := run("list")
		if err != nil {
			t.Fatal(err)
		}
		noControl(t, "list", out)
	})
	t.Run("announce", func(t *testing.T) {
		var b strings.Builder
		announce(&b, hostile, hostile, true)
		announce(&b, hostile, hostile, false)
		noControl(t, "announce", b.String())
	})
	t.Run("error line", func(t *testing.T) {
		noControl(t, "errorLine", errorLine(errors.New(hostile)))
		noControl(t, "oneLine", oneLine(errors.New(hostile)))
	})
}

func TestSafeEscapesWhatIsNotPrintableAndKeepsTheRest(t *testing.T) {
	bs := string(rune(92)) // a backslash, so the wanted escapes read plainly
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{"caf" + string(rune(0xe9)) + " ok", "caf" + string(rune(0xe9)) + " ok"},
		{string(rune(0x6307)) + string(rune(0x7d0b)), string(rune(0x6307)) + string(rune(0x7d0b))},
		{"a\x1bb", "a" + bs + "x1bb"},
		{"a\r\nb", "a" + bs + "x0d" + bs + "x0ab"},
		{"a" + string(rune(0x202e)) + "b", "a" + bs + "u202eb"},
		{"a" + string(rune(0x200b)) + "b", "a" + bs + "u200bb"},
		{"a" + string(rune(0xad)) + "b", "a" + bs + "u00adb"},
		{"a" + string(rune(0x2028)) + "b", "a" + bs + "u2028b"},
		{"a" + string(rune(0xa0)) + "b", "a" + bs + "u00a0b"}, // a space that is not a space: spoofing
		{"a\xffb", "a" + bs + "xffb"},
		{"a" + string(rune(0xe0001)) + "b", "a" + bs + "U000e0001b"},
		{"a\x7fb", "a" + bs + "x7fb"},
		{"", ""},
	} {
		if got := safe(tc.in); got != tc.want {
			t.Errorf("safe(%s) = %s, want %s", fmt.Sprintf("%q", tc.in), fmt.Sprintf("%q", got), fmt.Sprintf("%q", tc.want))
		}
	}
}
