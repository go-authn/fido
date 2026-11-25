// Command fido sets a security key's PIN and enrols its fingerprints, over
// the CTAP 2.1 commands of github.com/go-authn/fido.
//
//	fido info
//	fido pin set     [--pin-file FILE | --pin-from REF]
//	fido pin change  [--pin-file FILE | --pin-from REF] [--new-pin-file FILE | --new-pin-from REF]
//	fido fingerprint add [--name N] [--timeout D] [--pin-file FILE | --pin-from REF]
//	fido fingerprint list|rename ID NAME|remove ID [--pin-file FILE | --pin-from REF]
//	fido identify
//	fido attest [--pin-file FILE | --pin-from REF] [--save-to FILE]
//	fido yubikey info
//	fido mds lookup AAGUID | fido mds search WORD
//
// A PIN is read from the terminal with echo off (a new one is typed twice),
// from a regular file readable by its owner alone (--pin-file), or from a
// secret manager (--pin-from keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT,
// keepassxc:URL or file:PATH; see github.com/go-authn/secretsource), and never from an
// argument or an environment variable. The library takes a PIN as a Go
// string, which cannot be wiped; the byte buffers this command reads it into
// are.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	xterm "golang.org/x/term"

	authn "github.com/go-authn/fido"
	"github.com/go-authn/secretsource"
)

// keyAPI is the part of *authn.Key the commands use; tests replace it.
type keyAPI interface {
	GetInfo(context.Context) (authn.Info, error)
	PINRetries(context.Context) (authn.Retries, error)
	UVRetries(context.Context) (int, error)
	// The PIN forms take a slice, which the command wipes: a string cannot be.
	SetPINBytes(ctx context.Context, proto authn.PINProtocol, newPIN []byte, minLen uint) error
	ChangePINBytes(ctx context.Context, proto authn.PINProtocol, cur, newPIN []byte, minLen uint) error
	PINTokenBytes(ctx context.Context, pin []byte, proto authn.PINProtocol, perms authn.Permissions, rpID string) (authn.Token, error)
	Bio(info authn.Info) (bioAPI, error)
	Identity(context.Context) (authn.Identity, error)
	ReadName(context.Context) (string, error)
	SetName(ctx context.Context, name string, tok authn.NameTokens) error
	RemoveName(ctx context.Context, tok authn.NameTokens) error
	NameTokens(ctx context.Context, pin string, proto authn.PINProtocol, info authn.Info) (authn.NameTokens, error)
	// YubiKeyInfo reads Yubico's device info (read-only); only for a YubiKey.
	YubiKeyInfo(context.Context) (authn.YubiKeyInfo, error)
	MakeCredential(context.Context, authn.MakeCredentialRequest) (*authn.Attestation, error)
	// Device says which listed key this is.
	Device() device
	Close() error
}

// bioAPI is the part of *authn.Bio the commands use.
type bioAPI interface {
	Permissions() authn.Permissions
	SensorInfo(context.Context) (authn.SensorInfo, error)
	Enroll(ctx context.Context, tok authn.Token, timeout time.Duration, progress func(authn.EnrollStep)) ([]byte, error)
	Enumerate(context.Context, authn.Token) ([]authn.Enrollment, error)
	Rename(ctx context.Context, tok authn.Token, id []byte, name string) error
	Remove(ctx context.Context, tok authn.Token, id []byte) error
}

// realKey adapts *authn.Key to keyAPI.
type realKey struct {
	*authn.Key
	dev device
}

// Device says which listed key this is (its id and serial).
func (r realKey) Device() device { return r.dev }

func (r realKey) Bio(info authn.Info) (bioAPI, error) {
	b, err := r.Key.Bio(info)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// goos is replaced by tests.
var goos = runtime.GOOS

// The terminal, replaceable by tests.
var (
	isTerminal   = xterm.IsTerminal
	readPassword = xterm.ReadPassword
)

// readTerminal reads one secret with echo off. Tests replace it.
var readTerminal = func(cmd *cobra.Command, prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return nil, errors.New("no terminal to ask for a PIN: use --pin-file or --pin-from")
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	b, err := readPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	return b, err
}

// maxSecretFile bounds what a PIN file may hold.
const maxSecretFile = secretsource.MaxSize

// readRef resolves a secretsource reference (file:, keychain:,
// secretservice:). The bytes are the caller's to wipe.
func openRef(ctx context.Context, ref string) ([]byte, error) {
	s, err := secretsource.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// readRef is the manager lookup; tests replace it.
var readRef = openRef

// The write side of the same references, replaceable by tests.
var (
	storePIN    = secretsource.Store
	generatePIN = secretsource.Generate
)

// maxPINLen is the longest PIN CTAP 2.1 accepts (63 bytes, 6.5.5.5).
const maxPINLen = 63

// saveOpts are the flags that put a new PIN into a secret manager.
type saveOpts struct {
	to       string
	generate int
	replace  bool
}

func (o *saveOpts) addFlags(cmd *cobra.Command, src ...string) {
	cmd.Flags().StringVar(&o.to, "save-to", "", "store the new PIN in a secret manager (keychain:, secretservice:, keepassxc:URL) BEFORE setting it on the key")
	cmd.Flags().IntVar(&o.generate, "generate", 0, "draw N random characters as the new PIN (needs --save-to; N from the key's minimum to 63)")
	cmd.Flags().BoolVar(&o.replace, "replace", false, "overwrite an existing entry at --save-to")
	for _, s := range src {
		cmd.MarkFlagsMutuallyExclusive("generate", s)
	}
}

// newPIN gets the new PIN: drawn (--generate) or read as before.
func (o *saveOpts) newPIN(cmd *cobra.Command, src pinSrc, info authn.Info) ([]byte, error) {
	if !cmd.Flags().Changed("generate") {
		return readNewPIN(cmd, src)
	}
	if o.to == "" {
		return nil, errors.New("--generate needs --save-to: a PIN nobody could read back would lock the key")
	}
	if min := int(minLen(info)); o.generate < min || o.generate > maxPINLen {
		return nil, fmt.Errorf("--generate %d: this key wants a PIN of %d to %d characters", o.generate, min, maxPINLen)
	}
	return generatePIN(o.generate)
}

// undo runs when changing the PIN failed after the new one was stored. The key
// still has the CURRENT PIN, and the entry may be where that PIN was read from,
// so with --replace the current PIN is put back; without it the entry was new
// and holds a PIN that was never set.
func (o *saveOpts) undo(cmd *cobra.Command, cur []byte, cause error) error {
	if o.to == "" {
		return cause
	}
	if !o.replace {
		return fmt.Errorf("%w (the new PIN stays stored in %s although the key did not take it)", cause, o.to)
	}
	if err := storePIN(ctxOf(cmd), o.to, cur, secretsource.StoreOptions{Replace: true}); err != nil {
		return fmt.Errorf("%w (and the current PIN could not be put back in %s: %v; the key still has the CURRENT PIN, the entry now holds the NEW one)", cause, o.to, err)
	}
	return fmt.Errorf("%w (the current PIN was put back in %s)", cause, o.to)
}

// save stores p BEFORE it is set, so a failed store changes nothing on the key.
func (o *saveOpts) save(cmd *cobra.Command, p []byte) error {
	if o.to == "" {
		return nil
	}
	if err := storePIN(ctxOf(cmd), o.to, p, secretsource.StoreOptions{Replace: o.replace}); err != nil {
		return fmt.Errorf("the PIN was not stored in %s, so the key was not touched: %w", o.to, err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "New PIN stored in %s (not printed).\n", o.to)
	return nil
}

// readSecretFile reads a PIN from a regular file that its owner alone can
// read or write, and strips one trailing newline.
func readSecretFile(path string) ([]byte, error) {
	return openRef(context.Background(), "file:"+path)
}

// pinSrc is where a PIN comes from when it is not typed: a file (--pin-file)
// or a secretsource reference (--pin-from). Both empty means the terminal.
type pinSrc struct{ file, from string }

// read returns the PIN, or (nil, false, nil) when the terminal is to be asked.
func (s pinSrc) read(cmd *cobra.Command) ([]byte, bool, error) {
	switch {
	case s.from != "":
		b, err := readRef(ctxOf(cmd), s.from)
		return b, true, err
	case s.file != "":
		b, err := readSecretFile(s.file)
		return b, true, err
	}
	return nil, false, nil
}

// addFlags registers --<name>-file and --<name>-from, which exclude each other.
func (s *pinSrc) addFlags(cmd *cobra.Command, name, what string) {
	cmd.Flags().StringVar(&s.file, name+"-file", "", "read "+what+" from this file (mode 0600 or stricter) instead of the terminal")
	cmd.Flags().StringVar(&s.from, name+"-from", "", "read "+what+" from a secret manager instead of the terminal: keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT, keepassxc:URL (the entry's URL field) or file:PATH")
	cmd.MarkFlagsMutuallyExclusive(name+"-file", name+"-from")
}

// osExit is replaced by tests.
var osExit = os.Exit

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	root := RootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(root.ErrOrStderr(), errorLine(err))
		stop()
		osExit(1)
	}
}

// errorLine is the one line an error is reported as. The library's errors
// already start with "fido: ", so the program's own prefix is not added twice.
func errorLine(err error) string {
	return "fido: " + safe(strings.TrimPrefix(err.Error(), "fido: "))
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "fido",
		Short:         "Set a security key's PIN and enrol its fingerprints",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("device", "", "act on the key with this `ID` or name (see fido list; a name must be on exactly one key); with several keys attached and no --device, touch the one to use")
	root.AddCommand(listCmd(), infoCmd(), identifyCmd(), attestCmd(), yubikeyCmd(), mdsCmd(), nameCmd(), pinCmd(), fingerprintCmd())
	return root
}

// ctxOf is the command's context, or a background one when a test did not set it.
func ctxOf(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}

// protocolOf prefers PIN protocol two where the key offers both.
func protocolOf(info authn.Info) authn.PINProtocol {
	if slices.Contains(info.PINProtocols, uint(authn.PINProtocolTwo)) {
		return authn.PINProtocolTwo
	}
	return authn.PINProtocolOne
}

// readPIN gets a PIN from the file or the terminal.
func readPIN(cmd *cobra.Command, src pinSrc, prompt string) ([]byte, error) {
	if b, ok, err := src.read(cmd); ok {
		return b, err
	}
	return readTerminal(cmd, prompt)
}

// readNewPIN gets a new PIN: from the file or manager, or typed twice.
func readNewPIN(cmd *cobra.Command, src pinSrc) ([]byte, error) {
	if b, ok, err := src.read(cmd); ok {
		return b, err
	}
	a, err := readTerminal(cmd, "New PIN: ")
	if err != nil {
		return nil, err
	}
	b, err := readTerminal(cmd, "New PIN again: ")
	if err != nil {
		clear(a)
		return nil, err
	}
	defer clear(b)
	if !bytes.Equal(a, b) {
		clear(a)
		return nil, errors.New("the two PINs differ")
	}
	return a, nil
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Describe the attached key: PIN, fingerprint sensor and enrollments",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctxOf(cmd)
			k, err := openKey(cmd, false)
			if err != nil {
				return err
			}
			defer k.Close()
			info, err := k.GetInfo(ctx)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "versions:       %s\n", safe(fmt.Sprint(info.Versions)))
			fmt.Fprintf(out, "aaguid:         %x\n", info.AAGUID)
			fmt.Fprintf(out, "options:        %s\n", optionsLine(info))
			fmt.Fprintf(out, "pin protocols:  %v\n", info.PINProtocols)
			if info.Has("clientPin") {
				fmt.Fprintf(out, "PIN:            set (minimum %d characters)\n", minLen(info))
				if r, err := k.PINRetries(ctx); err == nil {
					fmt.Fprintf(out, "PIN tries:      %d left%s\n", r.PIN, map[bool]string{true: ", unplug the key to try again", false: ""}[r.PowerCycle])
				}
			} else {
				fmt.Fprintf(out, "PIN:            not set (fido pin set); minimum %d characters\n", minLen(info))
			}
			if info.ForcePINChange {
				fmt.Fprintln(out, "the PIN must be changed before it is used (fido pin change)")
			}
			b, err := k.Bio(info)
			if err != nil {
				fmt.Fprintln(out, "fingerprints:   no enrollment on this key")
				return nil
			}
			kind := "swipe"
			si, err := b.SensorInfo(ctx)
			if err != nil {
				return err
			}
			if si.Touch {
				kind = "touch"
			}
			fmt.Fprintf(out, "fingerprints:   %s sensor, %d good samples per finger, names up to %d bytes; %s\n",
				kind, si.MaxSamples, si.MaxNameLength, map[bool]string{true: "some enrolled", false: "none enrolled (fido fingerprint add)"}[info.Has("bioEnroll") || info.Has("userVerificationMgmtPreview")])
			if n, err := k.UVRetries(ctx); err == nil {
				fmt.Fprintf(out, "fingerprint tries: %d left\n", n)
			}
			return nil
		},
	}
}

// optionsLine renders the options alone, sorted: a true option by its name, a
// false one as name=false, because in CTAP 2.1 "uv" false (capable, not set up)
// and "uv" absent (not capable) mean different things.
func optionsLine(info authn.Info) string {
	names := make([]string, 0, len(info.Options))
	for n := range info.Options {
		names = append(names, n)
	}
	slices.Sort(names)
	for i, n := range names {
		if !info.Options[n] {
			names[i] = n + "=false"
		}
	}
	if len(names) == 0 {
		return "none declared"
	}
	return safe(strings.Join(names, ", "))
}

func minLen(info authn.Info) uint {
	if info.MinPINLength == 0 {
		return authn.DefaultMinPINLength
	}
	return info.MinPINLength
}

func pinCmd() *cobra.Command {
	pin := &cobra.Command{Use: "pin", Short: "Set or change the key's PIN"}
	var setFile pinSrc
	var setSave, changeSave saveOpts
	set := &cobra.Command{
		Use:   "set",
		Short: "Set the PIN of a key that has none",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctxOf(cmd)
			k, err := openKey(cmd, true)
			if err != nil {
				return err
			}
			defer k.Close()
			info, err := k.GetInfo(ctx)
			if err != nil {
				return err
			}
			if info.Has("clientPin") {
				return errors.New("this key already has a PIN: use `fido pin change`")
			}
			p, err := setSave.newPIN(cmd, setFile, info)
			if err != nil {
				return err
			}
			defer clear(p)
			if err := setSave.save(cmd, p); err != nil {
				return err
			}
			if err := k.SetPINBytes(ctx, protocolOf(info), p, info.MinPINLength); err != nil {
				if setSave.to != "" {
					err = fmt.Errorf("%w (the PIN stays stored in %s, for a key that has none; use --replace to overwrite it next time)", err, setSave.to)
				}
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "PIN set.")
			return nil
		},
	}
	setFile.addFlags(set, "pin", "the new PIN")
	setSave.addFlags(set, "pin-file", "pin-from")

	var curFile, newFile pinSrc
	change := &cobra.Command{
		Use:   "change",
		Short: "Change the PIN",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctxOf(cmd)
			k, err := openKey(cmd, true)
			if err != nil {
				return err
			}
			defer k.Close()
			info, err := k.GetInfo(ctx)
			if err != nil {
				return err
			}
			if !info.Has("clientPin") {
				return errors.New("this key has no PIN yet: use `fido pin set`")
			}
			if err := checkRetries(ctx, cmd, k); err != nil {
				return err
			}
			cur, err := readPIN(cmd, curFile, "Current PIN: ")
			if err != nil {
				return err
			}
			defer clear(cur)
			p, err := changeSave.newPIN(cmd, newFile, info)
			if err != nil {
				return err
			}
			defer clear(p)
			if err := changeSave.save(cmd, p); err != nil {
				return err
			}
			if err := k.ChangePINBytes(ctx, protocolOf(info), cur, p, info.MinPINLength); err != nil {
				return changeSave.undo(cmd, cur, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "PIN changed.")
			return nil
		},
	}
	curFile.addFlags(change, "pin", "the current PIN")
	newFile.addFlags(change, "new-pin", "the new PIN")
	changeSave.addFlags(change, "new-pin-file", "new-pin-from")
	pin.AddCommand(set, change)
	return pin
}

// checkRetries refuses before a prompt that could not be answered, and warns
// when a wrong PIN would be one of the last.
func checkRetries(ctx context.Context, cmd *cobra.Command, k keyAPI) error {
	r, err := k.PINRetries(ctx)
	if err != nil {
		return err
	}
	if r.PowerCycle {
		return errors.New("the key will take no more PINs until it is unplugged and plugged in again")
	}
	if r.PIN == 0 {
		return errors.New("the PIN is blocked: no tries are left, and only a reset, which erases the credentials, unblocks it")
	}
	if r.PIN <= 3 {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %d PIN tries left; a wrong PIN costs one.\n", r.PIN)
	}
	return nil
}

// session opens the key and returns what a fingerprint command needs: the
// enrollment interface and a token from the PIN.
func session(cmd *cobra.Command, pinFile pinSrc, write bool) (keyAPI, bioAPI, authn.Token, error) {
	ctx := ctxOf(cmd)
	k, err := openKey(cmd, write)
	if err != nil {
		return nil, nil, authn.Token{}, err
	}
	fail := func(err error) (keyAPI, bioAPI, authn.Token, error) {
		k.Close()
		return nil, nil, authn.Token{}, err
	}
	info, err := k.GetInfo(ctx)
	if err != nil {
		return fail(err)
	}
	b, err := k.Bio(info)
	if err != nil {
		return fail(err)
	}
	if !info.Has("clientPin") {
		return fail(errors.New("this key has no PIN yet: use `fido pin set` first (fingerprint management asks for it)"))
	}
	if info.ForcePINChange {
		return fail(errors.New("the PIN must be changed before it is used: `fido pin change`"))
	}
	if err := checkRetries(ctx, cmd, k); err != nil {
		return fail(err)
	}
	p, err := readPIN(cmd, pinFile, "PIN: ")
	if err != nil {
		return fail(err)
	}
	defer clear(p)
	tok, err := k.PINTokenBytes(ctx, p, protocolOf(info), b.Permissions(), "")
	if err != nil {
		return fail(err)
	}
	return k, b, tok, nil
}

func fingerprintCmd() *cobra.Command {
	fp := &cobra.Command{Use: "fingerprint", Aliases: []string{"fp"}, Short: "Enrol and manage fingerprints"}
	var pinFile pinSrc
	add := &cobra.Command{
		Use:   "add",
		Short: "Enrol a new fingerprint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, b, tok, err := session(cmd, pinFile, true)
			if err != nil {
				return err
			}
			defer k.Close()
			name, _ := cmd.Flags().GetString("name")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			ctx := ctxOf(cmd)
			si, err := b.SensorInfo(ctx)
			if err != nil {
				return err
			}
			if len(name) > si.MaxNameLength && si.MaxNameLength > 0 {
				return fmt.Errorf("the name is %d bytes; this key keeps at most %d", len(name), si.MaxNameLength)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Touch the sensor with the finger to enrol; about %d good touches are needed. Lift the finger between touches.\n", si.MaxSamples)
			id, err := b.Enroll(ctx, tok, timeout, func(s authn.EnrollStep) {
				progressLine(out, s)
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Enrolled fingerprint %s.\n", hex.EncodeToString(id))
			if name != "" {
				if err := b.Rename(ctx, tok, id, name); err != nil {
					return fmt.Errorf("enrolled %s but could not name it: %w", hex.EncodeToString(id), err)
				}
				fmt.Fprintf(out, "Named it %q.\n", name)
			}
			return nil
		},
	}
	add.Flags().String("name", "", "a friendly name for the fingerprint")
	add.Flags().Duration("timeout", 0, "how long the key waits for each touch (0: the key decides)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List the enrolled fingerprints",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, b, tok, err := session(cmd, pinFile, false)
			if err != nil {
				return err
			}
			defer k.Close()
			es, err := b.Enumerate(ctxOf(cmd), tok)
			if err != nil {
				return err
			}
			if len(es) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No fingerprint is enrolled.")
			}
			for _, e := range es {
				name := e.Name
				if name == "" {
					name = "(no name)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", hex.EncodeToString(e.ID), safe(name))
			}
			return nil
		},
	}
	rename := &cobra.Command{
		Use:   "rename ID NAME",
		Short: "Name an enrolled fingerprint (ID as `list` prints it)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := hex.DecodeString(args[0])
			if err != nil || len(id) == 0 {
				return fmt.Errorf("%q is not a fingerprint id: use the hex id `list` prints", args[0])
			}
			k, b, tok, err := session(cmd, pinFile, true)
			if err != nil {
				return err
			}
			defer k.Close()
			return b.Rename(ctxOf(cmd), tok, id, args[1])
		},
	}
	remove := &cobra.Command{
		Use:   "remove ID",
		Short: "Remove an enrolled fingerprint (ID as `list` prints it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := hex.DecodeString(args[0])
			if err != nil || len(id) == 0 {
				return fmt.Errorf("%q is not a fingerprint id: use the hex id `list` prints", args[0])
			}
			k, b, tok, err := session(cmd, pinFile, true)
			if err != nil {
				return err
			}
			defer k.Close()
			return b.Remove(ctxOf(cmd), tok, id)
		},
	}
	for _, c := range []*cobra.Command{add, list, rename, remove} {
		pinFile.addFlags(c, "pin", "the PIN")
	}
	fp.AddCommand(add, list, rename, remove)
	return fp
}

// progressLine says how one sample went and what the key wants next.
func progressLine(out io.Writer, s authn.EnrollStep) {
	if s.Remaining == 0 {
		fmt.Fprintf(out, "  %s. Done.\n", s.Status)
		return
	}
	if s.Status == authn.SampleGood {
		fmt.Fprintf(out, "  %s. Touch the sensor again: %d samples left.\n", s.Status, s.Remaining)
		return
	}
	fmt.Fprintf(out, "  Not counted: %s. Try again: %d samples left.\n", s.Status, s.Remaining)
}
