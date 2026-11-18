// Command fido sets a security key's PIN and enrols its fingerprints, over
// the CTAP 2.1 commands of github.com/go-authn/fido.
//
//	fido info
//	fido pin set     [--pin-file FILE]
//	fido pin change  [--pin-file FILE] [--new-pin-file FILE]
//	fido fingerprint add [--name N] [--timeout D] [--pin-file FILE]
//	fido fingerprint list|rename ID NAME|remove ID [--pin-file FILE]
//
// A PIN is read from the terminal with echo off (a new one is typed twice) or
// from a regular file readable by its owner alone (--pin-file), and never from
// an argument or an environment variable. The library takes a PIN as a Go
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
)

// keyAPI is the part of *authn.Key the commands use; tests replace it.
type keyAPI interface {
	GetInfo(context.Context) (authn.Info, error)
	PINRetries(context.Context) (authn.Retries, error)
	UVRetries(context.Context) (int, error)
	SetPIN(ctx context.Context, proto authn.PINProtocol, newPIN string, minLen uint) error
	ChangePIN(ctx context.Context, proto authn.PINProtocol, cur, newPIN string, minLen uint) error
	PINToken(ctx context.Context, pin string, proto authn.PINProtocol, perms authn.Permissions, rpID string) (authn.Token, error)
	Bio(info authn.Info) (bioAPI, error)
	Identity(context.Context) (authn.Identity, error)
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
type realKey struct{ *authn.Key }

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
		return nil, errors.New("no terminal to ask for a PIN: use --pin-file")
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	b, err := readPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	return b, err
}

// maxSecretFile bounds what a PIN file may hold.
const maxSecretFile = 4096

// readSecretFile reads a PIN from a regular file that its owner alone can
// read or write, and strips one trailing newline.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Checked on the open descriptor, not the path, so the file cannot be
	// swapped between the check and the read.
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%s: not a regular file", path)
	}
	if err == nil && st.Mode().Perm()&0o077 != 0 {
		err = fmt.Errorf("%s: mode %04o, must not be readable or writable by group or others", path, st.Mode().Perm())
	}
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err == nil && len(b) > maxSecretFile {
		err = fmt.Errorf("%s: longer than %d bytes", path, maxSecretFile)
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		n--
		if n > 0 && b[n-1] == '\r' {
			n--
		}
	}
	return b[:n], nil
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
	return "fido: " + strings.TrimPrefix(err.Error(), "fido: ")
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "fido",
		Short:         "Set a security key's PIN and enrol its fingerprints",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("device", "", "act on the key with this ID (see `fido list`); with several keys attached and no --device, touch the one to use")
	root.AddCommand(listCmd(), infoCmd(), pinCmd(), fingerprintCmd())
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
func readPIN(cmd *cobra.Command, file, prompt string) ([]byte, error) {
	if file != "" {
		return readSecretFile(file)
	}
	return readTerminal(cmd, prompt)
}

// readNewPIN gets a new PIN: from the file, or typed twice.
func readNewPIN(cmd *cobra.Command, file string) ([]byte, error) {
	if file != "" {
		return readSecretFile(file)
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
			fmt.Fprintf(out, "versions:       %v\n", info.Versions)
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
	return strings.Join(names, ", ")
}

func minLen(info authn.Info) uint {
	if info.MinPINLength == 0 {
		return authn.DefaultMinPINLength
	}
	return info.MinPINLength
}

func pinCmd() *cobra.Command {
	pin := &cobra.Command{Use: "pin", Short: "Set or change the key's PIN"}
	var setFile string
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
			p, err := readNewPIN(cmd, setFile)
			if err != nil {
				return err
			}
			defer clear(p)
			if err := k.SetPIN(ctx, protocolOf(info), string(p), info.MinPINLength); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "PIN set.")
			return nil
		},
	}
	set.Flags().StringVar(&setFile, "pin-file", "", "read the new PIN from this file (mode 0600 or stricter) instead of the terminal")

	var curFile, newFile string
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
			p, err := readNewPIN(cmd, newFile)
			if err != nil {
				return err
			}
			defer clear(p)
			if err := k.ChangePIN(ctx, protocolOf(info), string(cur), string(p), info.MinPINLength); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "PIN changed.")
			return nil
		},
	}
	change.Flags().StringVar(&curFile, "pin-file", "", "read the current PIN from this file (mode 0600 or stricter) instead of the terminal")
	change.Flags().StringVar(&newFile, "new-pin-file", "", "read the new PIN from this file (mode 0600 or stricter) instead of the terminal")
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
func session(cmd *cobra.Command, pinFile string, write bool) (keyAPI, bioAPI, authn.Token, error) {
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
	tok, err := k.PINToken(ctx, string(p), protocolOf(info), b.Permissions(), "")
	if err != nil {
		return fail(err)
	}
	return k, b, tok, nil
}

func fingerprintCmd() *cobra.Command {
	fp := &cobra.Command{Use: "fingerprint", Aliases: []string{"fp"}, Short: "Enrol and manage fingerprints"}
	var pinFile string
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
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", hex.EncodeToString(e.ID), name)
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
		c.Flags().StringVar(&pinFile, "pin-file", "", "read the PIN from this file (mode 0600 or stricter) instead of the terminal")
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
