package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	authn "github.com/go-authn/fido"
)

// Names. A name is stored ON the key (a credential under name.fido, see
// authn.SetName) so it follows the key across ports and machines, and is read
// with no touch and no PIN. CTAP 2.1 does not make every key answer that read;
// for a key that does not, a LOCAL alias table maps the key's best intrinsic
// id (its serial when it has one, otherwise model and port) to a name. Which of
// the two a key uses is always said.

// nameSource says where a name came from.
type nameSource int

const (
	nameNone   nameSource = iota // the key has no name
	nameOnKey                    // stored on the key
	nameAlias                    // from the local alias table
	nameHidden                   // the key has a name it will not show without a PIN
)

func (s nameSource) String() string {
	switch s {
	case nameOnKey:
		return "stored on the key"
	case nameAlias:
		return "local alias: this key does not answer a read of its name without a PIN"
	case nameHidden:
		return "this key does not answer a read of its name without a PIN, and no local alias is set"
	}
	return "no name"
}

// userConfigDir is replaced by tests.
var userConfigDir = os.UserConfigDir

// aliasPath is where the alias table lives: <user config dir>/fido/names.
func aliasPath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "fido", "names"), nil
}

// loadAliases reads the table; a missing file is an empty table. Each line is
// KEY TAB NAME. A name cannot contain a tab or a newline (authn.CheckName).
func loadAliases() (map[string]string, error) {
	path, err := aliasPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, name, ok := strings.Cut(sc.Text(), "\t")
		if ok && k != "" && authn.CheckName(name) == nil {
			m[k] = name
		}
	}
	return m, sc.Err()
}

// saveAliases writes the table with mode 0600 in a 0700 directory, through a
// temporary file, so a crash never leaves half a table.
func saveAliases(m map[string]string) error {
	path, err := aliasPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\t" + m[k] + "\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// aliasKey is the best intrinsic id a key offers: its serial when it has one,
// otherwise the port it sits in (so an alias without a serial is bound to the
// port), each with the model's AAGUID.
func aliasKey(aaguid [16]byte, d device) string {
	model := hex.EncodeToString(aaguid[:])
	if d.Serial != "" {
		return "serial:" + d.Serial + "/" + model
	}
	return "port:" + d.ID + "/" + model
}

// keyName finds a key's name: on the key when it answers the silent read, else
// from the alias table.
func keyName(ctx context.Context, k keyAPI) (string, nameSource, error) {
	n, err := k.ReadName(ctx)
	switch {
	case err == nil:
		return n, nameOnKey, nil
	case errors.Is(err, authn.ErrNoName):
		return "", nameNone, nil
	case errors.Is(err, authn.ErrNameRefused):
		id, ierr := k.Identity(ctx)
		if ierr != nil {
			return "", nameHidden, nil
		}
		aliases, lerr := loadAliases()
		if lerr != nil {
			return "", nameHidden, nil
		}
		if a, ok := aliases[aliasKey(id.AAGUID, k.Device())]; ok {
			return a, nameAlias, nil
		}
		return "", nameHidden, nil
	}
	return "", nameNone, err
}

// quoted renders a name for a message.
func quoted(name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf(" %q", name)
}

func nameCmd() *cobra.Command {
	nm := &cobra.Command{Use: "name", Short: "Name a key, on the key"}
	var pin pinSrc

	show := &cobra.Command{
		Use:   "show",
		Short: "Show the key's name (no touch, no PIN)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := openKey(cmd, false)
			if err != nil {
				return err
			}
			defer k.Close()
			name, src, err := keyName(ctxOf(cmd), k)
			if err != nil {
				return err
			}
			if name == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "name: none (%s)\n", src)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "name: %s (%s)\n", name, src)
			return nil
		},
	}

	set := &cobra.Command{
		Use:   "set NAME",
		Short: "Give the key a name, stored on the key (asks for the PIN; replaces any name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := authn.CheckName(name); err != nil {
				return err
			}
			k, tok, err := nameSession(cmd, pin)
			if err != nil {
				return err
			}
			defer k.Close()
			ctx := ctxOf(cmd)
			if err := k.SetName(ctx, name, tok); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			// Say how this key will be read from now on.
			_, rerr := k.ReadName(ctx)
			if errors.Is(rerr, authn.ErrNameRefused) {
				id, err := k.Identity(ctx)
				if err != nil {
					return err
				}
				aliases, err := loadAliases()
				if err != nil {
					return err
				}
				aliases[aliasKey(id.AAGUID, k.Device())] = name
				if err := saveAliases(aliases); err != nil {
					return err
				}
				path, _ := aliasPath()
				fmt.Fprintf(out, "Named %q. The name is stored on the key, but this key does not answer a read of it without a PIN, so it is also kept in a local alias table (%s), bound to this key's %s.\n",
					name, path, aliasBinding(k.Device()))
				return nil
			}
			if rerr != nil {
				return fmt.Errorf("the name was stored but could not be read back: %w", rerr)
			}
			if err := dropAlias(ctx, k); err != nil {
				return err
			}
			fmt.Fprintf(out, "Named %q (stored on the key; read with no touch and no PIN).\n", name)
			return nil
		},
	}

	remove := &cobra.Command{
		Use:   "remove",
		Short: "Remove the key's name (asks for the PIN)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, tok, err := nameSession(cmd, pin)
			if err != nil {
				return err
			}
			defer k.Close()
			ctx := ctxOf(cmd)
			if err := k.RemoveName(ctx, tok); err != nil {
				return err
			}
			if err := dropAlias(ctx, k); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "The name was removed.")
			return nil
		},
	}
	for _, c := range []*cobra.Command{set, remove} {
		pin.addFlags(c, "pin", "the PIN")
	}
	nm.AddCommand(show, set, remove)
	return nm
}

func aliasBinding(d device) string {
	if d.Serial != "" {
		return "serial number"
	}
	return "USB port (it has no serial number): move the key and the alias no longer applies"
}

// dropAlias forgets the alias of this key, if any.
func dropAlias(ctx context.Context, k keyAPI) error {
	id, err := k.Identity(ctx)
	if err != nil {
		return err
	}
	aliases, err := loadAliases()
	if err != nil {
		return err
	}
	key := aliasKey(id.AAGUID, k.Device())
	if _, ok := aliases[key]; !ok {
		return nil
	}
	delete(aliases, key)
	return saveAliases(aliases)
}

// nameSession opens the key for a write and gets the tokens naming needs from
// the PIN.
func nameSession(cmd *cobra.Command, pin pinSrc) (keyAPI, authn.NameTokens, error) {
	ctx := ctxOf(cmd)
	k, err := openKey(cmd, true)
	if err != nil {
		return nil, authn.NameTokens{}, err
	}
	fail := func(err error) (keyAPI, authn.NameTokens, error) {
		k.Close()
		return nil, authn.NameTokens{}, err
	}
	info, err := k.GetInfo(ctx)
	if err != nil {
		return fail(err)
	}
	if !info.Has("clientPin") {
		return fail(errors.New("this key has no PIN yet: use `fido pin set` first (naming asks for it)"))
	}
	if info.ForcePINChange {
		return fail(errors.New("the PIN must be changed before it is used: `fido pin change`"))
	}
	if err := checkRetries(ctx, cmd, k); err != nil {
		return fail(err)
	}
	p, err := readPIN(cmd, pin, "PIN: ")
	if err != nil {
		return fail(err)
	}
	defer clear(p)
	tok, err := k.NameTokens(ctx, string(p), protocolOf(info), info)
	if err != nil {
		return fail(err)
	}
	return k, tok, nil
}
