package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	authn "github.com/go-authn/fido"
	linuxfido "github.com/go-gnulinux/fido"
	macfido "github.com/go-macos/fido"
)

// device is one attached key, listed without being opened.
type device struct {
	// ID is what --device takes: stable while the key stays in its port.
	ID string
	// Label names the key to a person.
	Label string
	// Name is the product string and Serial the serial when the key has one.
	Name, Serial string
	// Vendor is the USB vendor id the operating system reports.
	Vendor uint16
	open   func(context.Context) (*authn.Key, error)
}

// The platform lists and openers, replaced by tests.
var (
	listMac         = macfido.Devices
	openMacDevice   = macfido.OpenDevice
	listLinux       = linuxfido.Devices
	openLinuxDevice = linuxfido.OpenDevice
)

// selectTimeout is how long the person has to touch the key to use.
var selectTimeout = 30 * time.Second

// listDevices lists the attached keys over the operating system's transport;
// tests replace it. Nothing is opened and nothing is touched.
var listDevices = func() ([]device, error) {
	var out []device
	switch goos {
	case "darwin":
		ds, err := listMac()
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			out = append(out, device{
				ID: d.Path, Label: d.String(), Name: d.Name, Serial: d.Serial, Vendor: d.VendorID,
				open: func(ctx context.Context) (*authn.Key, error) {
					t, err := openMacDevice(d)
					if err != nil {
						return nil, err
					}
					return authn.Open(ctx, t)
				},
			})
		}
	case "linux":
		ds, err := listLinux()
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			// The port is what stays put when another key is plugged in first;
			// /dev/hidrawN is numbered in the order the kernel met them.
			id := d.Phys
			if id == "" {
				id = d.Path
			}
			out = append(out, device{
				ID: id, Label: d.String(), Name: d.Name, Serial: d.Serial, Vendor: d.VendorID,
				open: func(ctx context.Context) (*authn.Key, error) {
					t, err := openLinuxDevice(d)
					if err != nil {
						return nil, err
					}
					return authn.Open(ctx, t)
				},
			})
		}
	default:
		return nil, fmt.Errorf("no CTAP transport for %s: Windows refuses raw HID to a process that is not elevated, "+
			"so PIN and fingerprint management need macOS or Linux", goos)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// chooseByTouch asks every key for a touch and returns the one touched; tests
// replace it.
var chooseByTouch = func(ctx context.Context, devs []device) (*authn.Selected, error) {
	cands := make([]authn.Candidate, len(devs))
	for i, d := range devs {
		cands[i] = authn.Candidate{Label: d.Label, Open: d.open}
	}
	return authn.Select(ctx, cands)
}

// errNoKey is what listing nothing means to the commands.
var errNoKey = errors.New("no security key is attached")

// findKey opens the key --device names: the one with that ID, matched exactly
// (a prefix or a position could name another key after a replug), else the one
// whose NAME it is. A name on two keys is refused, naming both.
func findKey(ctx context.Context, devs []device, want string) (device, *authn.Key, error) {
	for _, d := range devs {
		if d.ID == want {
			k, err := d.open(ctx)
			return d, k, err
		}
	}
	type match struct {
		d device
		k *authn.Key
	}
	var found []match
	closeAll := func() {
		for _, m := range found {
			m.k.Close()
		}
	}
	for _, d := range devs {
		k, err := d.open(ctx)
		if err != nil {
			continue // a key that will not open cannot be shown to have the name
		}
		if name, _, _ := keyName(ctx, realKey{k, d}); name == want {
			found = append(found, match{d, k})
			continue
		}
		k.Close()
	}
	switch len(found) {
	case 1:
		return found[0].d, found[0].k, nil
	case 0:
		var ids []string
		for _, d := range devs {
			ids = append(ids, d.ID)
		}
		return device{}, nil, fmt.Errorf("no attached key has the id or name %q (attached: %s); `fido list` shows them", want, strings.Join(ids, ", "))
	}
	closeAll()
	var labels []string
	for _, m := range found {
		labels = append(labels, m.d.Label)
	}
	return device{}, nil, fmt.Errorf("the name %q is on %d keys (%s): name them differently, or pass --device with an id", want, len(found), strings.Join(labels, "; "))
}

// openKey chooses the key a command acts on and opens it; tests replace it.
//
// With --device (an ID or a name), that key. With one key attached, that key.
// With several and no --device, the person touches the one to use (CTAP 2.1
// authenticatorSelection): a command that WRITES is never run on "the first".
// Either way the key is named on stderr BEFORE anything is done to it.
var openKey = func(cmd *cobra.Command, write bool) (keyAPI, error) {
	ctx := ctxOf(cmd)
	devs, err := listDevices()
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, errNoKey
	}
	errw := cmd.ErrOrStderr()
	want, _ := cmd.Flags().GetString("device")
	if want != "" || len(devs) == 1 {
		d, k := devs[0], (*authn.Key)(nil)
		if want != "" {
			if d, k, err = findKey(ctx, devs, want); err != nil {
				return nil, err
			}
		} else if k, err = d.open(ctx); err != nil {
			return nil, err
		}
		rk := realKey{k, d}
		name, _, _ := keyName(ctx, rk)
		announce(errw, d.Label, name, write)
		return rk, nil
	}

	fmt.Fprintf(errw, "%d security keys are attached:\n", len(devs))
	for _, d := range devs {
		fmt.Fprintf(errw, "  %s\n", safe(d.Label))
	}
	fmt.Fprintf(errw, "Touch the key to use (%s), or pass --device ID or NAME.\n", selectTimeout)
	sctx, stop := context.WithTimeout(ctx, selectTimeout)
	defer stop()
	sel, err := chooseByTouch(sctx, devs)
	if err != nil {
		return nil, err
	}
	if len(sel.AlsoTouched) > 0 {
		warn := fmt.Sprintf("%s and %s were touched at the same time", safe(sel.Label), safe(strings.Join(sel.AlsoTouched, ", ")))
		if write {
			sel.Key.Close()
			return nil, fmt.Errorf("%s: nothing was changed; touch ONE key, or pass --device ID", warn)
		}
		fmt.Fprintf(errw, "Warning: %s; using %s.\n", warn, safe(sel.Label))
	}
	rk := realKey{sel.Key, devs[sel.Index]}
	name, _, _ := keyName(ctx, rk)
	announce(errw, sel.Label, name, write)
	return rk, nil
}

// announce names the key (and its name, when it has one) before anything is
// done to it.
func announce(w interface{ Write([]byte) (int, error) }, label, name string, write bool) {
	if write {
		fmt.Fprintf(w, "This key will be changed: %s%s\n", safe(label), quoted(name))
		return
	}
	fmt.Fprintf(w, "Key: %s%s\n", safe(label), quoted(name))
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the attached keys (no touch, no PIN)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			devs, err := listDevices()
			if err != nil {
				return err
			}
			if len(devs) == 0 {
				return errNoKey
			}
			ctx := ctxOf(cmd)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "#\tID\tNAME\tPRODUCT\tSERIAL\tAAGUID\tPIN\tFINGERPRINTS")
			for i, d := range devs {
				serial := safe(d.Serial)
				if serial == "" {
					serial = "-"
				}
				devName, devID := safe(d.Name), safe(d.ID)
				k, err := d.open(ctx)
				if err != nil {
					fmt.Fprintf(tw, "%d\t%s\t?\t%s\t%s\t?\t?\t? (%s)\n", i, devID, devName, serial, oneLine(err))
					continue
				}
				rk := realKey{k, d}
				id, err := rk.Identity(ctx)
				if err != nil {
					k.Close()
					fmt.Fprintf(tw, "%d\t%s\t?\t%s\t%s\t?\t?\t? (%s)\n", i, devID, devName, serial, oneLine(err))
					continue
				}
				name, src, nerr := keyName(ctx, rk)
				k.Close()
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%x\t%s\t%s\n", i, devID, nameCell(name, src, nerr), devName, serial, id.AAGUID, pinWord(id), fingerprintWord(id))
			}
			return tw.Flush()
		},
	}
}

func pinWord(id authn.Identity) string {
	switch {
	case id.PINSet && id.ForcePINChange:
		return "set (change required)"
	case id.PINSet:
		return "set"
	case id.PINCapable:
		return "not set"
	}
	return "none"
}

func fingerprintWord(id authn.Identity) string {
	switch {
	case id.FingerprintsEnrolled:
		return "enrolled"
	case id.FingerprintCapable:
		return "none enrolled"
	}
	return "no sensor"
}

// oneLine trims a library error to what a table cell can hold.
func oneLine(err error) string {
	return safe(strings.TrimPrefix(strings.ReplaceAll(err.Error(), "\n", " "), "fido: "))
}

// nameCell is the NAME column: the name, marked when it comes from the local
// alias table, a dash for none, and a question mark when the key will not show
// its name (or could not be asked).
func nameCell(name string, src nameSource, err error) string {
	switch {
	case err != nil:
		return "? (" + oneLine(err) + ")"
	case src == nameAlias:
		return safe(name) + " (alias)"
	case src == nameHidden:
		return "? (will not show it without a PIN)"
	case name == "":
		return "-"
	}
	return safe(name)
}
