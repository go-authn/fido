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
	open         func(context.Context) (*authn.Key, error)
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
				ID: d.Path, Label: d.String(), Name: d.Name, Serial: d.Serial,
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
				ID: id, Label: d.String(), Name: d.Name, Serial: d.Serial,
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

// findDevice matches --device against the listed IDs, exactly: a prefix or a
// position could name a different key after a replug.
func findDevice(devs []device, id string) (device, error) {
	for _, d := range devs {
		if d.ID == id {
			return d, nil
		}
	}
	var ids []string
	for _, d := range devs {
		ids = append(ids, d.ID)
	}
	return device{}, fmt.Errorf("no attached key has the id %q (attached: %s); `fido list` shows them", id, strings.Join(ids, ", "))
}

// openKey chooses the key a command acts on and opens it; tests replace it.
//
// With --device, that key. With one key attached, that key. With several and no
// --device, the person touches the one to use (CTAP 2.1 authenticatorSelection):
// a command that WRITES is never run on "the first". Either way the key is
// named on stderr BEFORE anything is done to it.
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
		d := devs[0]
		if want != "" {
			if d, err = findDevice(devs, want); err != nil {
				return nil, err
			}
		}
		k, err := d.open(ctx)
		if err != nil {
			return nil, err
		}
		announce(errw, d.Label, write)
		return realKey{k}, nil
	}

	fmt.Fprintf(errw, "%d security keys are attached:\n", len(devs))
	for _, d := range devs {
		fmt.Fprintf(errw, "  %s\n", d.Label)
	}
	fmt.Fprintf(errw, "Touch the key to use (%s), or pass --device ID.\n", selectTimeout)
	sctx, stop := context.WithTimeout(ctx, selectTimeout)
	defer stop()
	sel, err := chooseByTouch(sctx, devs)
	if err != nil {
		return nil, err
	}
	if len(sel.AlsoTouched) > 0 {
		warn := fmt.Sprintf("%s and %s were touched at the same time", sel.Label, strings.Join(sel.AlsoTouched, ", "))
		if write {
			sel.Key.Close()
			return nil, fmt.Errorf("%s: nothing was changed; touch ONE key, or pass --device ID", warn)
		}
		fmt.Fprintf(errw, "Warning: %s; using %s.\n", warn, sel.Label)
	}
	announce(errw, sel.Label, write)
	return realKey{sel.Key}, nil
}

// announce names the key before anything is done to it.
func announce(w interface{ Write([]byte) (int, error) }, label string, write bool) {
	if write {
		fmt.Fprintf(w, "This key will be changed: %s\n", label)
		return
	}
	fmt.Fprintf(w, "Key: %s\n", label)
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
			fmt.Fprintln(tw, "#\tID\tPRODUCT\tSERIAL\tAAGUID\tPIN\tFINGERPRINTS")
			for i, d := range devs {
				serial := d.Serial
				if serial == "" {
					serial = "-"
				}
				row := fmt.Sprintf("%d\t%s\t%s\t%s\t", i, d.ID, d.Name, serial)
				k, err := d.open(ctx)
				if err != nil {
					fmt.Fprintf(tw, "%s?\t?\t? (%s)\n", row, oneLine(err))
					continue
				}
				id, err := realKey{k}.Identity(ctx)
				k.Close()
				if err != nil {
					fmt.Fprintf(tw, "%s?\t?\t? (%s)\n", row, oneLine(err))
					continue
				}
				fmt.Fprintf(tw, "%s%x\t%s\t%s\n", row, id.AAGUID, pinWord(id), fingerprintWord(id))
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
	return strings.TrimPrefix(strings.ReplaceAll(err.Error(), "\n", " "), "fido: ")
}
