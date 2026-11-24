package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/go-authn/fido/mds"
)

// maxSearchLines bounds what `mds search` prints.
const maxSearchLines = 50

// selfDeclared is said every time an AAGUID is shown as coming from a key.
const selfDeclared = "note: this AAGUID is what the key says about itself in getInfo. It is self-declared, " +
	"so it proves nothing: only a verified attestation statement (makeCredential) that chains to the " +
	"attestation root certificates above proves that the key is this model."

// newMDSClient builds the client of the FIDO Metadata Service. Verification
// is not a setting: the client carries no verification option, and the blob
// is checked against the pinned GlobalSign root on every load, cached or not.
func newMDSClient() (*mds.Client, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	return &mds.Client{Dir: filepath.Join(dir, "go-authn-fido", "mds")}, nil
}

// loadMDS returns the verified blob; tests replace it.
var loadMDS = func(ctx context.Context, refresh bool) (*mds.Blob, error) {
	c, err := newMDSClient()
	if err != nil {
		return nil, err
	}
	return c.Load(ctx, refresh)
}

func addRefresh(c *cobra.Command) *bool {
	return c.Flags().Bool("refresh", false, "download the blob again even if the cached one is still valid")
}

func mdsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "mds",
		Short: "Look an authenticator model up in the FIDO Metadata Service (MDS3)",
		Long: "The blob is downloaded from " + mds.DefaultURL + " and kept in the user cache " +
			"directory. It is verified on every use: JWS signature, certificate chain to the pinned " +
			"GlobalSign Root R46, the name " + mds.Hostname + ", revocation of every certificate " +
			"of the chain, and its nextUpdate. There is no option to skip the verification.",
	}
	lookup := &cobra.Command{
		Use:   "lookup AAGUID",
		Short: "Show the MDS entry of an AAGUID, with its attestation root certificates",
		Args:  cobra.ExactArgs(1),
	}
	refresh := addRefresh(lookup)
	lookup.RunE = func(cmd *cobra.Command, args []string) error {
		g, ok := mds.NormalizeAAGUID(args[0])
		if !ok {
			return fmt.Errorf("%q is not an AAGUID (16 bytes in hex, with or without dashes)", safe(args[0]))
		}
		b, err := loadMDS(ctxOf(cmd), *refresh)
		if err != nil {
			return err
		}
		e := b.Lookup(g)
		if e == nil {
			return fmt.Errorf("%s is not listed in the FIDO MDS (blob no %d)", g, b.No)
		}
		return printEntry(cmd.OutOrStdout(), b, e)
	}
	search := &cobra.Command{
		Use:   "search WORD",
		Short: "List the models whose name or AAGUID contains WORD",
		Args:  cobra.ExactArgs(1),
	}
	refreshS := addRefresh(search)
	search.RunE = func(cmd *cobra.Command, args []string) error {
		b, err := loadMDS(ctxOf(cmd), *refreshS)
		if err != nil {
			return err
		}
		found := b.Search(args[0])
		out := cmd.OutOrStdout()
		for i, e := range found {
			if i == maxSearchLines {
				fmt.Fprintf(out, "... and %d more\n", len(found)-i)
				break
			}
			fmt.Fprintf(out, "%s  %s\n", safe(e.AAGUID), safe(e.Description()))
		}
		if len(found) == 0 {
			return fmt.Errorf("nothing in the FIDO MDS (blob no %d) matches %q", b.No, safe(args[0]))
		}
		return nil
	}
	c.AddCommand(lookup, search)
	return c
}

// printEntry prints what the verified blob says of one model.
func printEntry(out io.Writer, b *mds.Blob, e *mds.Entry) error {
	fmt.Fprintf(out, "aaguid:         %s\n", safe(e.AAGUID))
	fmt.Fprintf(out, "description:    %s\n", safe(e.Description()))
	if s := e.MetadataStatement; s != nil {
		fmt.Fprintf(out, "protocol:       %s\n", safe(s.ProtocolFamily))
		fmt.Fprintf(out, "key protection: %s\n", safe(strings.Join(s.KeyProtection, ", ")))
		fmt.Fprintf(out, "attestation:    %s\n", safe(strings.Join(s.AttestationTypes, ", ")))
	}
	for _, r := range e.StatusReports {
		fmt.Fprintf(out, "status:         %s (from %s)\n", safe(r.Status), safe(r.EffectiveDate))
	}
	roots, err := e.RootCertificates()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "attestation root certificates: %d\n", len(roots))
	for _, c := range roots {
		sum := sha256.Sum256(c.Raw)
		fmt.Fprintf(out, "  %s\n    sha-256 %s\n", safe(c.Subject.String()), hex.EncodeToString(sum[:]))
	}
	fmt.Fprintf(out, "blob:           no %d, verified against GlobalSign Root R46, next update %s\n", b.No, safe(b.NextUpdateDate))
	return nil
}

func identifyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "identify",
		Short: "Name the attached key's model from the FIDO Metadata Service (read-only)",
		Long: "Reads the AAGUID the key reports in getInfo and looks it up in the verified " +
			"FIDO MDS. The AAGUID is self-declared by the key: this names the model the key " +
			"CLAIMS to be, and only a verified attestation proves it.",
		Args: cobra.NoArgs,
	}
	refresh := addRefresh(c)
	c.RunE = func(cmd *cobra.Command, _ []string) error {
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
		g, _ := mds.NormalizeAAGUID(hex.EncodeToString(info.AAGUID[:]))
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "reported aaguid: %s (self-declared)\n", g)
		b, err := loadMDS(ctx, *refresh)
		if err != nil {
			return err
		}
		e := b.Lookup(g)
		if e == nil {
			fmt.Fprintf(out, "not listed in the FIDO MDS (blob no %d)\n%s\n", b.No, selfDeclared)
			return nil
		}
		if err := printEntry(out, b, e); err != nil {
			return err
		}
		fmt.Fprintln(out, selfDeclared)
		return nil
	}
	return c
}
