package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"

	authn "github.com/go-authn/fido"
	"github.com/go-authn/fido/mds"
	"github.com/go-authn/webauthn"
)

// The throwaway relying party every attestation is made for. ".invalid" is
// reserved (RFC 6761): no site can ever own it, so the credential is useless
// to anyone and registers nowhere.
const (
	attestRPID    = "fido-attest.invalid"
	attestOrigin  = "https://" + attestRPID
	maxStmtCerts  = 8
	maxStmtCertSz = 8 << 10
	maxStmtSig    = 1 << 10
)

// oidAAGUID is id-fido-gen-ce-aaguid (WebAuthn §8.2.1).
var oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// stmt is the packed attestation statement (WebAuthn §8.2), as far as this
// command reads it. Unknown members are ignored here; the verifier refuses them.
type stmt struct {
	Alg int64    `cbor:"alg"`
	Sig []byte   `cbor:"sig"`
	X5C [][]byte `cbor:"x5c"`
}

// parseStmt reads the statement's alg, sig and x5c, bounded: the statement is
// the key's word and is parsed before anything has verified it.
func parseStmt(raw []byte) (stmt, error) {
	var s stmt
	if len(raw) == 0 {
		return s, nil
	}
	if err := cbor.Unmarshal(raw, &s); err != nil {
		return stmt{}, fmt.Errorf("the attestation statement is not a CBOR map: %w", err)
	}
	if len(s.X5C) > maxStmtCerts {
		return stmt{}, fmt.Errorf("x5c holds %d certificates, more than the %d accepted", len(s.X5C), maxStmtCerts)
	}
	if len(s.Sig) > maxStmtSig {
		return stmt{}, fmt.Errorf("sig is %d bytes, more than the %d accepted", len(s.Sig), maxStmtSig)
	}
	for i, c := range s.X5C {
		if len(c) > maxStmtCertSz {
			return stmt{}, fmt.Errorf("x5c[%d] is %d bytes, more than the %d accepted", i, len(c), maxStmtCertSz)
		}
	}
	return s, nil
}

// aaguidExt is what a certificate says about id-fido-gen-ce-aaguid.
type aaguidExt struct {
	Present  bool
	Critical bool
	Value    []byte // the 16 bytes, when the extension is a well-formed OCTET STRING of 16
	Err      string // why Value is empty although Present
}

// certAAGUID reads the extension out of a certificate.
func certAAGUID(c *x509.Certificate) aaguidExt {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidAAGUID) {
			continue
		}
		x := aaguidExt{Present: true, Critical: e.Critical}
		var got []byte
		rest, err := asn1.Unmarshal(e.Value, &got)
		switch {
		case err != nil:
			x.Err = "not a DER OCTET STRING"
		case len(rest) != 0:
			x.Err = "trailing bytes after the OCTET STRING"
		case len(got) != 16:
			x.Err = fmt.Sprintf("the OCTET STRING is %d bytes, not 16", len(got))
		default:
			x.Value = got
		}
		return x
	}
	return aaguidExt{}
}

// fmtAAGUID prints 16 bytes the way MDS does.
func fmtAAGUID(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) != 32 {
		return h
	}
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// printCert prints one x5c certificate: its identity and its AAGUID extension.
func printCert(out io.Writer, i int, c *x509.Certificate, authAAGUID [16]byte) {
	fmt.Fprintf(out, "  x5c[%d]\n", i)
	fmt.Fprintf(out, "    subject:   %s\n", safe(c.Subject.String()))
	fmt.Fprintf(out, "    issuer:    %s\n", safe(c.Issuer.String()))
	fmt.Fprintf(out, "    serial:    %s\n", c.SerialNumber.Text(16))
	fmt.Fprintf(out, "    valid:     %s to %s\n", c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	x := certAAGUID(c)
	switch {
	case !x.Present:
		fmt.Fprintf(out, "    id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4): ABSENT\n")
	case x.Value == nil:
		fmt.Fprintf(out, "    id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4): PRESENT but malformed (%s), critical=%t\n", x.Err, x.Critical)
	default:
		match := "DIFFERS from"
		if bytes.Equal(x.Value, authAAGUID[:]) {
			match = "EQUALS"
		}
		fmt.Fprintf(out, "    id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4): PRESENT %s, critical=%t, %s authData's AAGUID\n", fmtAAGUID(x.Value), x.Critical, match)
	}
}

// attestOpts holds the flags of `fido attest`.
type attestOpts struct {
	pin    pinSrc
	saveTo string
}

// checkSaveTo refuses before the key is touched: nothing is overwritten.
func checkSaveTo(path string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s exists or cannot be examined: --save-to never overwrites", safe(path))
	}
	return nil
}

// writeNew writes b to a file that did not exist, readable by its owner only.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	return errors.Join(werr, f.Close())
}

func attestCmd() *cobra.Command {
	var o attestOpts
	c := &cobra.Command{
		Use:   "attest",
		Short: "Register a throwaway credential and show the key's attestation, verified against the MDS roots",
		Long: "Makes a credential for the reserved relying party " + attestRPID + " with user " +
			"verification required (the fingerprint, when the key has one; else the PIN), then " +
			"prints what the key attested: format, algorithm, the AAGUID of the authenticator data, " +
			"the flags, and for every certificate of the statement its subject, issuer, serial, " +
			"validity and whether it carries the id-fido-gen-ce-aaguid extension and what it holds. " +
			"It then verifies the signature over authData||clientDataHash with the leaf key (through " +
			"github.com/go-authn/webauthn) and the chain against the attestation roots the verified " +
			"FIDO MDS lists for that AAGUID.\n\n" +
			"The credential is NOT discoverable: it is not stored on the key (a non-resident credential " +
			"is a blob the key can decrypt later), so there is nothing to delete. Nothing printed is a " +
			"secret; a PIN is read only from the terminal, --pin-file or --pin-from, never an argument.",
		Args: cobra.NoArgs,
	}
	refresh := addRefresh(c)
	o.pin.addFlags(c, "pin", "the PIN, when the key has no built-in verification or this is given,")
	c.Flags().StringVar(&o.saveTo, "save-to", "", "write the attestation object (CBOR) to this new `FILE` (mode 0600; an existing file is never overwritten)")
	c.RunE = func(cmd *cobra.Command, _ []string) error { return runAttest(cmd, o, *refresh) }
	return c
}

func runAttest(cmd *cobra.Command, o attestOpts, refresh bool) error {
	ctx := ctxOf(cmd)
	out := cmd.OutOrStdout()
	if err := checkSaveTo(o.saveTo); err != nil {
		return err
	}
	k, err := openKey(cmd, false)
	if err != nil {
		return err
	}
	defer k.Close()
	info, err := k.GetInfo(ctx)
	if err != nil {
		return err
	}

	// crypto/rand.Read never fails: the process stops if the system source does.
	challenge := make([]byte, 32)
	userID := make([]byte, 32)
	rand.Read(challenge)
	rand.Read(userID)
	cdJSON := []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) +
		`","origin":"` + attestOrigin + `"}`)
	hash := sha256.Sum256(cdJSON)
	req := authn.MakeCredentialRequest{
		ClientDataHash: hash[:],
		RP:             authn.RelyingParty{ID: attestRPID, Name: "fido attest (throwaway)"},
		User:           authn.User{ID: userID, Name: "attest", DisplayName: "attest"},
		Algorithms:     []int64{authn.AlgES256},
		Options:        map[string]bool{"rk": false},
	}
	usePIN := o.pin.file != "" || o.pin.from != "" || !info.Has("uv")
	switch {
	case usePIN && !info.Has("clientPin"):
		return errors.New("this key has neither a configured built-in verification (fingerprint) nor a PIN: it cannot make a verified credential")
	case usePIN:
		if info.ForcePINChange {
			return errors.New("the PIN must be changed before it is used: `fido pin change`")
		}
		if err := checkRetries(ctx, cmd, k); err != nil {
			return err
		}
		p, err := readPIN(cmd, o.pin, "PIN: ")
		if err != nil {
			return err
		}
		defer clear(p)
		tok, err := k.PINTokenBytes(ctx, p, protocolOf(info), authn.PermMakeCredential, attestRPID)
		if err != nil {
			return err
		}
		req.Token = tok
	default:
		req.Options["uv"] = true
		fmt.Fprintln(cmd.ErrOrStderr(), "Touch the key and present a finger when it asks.")
	}

	att, err := k.MakeCredential(ctx, req)
	if err != nil {
		return err
	}
	obj, err := attestationObject(att)
	if err != nil {
		return err
	}
	if o.saveTo != "" {
		if err := writeNew(o.saveTo, obj); err != nil {
			return fmt.Errorf("--save-to: %w", err)
		}
		fmt.Fprintf(out, "attestation object (%d bytes, CBOR) saved to %s\n", len(obj), safe(o.saveTo))
	}
	return reportAttestation(cmd, out, att, obj, challenge, cdJSON, refresh)
}

// attestationObject is the WebAuthn attestationObject (§6.5) of a registration,
// in CTAP2 canonical form.
func attestationObject(att *authn.Attestation) ([]byte, error) {
	stmtRaw := []byte(att.Statement)
	if len(stmtRaw) == 0 {
		stmtRaw = []byte{0xa0} // an empty map
	}
	return ctap2Enc.Marshal(map[string]any{
		"fmt":      att.Format,
		"attStmt":  cbor.RawMessage(stmtRaw),
		"authData": att.AuthData,
	})
}

// ctap2Enc encodes canonically; the options are constants, which EncMode accepts.
var ctap2Enc, _ = cbor.CTAP2EncOptions().EncMode()

// flagNames lists the set flags of authenticator data.
func flagNames(f authn.Flags) string {
	var s []string
	for _, p := range []struct {
		b authn.Flags
		n string
	}{{authn.FlagUP, "UP"}, {authn.FlagUV, "UV"}, {authn.FlagBE, "BE"}, {authn.FlagBS, "BS"}, {authn.FlagAT, "AT"}, {authn.FlagED, "ED"}} {
		if f.Has(p.b) {
			s = append(s, p.n)
		}
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, "|")
}

// reportAttestation prints the evidence and the verdicts. It prints every
// certificate before it judges any, so that a statement that fails still shows
// what it carried; the returned error says which verdict failed.
func reportAttestation(cmd *cobra.Command, out io.Writer, att *authn.Attestation, obj, challenge, cdJSON []byte, refresh bool) error {
	aaguid := att.Parsed.AAGUID
	fmt.Fprintf(out, "fmt:            %s\n", safe(att.Format))
	fmt.Fprintf(out, "authData AAGUID: %s\n", fmtAAGUID(aaguid[:]))
	fmt.Fprintf(out, "flags:          0x%02x (%s)\n", byte(att.Parsed.Flags), flagNames(att.Parsed.Flags))
	fmt.Fprintf(out, "credential:     discardable: made non-resident (rk=false) for %s, so nothing is stored on the key\n", attestRPID)

	s, perr := parseStmt(att.Statement)
	if perr != nil {
		fmt.Fprintf(out, "statement:      UNREADABLE: %s\n", safe(perr.Error()))
	} else {
		fmt.Fprintf(out, "alg:            %d\n", s.Alg)
		fmt.Fprintf(out, "x5c:            %d certificate(s)\n", len(s.X5C))
	}
	for i, der := range s.X5C {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Fprintf(out, "  x5c[%d]: NOT A CERTIFICATE: %s\n", i, safe(err.Error()))
			continue
		}
		printCert(out, i, c, aaguid)
	}

	var failed []string
	rp := webauthn.RelyingParty{ID: attestRPID, Origins: []string{attestOrigin}}
	_, wa, verr := rp.VerifyRegistrationAttested(challenge, cdJSON, obj, webauthn.Policy{RequireUV: true})
	if verr != nil {
		fmt.Fprintf(out, "statement:      NOT VERIFIED: %s\n", safe(verr.Error()))
		failed = append(failed, "statement")
	} else if wa.Type != webauthn.AttestationBasic {
		fmt.Fprintf(out, "statement:      %s attestation: it proves nothing about the hardware, there is no chain to check\n", safe(att.Format))
		failed = append(failed, "no certificate chain")
	} else {
		fmt.Fprintf(out, "statement:      VERIFIED: signature over authData||clientDataHash by the leaf key, the certificate rules of WebAuthn 8.2.1, and the AAGUID extension (when present) equal to authData's\n")
		if err := verifyChain(cmd, out, wa, aaguid, refresh); err != nil {
			failed = append(failed, "chain")
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the attestation is not verified (%s)", strings.Join(failed, ", "))
	}
	return nil
}

// verifyChain checks the leaf against the roots the verified MDS lists for the AAGUID.
func verifyChain(cmd *cobra.Command, out io.Writer, wa webauthn.Attestation, aaguid [16]byte, refresh bool) error {
	g, _ := mds.NormalizeAAGUID(hex.EncodeToString(aaguid[:]))
	b, err := loadMDS(ctxOf(cmd), refresh)
	if err != nil {
		fmt.Fprintf(out, "chain:          NOT CHECKED: the MDS could not be loaded: %s\n", safe(err.Error()))
		return err
	}
	e := b.Lookup(g)
	if e == nil {
		fmt.Fprintf(out, "chain:          NOT VERIFIED: %s is not listed in the FIDO MDS (blob no %d)\n", g, b.No)
		return errors.New("not listed")
	}
	roots, err := e.RootCertificates()
	if err != nil {
		fmt.Fprintf(out, "chain:          NOT CHECKED: the MDS roots of %s are unreadable: %s\n", g, safe(err.Error()))
		return err
	}
	if err := wa.VerifyTrustPath(roots, time.Now()); err != nil {
		fmt.Fprintf(out, "chain:          NOT VERIFIED against the %d MDS attestation root(s) of %s (%s): %s\n", len(roots), g, safe(e.Description()), safe(err.Error()))
		return err
	}
	fmt.Fprintf(out, "chain:          VERIFIED to one of the %d MDS attestation root(s) of %s (%s), blob no %d\n", len(roots), g, safe(e.Description()), b.No)
	return nil
}
