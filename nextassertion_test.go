package fido

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

// Three discoverable credentials of one relying party, and one of another.
func threeCredentials(t *testing.T) (*Key, *virtualAuthenticator) {
	t.Helper()
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	for range 3 {
		register(t, k, v, Extensions{HMACSecret: true}, Token{})
	}
	_, err := k.MakeCredential(context.Background(), MakeCredentialRequest{
		ClientDataHash: testCDH, RP: RelyingParty{ID: "other.example"}, User: User{ID: []byte("x")},
		Options: map[string]bool{"rk": true}, Extensions: Extensions{HMACSecret: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return k, v
}

func discoverAll(k *Key, h *HMACSecret, max int) ([]*Assertion, error) {
	return k.GetAssertions(context.Background(), GetAssertionRequest{
		RPID: testRP, ClientDataHash: testCDH, HMACSecret: h,
	}, max)
}

func TestGetAssertionsWalksEveryCredentialNewestFirst(t *testing.T) {
	k, v := threeCredentials(t)
	v.nextHMAC = true
	as, err := discoverAll(k, &HMACSecret{Salt1: salt1, Salt2: salt2}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 3 {
		t.Fatalf("%d assertions, want the 3 credentials of the relying party", len(as))
	}
	want := []string{"getAssertion", "getNextAssertion", "getNextAssertion"}
	if got := v.asked[len(v.asked)-3:]; !slices.Equal(got, want) {
		t.Fatalf("commands %v, want %v", got, want)
	}
	// §6.2.2 step 12.2.1: newest first; and each output is that credential's.
	for i, a := range as {
		c := v.creds[2-i]
		if !bytes.Equal(a.Credential.ID, c.id) {
			t.Fatalf("assertion %d is not credential %d (newest first)", i, 2-i)
		}
		if a.HMACSecret == nil || !bytes.Equal(a.HMACSecret.First, c.expected(false, salt1)) ||
			!bytes.Equal(a.HMACSecret.Second, c.expected(false, salt2)) {
			t.Fatalf("assertion %d: hmac-secret is not that credential's", i)
		}
	}
	if as[0].Available != 3 {
		t.Fatalf("numberOfCredentials %d", as[0].Available)
	}
}

func TestGetAssertionsNextWithoutHMACIsNilNotAnError(t *testing.T) {
	// §6.3 does not promise extension outputs: an authenticator that leaves
	// them out of the next assertions must be visible, not fatal.
	k, v := threeCredentials(t)
	v.nextHMAC = false
	as, err := discoverAll(k, &HMACSecret{Salt1: salt1}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if as[0].HMACSecret == nil {
		t.Fatal("the first assertion lost its output")
	}
	for i, a := range as[1:] {
		if a.HMACSecret != nil {
			t.Fatalf("next assertion %d invented an output", i+1)
		}
	}
}

func TestGetAssertionsBoundsAndErrors(t *testing.T) {
	k, v := threeCredentials(t)
	if _, err := discoverAll(k, nil, 0); err == nil {
		t.Fatal("a bound of 0 accepted")
	}
	before := len(v.asked)
	if _, err := discoverAll(k, nil, 2); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("3 announced, bound 2: %v", err)
	}
	if got := v.asked[before:]; !slices.Equal(got, []string{"getAssertion"}) {
		t.Fatalf("a refused count still sent %v", got)
	}
	// A key that announces more than it has: the walk fails on the missing
	// one instead of inventing it.
	v.announce = 5
	if _, err := discoverAll(k, nil, 10); err == nil || !strings.Contains(err.Error(), "next assertion 4 of 5") {
		t.Fatalf("lying count: %v", err)
	}
	v.announce = 0
	// One credential named in Allow: no walk.
	as, err := k.GetAssertions(context.Background(), GetAssertionRequest{
		RPID: testRP, ClientDataHash: testCDH, Allow: []Credential{{ID: v.creds[0].id}},
	}, 10)
	if err != nil || len(as) != 1 {
		t.Fatalf("named credential: %d %v", len(as), err)
	}
	// The first request failing is reported as is.
	if _, err := k.GetAssertions(context.Background(), GetAssertionRequest{RPID: "", ClientDataHash: testCDH}, 10); err == nil {
		t.Fatal("empty rp id accepted")
	}
	if _, err := k.GetAssertions(context.Background(), GetAssertionRequest{RPID: "nobody.example", ClientDataHash: testCDH}, 10); err == nil {
		t.Fatal("no credential, no error")
	}
}

func TestGetAssertionsCorruptNextReply(t *testing.T) {
	k, v := threeCredentials(t)
	v.nextHMAC = true
	// A next assertion whose hmac-secret output is malformed is an error, not
	// a silent nil. (AES-CBC has no tag, so a flipped byte decrypts to other
	// bytes; what the client CAN check is the length: one block short.)
	n := 0
	v.tamper = func(_ int, _, enc []byte) []byte {
		n++
		if n > 1 {
			return enc[:len(enc)-16]
		}
		return enc
	}
	if _, err := discoverAll(k, &HMACSecret{Salt1: salt1}, 10); err == nil || !strings.Contains(err.Error(), "next assertion 2 of 3") {
		t.Fatalf("tampered next output: %v", err)
	}
}
