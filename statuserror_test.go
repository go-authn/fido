package fido

import (
	"context"
	"errors"
	"testing"
)

// TestStatusErrorIsTypedAndKeepsItsMessage: a refusal can be told apart with
// errors.As, through the wrapping GetAssertions adds, and the message is the
// one callers already saw.
func TestStatusErrorIsTypedAndKeepsItsMessage(t *testing.T) {
	v := newVirtualAuthenticator(t, "1234")
	k := virtualKey(t, v)
	_, err := k.GetAssertion(context.Background(), GetAssertionRequest{RPID: "nobody.example", ClientDataHash: testCDH})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != StatusNoCredentials {
		t.Fatalf("not a StatusError with 0x2e: %v", err)
	}
	if want := "fido: " + k.Name() + ": " + StatusNoCredentials.String(); err.Error() != want {
		t.Fatalf("message %q, want %q", err.Error(), want)
	}
	// Through a wrapping layer as well.
	_, err = k.GetAssertions(context.Background(), GetAssertionRequest{RPID: "nobody.example", ClientDataHash: testCDH}, 3)
	if !errors.As(err, &se) || se.Status != StatusNoCredentials {
		t.Fatalf("GetAssertions lost the status: %v", err)
	}
	// The names match the table's numbers.
	for s, want := range map[Status]byte{
		StatusOperationDenied: 0x27, StatusNoCredentials: 0x2e, StatusUserActionTimeout: 0x2f,
		StatusPINInvalid: 0x31, StatusPINBlocked: 0x32, StatusPINAuthBlocked: 0x34,
	} {
		if byte(s) != want || statusNames[s] == "" {
			t.Errorf("%#x: named %#x, described %q", byte(s), want, statusNames[s])
		}
	}
}
