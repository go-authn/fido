package main

import (
	"context"
	"fmt"

	authn "github.com/go-authn/fido"
)

// The name methods of the fake key (fields are on fake in main_test.go).

func (f *fake) Device() device { return f.dev }

func (f *fake) ReadName(context.Context) (string, error) {
	if f.readNameErr != nil {
		return "", f.readNameErr
	}
	if f.refuses {
		return "", fmt.Errorf("%w: status 0x27", authn.ErrNameRefused)
	}
	if f.stored == "" {
		return "", authn.ErrNoName
	}
	return f.stored, nil
}

func (f *fake) SetName(_ context.Context, name string, _ authn.NameTokens) error {
	if f.setNameErr != nil {
		return f.setNameErr
	}
	f.setNames = append(f.setNames, name)
	f.stored = name
	return nil
}

func (f *fake) RemoveName(context.Context, authn.NameTokens) error {
	f.removedNames++
	if f.removeNameErr == nil {
		f.stored = ""
	}
	return f.removeNameErr
}

func (f *fake) NameTokens(_ context.Context, pin string, _ authn.PINProtocol, _ authn.Info) (authn.NameTokens, error) {
	f.tokenPIN = pin
	return authn.NameTokens{}, f.nameTokensErr
}
