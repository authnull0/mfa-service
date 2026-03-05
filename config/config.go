package config

import (
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

func SetupWebAuthn(rpDisplayName, rpID, rpOrigin string) *webauthn.WebAuthn {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{"https://sscdev.authnull.com"},
	}
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		panic("failed to create webauthn instance: " + err.Error())
	}
	log.Default().Printf("Successfully setup WebAuthn values : %v", webAuthn)
	return webAuthn
}
