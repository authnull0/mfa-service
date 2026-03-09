package config

import (
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

func SetupWebAuthn(rpDisplayName, rpID, rpOrigin string) *webauthn.WebAuthn {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          "http://localhost:8080",
		RPOrigins:     []string{"https://sscdev.authnull.com", "http://localhost:8080"},
	}
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		panic("failed to create webauthn instance: " + err.Error())
	}
	log.Default().Printf("Successfully setup WebAuthn values : %v", webAuthn.Config.RPOrigins)
	log.Default().Printf("Successfully setup WebAuthn values : %v", webAuthn.Config.RPID)
	log.Default().Printf("Successfully setup WebAuthn values : %v", webAuthn.Config.RPDisplayName)

	return webAuthn
}
