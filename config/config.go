package config

import "github.com/go-webauthn/webauthn/webauthn"

func SetupWebAuthn(rpDisplayName, rpID, rpOrigin string) *webauthn.WebAuthn {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		panic("failed to create webauthn instance: " + err.Error())
	}
	return webAuthn
}
