package dto

// passkey_dto.go — add these to your existing dto package.
// Pattern: sessionData is serialized by the server, sent to the client,
// and echoed back in the next request — no server-side session store needed.

import (
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
)

// ── Requests ──────────────────────────────────────────────────────────────────

type PasskeySetupRequest struct {
	Email    string `json:"email"     binding:"required,email"`
	TenantID int    `json:"tenant_id" binding:"required"`
}

type PasskeyConfirmRequest struct {
	Email       string          `json:"email"        binding:"required,email"`
	TenantID    int             `json:"tenant_id"    binding:"required"`
	SessionData json.RawMessage `json:"session_data" binding:"required"` // echoed from BeginSetup response
	Credential  json.RawMessage `json:"credential"   binding:"required"` // raw output of navigator.credentials.create()
}

type PasskeyAuthRequest struct {
	Email    string `json:"email"     binding:"required,email"`
	TenantID int    `json:"tenant_id" binding:"required"`
}

type PasskeyVerifyRequest struct {
	Email       string          `json:"email"        binding:"required,email"`
	TenantID    int             `json:"tenant_id"    binding:"required"`
	SessionData json.RawMessage `json:"session_data" binding:"required"` // echoed from BeginAuthentication response
	Credential  json.RawMessage `json:"credential"   binding:"required"` // raw output of navigator.credentials.get()
}

// ── Responses ─────────────────────────────────────────────────────────────────

type PasskeySetupResponse struct {
	Success     bool                         `json:"success"`
	Options     *protocol.CredentialCreation `json:"options"`      // consumed by navigator.credentials.create()
	SessionData json.RawMessage              `json:"session_data"` // client must return this in confirmSetup
}

type PasskeyConfirmResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type PasskeyAuthOptionsResponse struct {
	Success     bool                          `json:"success"`
	Options     *protocol.CredentialAssertion `json:"options"`      // consumed by navigator.credentials.get()
	SessionData json.RawMessage               `json:"session_data"` // client must return this in verify
}

// AuthenticationResponse is already defined in your project; passkey reuses it.
