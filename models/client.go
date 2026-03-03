// models/client.go
package models

import (
	"log"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lib/pq"
)

// Method to set credentials (called before BeginLogin)
func (u *WebAuthnUser) SetCredentials(creds []webauthn.Credential) {
	u.Credentials = creds
}

// WebAuthn interface method - returns loaded credentials
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	if len(u.Credentials) == 0 {
		log.Printf("Warning: WebAuthnCredentials called but no credentials loaded for user %s", u.Email)
	}
	return u.Credentials
}

type Client struct {
	ID               string `gorm:"primaryKey"`
	ClientID         string `gorm:"uniqueIndex"`
	TenantID         string
	ProjectID        string
	Name             string
	Active           bool
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
	LastLogin        *time.Time            `json:"last_login,omitempty"`
	MFAEnabled       bool                  `gorm:"default:false;not null"`
	MFAMethod        pq.StringArray        `gorm:"type:text[]"`
	MFADefaultMethod string                `gorm:"type:text"`
	MFAEnrolledAt    time.Time             `gorm:"type:timestamptz"`
	MFAVerified      *bool                 `json:"mfa_verified,omitempty" gorm:"default:false"`
	Email            string                `json:"email"`
	credentials      []webauthn.Credential `gorm:"-" json:"-"`
}
type WebAuthnUser struct {
	ID          int
	Email       string
	Credentials []webauthn.Credential
}

func NewWebAuthnUser(c *WebAuthnUser) *WebAuthnUser {
	return c
}

// WebAuthn interface methods
func (u *WebAuthnUser) WebAuthnID() []byte {
	// Use ClientID instead of ID for WebAuthn
	return []byte(strconv.Itoa(int(u.ID)))
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.Email != "" {
		return u.Email
	}
	return u.Email
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (c *WebAuthnUser) ToWebAuthnUser() webauthn.User {
	return c
}

// func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
// 	return u.Credentials
// }
