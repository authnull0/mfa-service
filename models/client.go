// models/client.go
package models

import (
	"log"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lib/pq"
)

// Method to set credentials (called before BeginLogin)
func (u *Client) SetCredentials(creds []webauthn.Credential) {
	u.credentials = creds
}

// WebAuthn interface method - returns loaded credentials
func (u *Client) WebAuthnCredentials() []webauthn.Credential {
	if len(u.credentials) == 0 {
		log.Printf("Warning: WebAuthnCredentials called but no credentials loaded for user %s", u.Email)
	}
	return u.credentials
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

func NewWebAuthnUser(c *Client) *Client {
	return c
}

// WebAuthn interface methods
func (u *Client) WebAuthnID() []byte {
	// Use ClientID instead of ID for WebAuthn
	return []byte(u.ClientID)
}

func (u *Client) WebAuthnName() string {
	return u.Email
}

func (u *Client) WebAuthnDisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

func (u *Client) WebAuthnIcon() string {
	return ""
}

func (c *Client) ToWebAuthnUser() webauthn.User {
	return c
}
