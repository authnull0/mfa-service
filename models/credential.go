package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Credential struct {
	ID              uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ClientID        string         `gorm:"not null;index;column:client_id" json:"client_id"`
	CredentialID    []byte         `gorm:"unique;not null;column:credential_id" json:"credential_id"`
	PublicKey       []byte         `gorm:"not null;column:public_key" json:"public_key"`
	AttestationType string         `gorm:"column:attestation_type" json:"attestation_type"`
	AAGUID          *uuid.UUID     `gorm:"type:uuid;column:aaguid" json:"aaguid"`
	SignCount       int64          `gorm:"column:sign_count;default:0" json:"sign_count"`
	Transports      pq.StringArray `gorm:"type:text[];column:transports" json:"transports"`
	CreatedAt       time.Time      `gorm:"column:created_at;default:now()" json:"created_at"`
	UpdatedAt       time.Time      `gorm:"column:updated_at;default:now()" json:"updated_at"`
}

// Specify table name
func (Credential) TableName() string {
	return "did.credentials"
}

type PasskeyCredential struct {
	ID              uint           `gorm:"primaryKey;autoIncrement"                    db:"id"`
	UserID          int            `gorm:"type:varchar(255);not null;index"            db:"user_id"`          // FK → your clients table
	TenantID        int            `gorm:"type:varchar(255);not null;index"            db:"tenant_id"`        // for multi-tenant isolation
	CredentialID    []byte         `gorm:"type:bytea;not null;uniqueIndex"             db:"credential_id"`    // WebAuthn credential ID (raw bytes)
	PublicKey       []byte         `gorm:"type:bytea;not null"                         db:"public_key"`       // COSE-encoded public key
	AttestationType string         `gorm:"type:varchar(64);not null;default:'none'"    db:"attestation_type"` // "none", "packed", "fido-u2f", etc.
	AAGUID          []byte         `gorm:"type:bytea"                                  db:"aaguid"`           // authenticator model identifier
	SignCount       uint32         `gorm:"type:bigint;not null;default:0"              db:"sign_count"`       // increments each login; rollback = cloned key
	Transports      pq.StringArray `gorm:"type:text[]"                                 db:"transports"`       // ["usb","nfc","ble","internal"]
	UserVerified    bool           `gorm:"not null;default:false"                      db:"user_verified"`    // was PIN/biometric verified at registration?
	BackupEligible  bool           `gorm:"not null;default:false"                      db:"backup_eligible"`  // can this passkey sync to the cloud?
	BackupState     bool           `gorm:"not null;default:false"                      db:"backup_state"`     // is it currently backed up?
	Name            string         `gorm:"type:varchar(255)"                           db:"name"`             // user-friendly label e.g. "MacBook Touch ID"
	LastUsedAt      *time.Time     `gorm:"index"                                       db:"last_used_at"`
	CreatedAt       time.Time      `gorm:"autoCreateTime"                              db:"created_at"`
	UpdatedAt       time.Time      `gorm:"autoUpdateTime"                              db:"updated_at"`
}

func (PasskeyCredential) TableName() string {
	return "did.passkey_credentials"
}
