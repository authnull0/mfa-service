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
