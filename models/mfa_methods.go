package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

type MFAMethod struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ClientID    string         `gorm:"not null;index" json:"client_id"`
	MethodType  string         `gorm:"size:20;not null" json:"method_type"`
	MethodData  datatypes.JSON `gorm:"type:jsonb" json:"method_data"`
	Enabled     bool           `gorm:"default:false" json:"enabled"`
	Verified    bool           `gorm:"default:false" json:"verified"`
	BackupCodes pq.StringArray `gorm:"type:text[]" json:"-"` // Hidden from JSON for security
	EnrolledAt  *time.Time     `json:"enrolled_at"`
	LastUsedAt  *time.Time     `json:"last_used_at"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	UserID      int            `gorm:"column:user_id" json:"user_id"`
}

func (MFAMethod) TableName() string {
	return "did.mfa_methods"
}

type MFAConfig struct {
	Id          int    `json:"id"`
	TenantID    int    `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Default     bool   `json:"is_default"`
}

func (MFAConfig) TableName() string {
	return "did.mfa_config"
}

type TenantMfaConfig struct {
	TenantId    int    `json:"tenant_id"`
	FactorId    int    `json:"factor_id"`
	FactorOrder int    `json:"factor_order"`
	Status      string `json:"status"`
}

func (TenantMfaConfig) TableName() string {
	return "did.tenant_mfa_config"
}

type TOTP struct {
	UserID    int    `gorm:"column:user_id" json:"user_id"`
	TenantID  int    `gorm:"column:tenant_id" json:"tenant_id"`
	OrgID     int    `gorm:"column:org_id" json:"org_id"`
	AppID     int    `gorm:"column:app_id" json:"app_id"`
	SecretEnc string `gorm:"column:secret_key" json:"secret_enc"`
	//ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	Status    string    `gorm:"column:status" json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (TOTP) TableName() string {
	return "did.totp"
}
