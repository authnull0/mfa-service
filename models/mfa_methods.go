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

type AdMfaProviderConfig struct {
	OrgId     int       `gorm:"primaryKey;column:org_id"`
	Provider  string    `gorm:"column:provider"`
	Config    string    `gorm:"column:config"` // AES-GCM encrypted JSON
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (AdMfaProviderConfig) TableName() string {
	return "did.ad_mfa_provider_config"
}
