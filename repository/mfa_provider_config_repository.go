package repositories

import (
	"encoding/json"
	"log"
	"time"

	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	util "github.com/authnull0/mfa-service/utils"
	"gorm.io/gorm"
)

type ProviderConfigRepository struct {
	DB *gorm.DB
}

func NewProviderConfigRepository(db *gorm.DB) *ProviderConfigRepository {
	return &ProviderConfigRepository{DB: db}
}

type providerConfigFields struct {
	// Duo
	IKey     string `json:"ikey,omitempty"`
	SKey     string `json:"skey,omitempty"`
	Host     string `json:"host,omitempty"`
	// Okta
	Domain   string `json:"domain,omitempty"`
	APIToken string `json:"api_token,omitempty"`
	// Azure AD
	TenantId     string `json:"tenant_id,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func (r *ProviderConfigRepository) Set(req dto.SetMFAProviderRequest) (*dto.SetMFAProviderResponse, error) {
	cfg := providerConfigFields{}
	switch req.Provider {
	case "duo":
		if req.IKey == "" || req.SKey == "" || req.Host == "" {
			return &dto.SetMFAProviderResponse{Message: "duo requires ikey, skey, host", Code: 400, Status: "Failure"}, nil
		}
		cfg.IKey = req.IKey
		cfg.SKey = req.SKey
		cfg.Host = req.Host
	case "okta":
		if req.Domain == "" || req.APIToken == "" {
			return &dto.SetMFAProviderResponse{Message: "okta requires domain, apiToken", Code: 400, Status: "Failure"}, nil
		}
		cfg.Domain = req.Domain
		cfg.APIToken = req.APIToken
	case "azure_ad":
		if req.TenantId == "" || req.ClientId == "" || req.ClientSecret == "" {
			return &dto.SetMFAProviderResponse{Message: "azure_ad requires tenantId, clientId, clientSecret", Code: 400, Status: "Failure"}, nil
		}
		cfg.TenantId = req.TenantId
		cfg.ClientId = req.ClientId
		cfg.ClientSecret = req.ClientSecret
	case "expo", "":
		req.Provider = "expo"
	default:
		return &dto.SetMFAProviderResponse{Message: "unsupported provider: " + req.Provider, Code: 400, Status: "Failure"}, nil
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return &dto.SetMFAProviderResponse{Message: "config error", Code: 500, Status: "Failure"}, err
	}

	encrypted, err := util.EncryptString(string(cfgJSON))
	if err != nil {
		log.Printf("set mfa provider: encrypt: %v", err)
		return &dto.SetMFAProviderResponse{Message: "encryption error", Code: 500, Status: "Failure"}, err
	}

	now := time.Now()
	row := models.AdMfaProviderConfig{
		OrgId:     req.OrgId,
		Provider:  req.Provider,
		Config:    encrypted,
		UpdatedAt: now,
		CreatedAt: now,
	}

	if err := r.DB.Where("org_id = ?", req.OrgId).
		Assign(models.AdMfaProviderConfig{Provider: req.Provider, Config: encrypted, UpdatedAt: now}).
		FirstOrCreate(&row).Error; err != nil {
		log.Printf("set mfa provider: upsert: %v", err)
		return &dto.SetMFAProviderResponse{Message: "db error", Code: 500, Status: "Failure"}, err
	}
	r.DB.Model(&row).Updates(map[string]interface{}{
		"provider":   req.Provider,
		"config":     encrypted,
		"updated_at": now,
	})

	return &dto.SetMFAProviderResponse{Message: "provider configured", Code: 200, Status: "Success"}, nil
}

func (r *ProviderConfigRepository) Get(orgId int) (*dto.GetMFAProviderResponse, error) {
	var row models.AdMfaProviderConfig
	if err := r.DB.Where("org_id = ?", orgId).First(&row).Error; err != nil {
		return &dto.GetMFAProviderResponse{
			Message: "ok", Code: 200, Status: "Success", Provider: "expo",
		}, nil
	}

	resp := &dto.GetMFAProviderResponse{
		Message:  "ok",
		Code:     200,
		Status:   "Success",
		Provider: row.Provider,
	}

	decrypted, err := util.DecryptString(row.Config)
	if err == nil {
		var cfg providerConfigFields
		if json.Unmarshal([]byte(decrypted), &cfg) == nil {
			resp.Host = cfg.Host
			resp.Domain = cfg.Domain
		}
	}

	return resp, nil
}

func (r *ProviderConfigRepository) Delete(orgId int) (*dto.DeleteMFAProviderResponse, error) {
	if err := r.DB.Where("org_id = ?", orgId).Delete(&models.AdMfaProviderConfig{}).Error; err != nil {
		log.Printf("delete mfa provider org %d: %v", orgId, err)
		return &dto.DeleteMFAProviderResponse{Message: "db error", Code: 500, Status: "Failure"}, err
	}
	return &dto.DeleteMFAProviderResponse{Message: "provider config deleted", Code: 200, Status: "Success"}, nil
}

// GetProviderConfig returns decrypted credentials — used internally by ad-service only.
func (r *ProviderConfigRepository) GetProviderConfig(orgId int) (*dto.GetProviderConfigResponse, error) {
	var row models.AdMfaProviderConfig
	if err := r.DB.Where("org_id = ?", orgId).First(&row).Error; err != nil {
		return &dto.GetProviderConfigResponse{Provider: "expo"}, nil
	}

	resp := &dto.GetProviderConfigResponse{Provider: row.Provider}

	decrypted, err := util.DecryptString(row.Config)
	if err != nil {
		log.Printf("get provider config org %d: decrypt: %v", orgId, err)
		return &dto.GetProviderConfigResponse{Provider: "expo"}, nil
	}

	var cfg providerConfigFields
	if err := json.Unmarshal([]byte(decrypted), &cfg); err == nil {
		resp.IKey         = cfg.IKey
		resp.SKey         = cfg.SKey
		resp.Host         = cfg.Host
		resp.Domain       = cfg.Domain
		resp.APIToken     = cfg.APIToken
		resp.TenantId     = cfg.TenantId
		resp.ClientId     = cfg.ClientId
		resp.ClientSecret = cfg.ClientSecret
	}

	return resp, nil
}
