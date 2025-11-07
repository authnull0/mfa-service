// repositories/client_repository.go
package repositories

import (
	"log"
	"time"

	"github.com/authnull0/mfa-service/models"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type GlobalRepository struct {
	DB *gorm.DB
}

func NewGlobalRepository(db *gorm.DB) *GlobalRepository {
	return &GlobalRepository{DB: db}
}

func (r *GlobalRepository) GetTenantByID(tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := r.DB.Where("tenant_id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, err
	}
	return &tenant, nil
}

type ClientRepository struct {
	DB *gorm.DB
}

func NewClientRepository(db *gorm.DB) *ClientRepository {
	return &ClientRepository{DB: db}
}

func (r *ClientRepository) GetClientByEmail(email string) (*models.Client, error) {
	var client models.Client
	if err := r.DB.Where("email = ?", email).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

type CredentialRepository struct {
	DB *gorm.DB
}

func NewCredentialRepository(db *gorm.DB) *CredentialRepository {
	return &CredentialRepository{DB: db}
}

func (r *CredentialRepository) AddCredential(userID string, cred *webauthn.Credential) error {
	// Convert AAGUID bytes to UUID
	var aaguid *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		parsedAAGUID, err := uuid.FromBytes(cred.Authenticator.AAGUID)
		if err != nil {
			log.Printf("Warning: Invalid AAGUID format: %v", err)
			// Use nil for invalid AAGUID (database allows null)
			aaguid = nil
		} else {
			aaguid = &parsedAAGUID
		}
	}

	// Convert transports to string array
	var transports pq.StringArray
	if cred.Transport != nil {
		transports = make(pq.StringArray, len(cred.Transport))
		for i, transport := range cred.Transport {
			transports[i] = string(transport)
		}
	}

	// Generate UUID for the credential record
	credentialUUID := uuid.New()

	credential := models.Credential{
		ID:              credentialUUID,                      // Use proper UUID type
		ClientID:        userID,                              // Map userID to ClientID
		CredentialID:    cred.ID,                             // WebAuthn credential ID
		PublicKey:       cred.PublicKey,                      // Public key bytes
		AttestationType: cred.AttestationType,                // Attestation type
		AAGUID:          aaguid,                              // UUID pointer (nullable)
		SignCount:       int64(cred.Authenticator.SignCount), // Convert uint32 to int64
		Transports:      transports,                          // Transport methods
		CreatedAt:       time.Now(),                          // Creation timestamp
		UpdatedAt:       time.Now(),                          // Update timestamp
	}

	return r.DB.Create(&credential).Error
}

func (r *ClientRepository) GetClientByEmailAndTenant(email string, tenantID int) (*models.Client, error) {
	var client models.Client
	err := r.DB.Where("email = ? AND tenant_id = ?", email, tenantID).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepository) SaveCredential(credential *models.Credential) error {
	return r.DB.Create(credential).Error
}

func (r *ClientRepository) GetCredentialsByClientID(clientID string) ([]models.Credential, error) {
	var credentials []models.Credential
	err := r.DB.Where("client_id = ?", clientID).Find(&credentials).Error
	return credentials, err
}

// Update credential sign count after successful authentication
func (r *ClientRepository) UpdateCredentialSignCount(credentialID []byte, newSignCount uint32) error {
	return r.DB.Model(&models.Credential{}).
		Where("credential_id = ?", credentialID).
		Update("sign_count", int64(newSignCount)).Error
}

// Check if client has WebAuthn enabled and has credentials
func (r *ClientRepository) HasWebAuthnCredentials(clientID string) (bool, error) {
	var count int64
	err := r.DB.Model(&models.Credential{}).
		Where("client_id = ?", clientID).
		Count(&count).Error
	return count > 0, err
}

// In repositories/client_repository.go
func (r *ClientRepository) GetCredentialCountByClientID(clientID string) (int, error) {
	var count int64
	err := r.DB.Model(&models.Credential{}).Where("client_id = ?", clientID).Count(&count).Error
	return int(count), err
}
