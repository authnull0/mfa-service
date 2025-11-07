package repositories

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authnull0/mfa-service/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type MFARepository struct {
	DB *gorm.DB
}

func NewMFARepository(db *gorm.DB) *MFARepository {
	return &MFARepository{DB: db}
}

// To add entry in user_mfa_config
func (r *MFARepository) AddUserMFAConfig(cfg *models.UserMFAConfig) error {
	//var existing models.UserMFAConfig

	// // Check for duplicates
	// err := r.DB.
	// 	Where("user_id = ? AND tenant_id = ? AND mfa_type = ? and status = Active", cfg.UserID, cfg.TenantID, cfg.MFAType).
	// 	First(&existing).Error

	// if err == nil {
	// 	// Already exists
	// 	log.Default().Printf("MFA config already exists for user_id=%d, tenant_id=%d, mfa_type=%d", cfg.UserID, cfg.TenantID, cfg.MFAType)
	// 	return nil
	// }

	// Not found proceed to create
	return r.DB.Create(cfg).Error
}

// EnableMethod creates or updates an MFA method for a client
func (r *MFARepository) EnableMethod(clientID string, methodType string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	now := time.Now()

	return r.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "client_id"}, {Name: "method_type"}},
		DoUpdates: clause.AssignmentColumns([]string{"method_data", "enabled", "verified", "enrolled_at", "updated_at"}),
	}).Create(&models.MFAMethod{
		ClientID:   clientID,
		MethodType: methodType,
		MethodData: jsonData,
		Enabled:    true,
		Verified:   true,
		EnrolledAt: &now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error
}

// GetUserMethods returns all enabled MFA methods for a client
func (r *MFARepository) GetUserMethods(clientID string) ([]models.MFAMethod, error) {
	var methods []models.MFAMethod
	err := r.DB.Where("client_id = ? AND enabled = true", clientID).Find(&methods).Error
	return methods, err
}

// GetMethod returns a specific MFA method for a client
func (r *MFARepository) GetMethod(userId int, methodType string) (*models.MFAMethod, error) {
	var method models.MFAMethod
	err := r.DB.Where("user_id = ? AND method_type = ?", userId, methodType).Order("updated_at DESC").Find(&method).Error
	return &method, err
}

// UpdateLastUsed updates the last_used_at timestamp for a method
func (r *MFARepository) UpdateLastUsed(userID int, methodType string) error {
	return r.DB.Model(&models.MFAMethod{}).
		Where("user_id = ? AND method_type = ?", userID, methodType).
		Update("last_used_at", time.Now()).Error
}

// DisableMethod disables an MFA method
func (r *MFARepository) DisableMethod(clientID string, methodType string) error {
	return r.DB.Model(&models.MFAMethod{}).
		Where("client_id = ? AND method_type = ?", clientID, methodType).
		Updates(map[string]interface{}{
			"enabled":    false,
			"updated_at": time.Now(),
		}).Error
}

// HasMethod checks if a client has a specific MFA method enabled
func (r *MFARepository) HasMethod(clientID string, methodType string) (bool, error) {
	var count int64
	err := r.DB.Model(&models.MFAMethod{}).
		Where("client_id = ? AND method_type = ? AND enabled = true", clientID, methodType).
		Count(&count).Error
	return count > 0, err
}

// EnableMethodWithBackupCodes creates an MFA method with backup codes
func (r *MFARepository) EnableMethodWithBackupCodes(userId int, methodType string, data interface{}, backupCodes pq.StringArray) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	now := time.Now()

	return r.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "method_type"}},
		DoUpdates: clause.AssignmentColumns([]string{"method_data", "backup_codes", "enabled", "verified", "enrolled_at", "updated_at"}),
	}).Create(&models.MFAMethod{
		ClientID:    uuid.New().String(),
		UserID:      userId,
		MethodType:  methodType,
		MethodData:  jsonData,
		BackupCodes: backupCodes,
		Enabled:     true,
		Verified:    true,
		EnrolledAt:  &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}).Error
}

// UpdateBackupCodes updates the backup codes for a method
func (r *MFARepository) UpdateBackupCodes(clientID, methodType string, backupCodes pq.StringArray) error {
	return r.DB.Model(&models.MFAMethod{}).
		Where("client_id = ? AND method_type = ?", clientID, methodType).
		Updates(map[string]interface{}{
			"backup_codes": backupCodes,
			"last_used_at": time.Now(),
			"updated_at":   time.Now(),
		}).Error
}

// EnableMethodWithExpiry creates an MFA method with expiration
func (r *MFARepository) EnableMethodWithExpiry(clientID string, methodType string, data interface{}, enabled bool, expiresAt time.Time) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	now := time.Now()

	return r.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "client_id"}, {Name: "method_type"}},
		DoUpdates: clause.AssignmentColumns([]string{"method_data", "enabled", "expires_at", "updated_at"}),
	}).Create(&models.MFAMethod{
		ClientID:   clientID,
		MethodType: methodType,
		MethodData: jsonData,
		Enabled:    enabled,
		ExpiresAt:  &expiresAt,
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error
}

// UpdateMethodData updates only the method_data field
func (r *MFARepository) UpdateMethodData(clientID, methodType string, data []byte) error {
	return r.DB.Model(&models.MFAMethod{}).
		Where("client_id = ? AND method_type = ?", clientID, methodType).
		Update("method_data", data).Error
}

// func (r *MFARepository) GetUserMFAMethods(domainID string) ([]models.MFAConfig, error) {
// 	var methods []models.MFAConfig
// 	err := r.DB.Where("tenant_id = ? and status= 'Active'", domainID).Find(&methods).Error
// 	return methods, err
// }

func (r *MFARepository) GetUserMFAMethods(domainID string) ([]models.MFAConfig, error) {
	var tenantConfigs []models.TenantMfaConfig
	if err := r.DB.Where("tenant_id = ?", domainID).Find(&tenantConfigs).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch tenant MFA config: %w", err)
	}

	// Collect all factor IDs
	factorIDs := make([]int, 0, len(tenantConfigs))
	orderMap := make(map[int]int) // factor_id → factor_order
	for _, cfg := range tenantConfigs {
		factorIDs = append(factorIDs, cfg.FactorId)
		orderMap[cfg.FactorId] = cfg.FactorOrder
	}

	// Now fetch from MFA config table where status = Active and ID in factorIDs
	var methods []models.MFAConfig
	if err := r.DB.Where("id IN ? AND status = ?", factorIDs, "Active").Find(&methods).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch MFA config: %w", err)
	}

	// Optional: sort methods by factor order (using the map)
	sort.SliceStable(methods, func(i, j int) bool {
		return orderMap[methods[i].Id] < orderMap[methods[j].Id]
	})

	return methods, nil
}

func (r *MFARepository) FindUserDetails(email string, tenantId int) models.User {

	var user models.User
	tenantIdStr := strconv.Itoa(tenantId)

	if err := r.DB.Where("email_address = ? AND domain_id = ?", email, tenantIdStr).First(&user).Error; err != nil {
		return models.User{}
	}
	return user
}

func (r *MFARepository) FindTenantId(tenantname string) models.Tenant {

	var tenant models.Tenant
	if err := r.DB.Where("LOWER(tenant_name) = ?", strings.ToLower(tenantname)).First(&tenant).Error; err != nil {
		return models.Tenant{}
	}
	return tenant
}
