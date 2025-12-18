package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authnull0/mfa-service/config"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	services "github.com/authnull0/mfa-service/service"
	util "github.com/authnull0/mfa-service/utils"
)

type TOTPHandler struct {
	Service *services.TOTPService
}

func NewTOTPHandler() *TOTPHandler {
	return &TOTPHandler{
		Service: services.NewTOTPService(),
	}
}

// @Summary      Begin TOTP Setup
// @Description  Start TOTP authenticator app setup process
// @Tags         TOTP
// @Accept       json
// @Produce      json
// @Param        request body dto.TOTPSetupRequest true "User information"
// @Success      200 {object} dto.TOTPSetupResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      404 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /totp/beginSetup [post]
// BeginTOTPSetup generates TOTP secret and QR code
func (h *TOTPHandler) BeginTOTPSetup(c *gin.Context) {
	var req dto.TOTPSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Default().Printf("Parsed orgname: %s, tenantname: %s", orgname, tenantname)
	log.Printf("Starting TOTP setup for email: %s, tenant: %s", req.Email, orgname)
	// tenantDB, err := config.ConnectTenantDB(orgname)
	// if err != nil {
	// 	log.Printf("Failed to connect to tenant database: %v", err)
	// 	c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
	// 	return
	// }
	//mfaRepo := repositories.NewMFARepository(tenantDB)
	//tenant := mfaRepo.FindTenantId(tenantname)
	// Get client from database - removed unused variables
	// _, _, err = fetchClientForMFA(req.Email, tenant.Id)
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
	// 	return
	// }

	// Generate TOTP secret
	issuer := os.Getenv("WEBAUTHN_RP_NAME")
	if issuer == "" {
		issuer = "AuthSec"
	}
	log.Default().Printf("Using issuer: %s", issuer)
	key, err := h.Service.GenerateSecret(req.Email, issuer)
	if err != nil {
		log.Printf("Failed to generate TOTP secret: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to generate secret"})
		return
	}

	// Generate QR code
	qrCode, err := h.Service.GenerateQRCode(key, 256)
	if err != nil {
		log.Printf("Failed to generate QR code: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to generate QR code"})
		return
	}

	// Return setup data (secret will be confirmed in next step)
	response := dto.TOTPSetupResponse{
		Secret:      key.Secret(),
		QRCode:      base64.StdEncoding.EncodeToString(qrCode),
		ManualEntry: key.Secret(),
		Issuer:      issuer,
		Account:     req.Email,
		OTPAuthURL:  key.String(),
	}
	c.JSON(http.StatusOK, response)
}

// @Summary      Confirm TOTP Setup
// @Description  Confirm TOTP setup with verification code
// @Tags         TOTP
// @Accept       json
// @Produce      json
// @Param        request body dto.TOTPConfirmRequest true "TOTP confirmation data"
// @Success      200 {object} dto.TOTPConfirmResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      404 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /totp/confirmSetup [post]
// ConfirmTOTPSetup validates TOTP code and enables TOTP
func (h *TOTPHandler) ConfirmTOTPSetup(c *gin.Context) {
	var req dto.TOTPConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Printf("Confirming TOTP setup for email: %s, tenant: %s", req.Email, orgname)
	tenantDB, err := config.ConnectTenantDB(orgname)
	if err != nil {
		log.Printf("Failed to connect to tenant database: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	log.Printf("Confirming TOTP setup for email: %s", req.Email)

	// Validate the TOTP code
	if !h.Service.ValidateCodeWithWindow(req.Secret, req.Code, 1) {
		log.Printf("Invalid TOTP code provided for: %s", req.Email)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid TOTP code"})
		return
	}

	// Get client from database
	// tenantDB, client, err := fetchClientForMFA(req.Email, tenant.Id)
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
	// 	return
	// }
	// log.Default().Printf("Fetched client: %s", client.Email)

	// Generate backup codes
	backupCodes, err := h.Service.GenerateBackupCodes(10)
	if err != nil {
		log.Printf("Failed to generate backup codes: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to generate backup codes"})
		return
	}

	// Encrypt secret and backup codes
	encryptedSecret, err := util.EncryptString(req.Secret)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to save TOTP data"})
		return
	}

	// Encrypt backup codes
	encryptedCodes := make(pq.StringArray, len(backupCodes))
	for i, code := range backupCodes {
		encrypted, err := util.EncryptString(code)
		if err != nil {
			log.Printf("Failed to encrypt backup code: %v", err)
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to save backup codes"})
			return
		}
		encryptedCodes[i] = encrypted
	}

	// Create TOTP method data
	totpData := map[string]interface{}{
		"secret_encrypted": encryptedSecret,
		"issuer":           os.Getenv("WEBAUTHN_RP_NAME"),
		"algorithm":        "SHA1",
		"digits":           6,
		"period":           30,
		"setup_completed":  time.Now().UTC(),
	}

	// Save to MFA methods table
	user := mfaRepo.FindUserDetails(req.Email, tenant.Id)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	err = mfaRepo.EnableMethodWithBackupCodes(user.UserId, "totp", totpData, encryptedCodes)
	if err != nil {
		log.Printf("Failed to save TOTP method: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to enable TOTP"})
		return
	}

	var mfaConfig models.MFAConfig
	if err := tenantDB.Where("name = ? AND tenant_id = ?", "TOTP", tenant.Id).First(&mfaConfig).Error; err == nil {
		log.Printf("Fetched MFA config Details for TOTP: %+v", mfaConfig)

	} else if err != gorm.ErrRecordNotFound {
		log.Printf("Database error checking existing MFA config: %v", err)
	}
	// Build UserMFAConfig record
	userMFAConfig := &models.UserMFAConfig{
		UserID:    user.UserId,
		TenantID:  tenant.Id,
		OrgID:     tenant.OrganizationId,
		AppID:     1, //Hardcoded for TOTP
		MFAType:   mfaConfig.Id,
		MFADetail: mfaConfig.Description,
		Status:    "Active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Call repository function
	if err := mfaRepo.AddUserMFAConfig(userMFAConfig); err != nil {
		log.Printf("Failed to save user MFA config: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to enable user MFA config"})
		return
	}

	// Update client MFA settings in clients table
	// updates := map[string]interface{}{
	// 	"mfa_enabled": true,
	// 	"updated_at":  time.Now(),
	// }

	// // Set as default method if no other method is set
	// if client.MFADefaultMethod == "" {
	// 	updates["mfa_default_method"] = "totp"
	// }

	// // Add TOTP to MFA methods array if not present
	// newMethods := client.MFAMethod
	// if !contains(newMethods, "totp") {
	// 	newMethods = append(newMethods, "totp")
	// 	updates["mfa_method"] = newMethods
	// }

	// if err := tenantDB.Model(&client).Updates(updates).Error; err != nil {
	// 	log.Printf("Failed to update client MFA settings: %v", err)
	// 	c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to update MFA settings"})
	// 	return
	// }

	// Format backup codes for display
	displayCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		displayCodes[i] = h.Service.FormatBackupCode(code)
	}

	log.Printf("TOTP setup completed successfully for: %s", req.Email)

	response := dto.TOTPConfirmResponse{
		Success:     true,
		Message:     "TOTP enabled successfully",
		BackupCodes: displayCodes,
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Verify TOTP Code
// @Description  Verify TOTP code for authentication
// @Tags         TOTP
// @Accept       json
// @Produce      json
// @Param        request body dto.TOTPVerifyRequest true "TOTP verification data"
// @Success      200 {object} dto.AuthenticationResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      404 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /totp/verify [post]
// VerifyTOTP validates TOTP code for authentication
func (h *TOTPHandler) VerifyTOTP(c *gin.Context) {
	var req dto.TOTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Printf("Verifying TOTP setup for email: %s, tenant: %s", req.Email, orgname)
	tenantDB, err := config.ConnectTenantDB(orgname)
	if err != nil {
		log.Printf("Failed to connect to tenant database: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	log.Printf("Verifying TOTP code for email: %s", req.Email)

	// // Get client from database
	// tenantDB, client, err := fetchClientForMFA(req.Email, tenant.Id)
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
	// 	return
	// }
	// log.Default().Printf("Fetched client: %s", client.Email)
	// Get TOTP method from MFA methods table
	user := mfaRepo.FindUserDetails(req.Email, tenant.Id)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	method, err := mfaRepo.GetMethod(user.UserId, "totp")
	if err != nil || !method.Enabled {
		log.Printf("TOTP not enabled for client: %s", req.Email)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "TOTP not enabled for this account"})
		return
	}
	log.Default().Printf("Fetched MFA method: %+v", method)
	// First, check if it's a backup code
	if len(req.Code) == 8 || len(req.Code) == 9 { // 8 chars or with dash
		if err := h.verifyBackupCode(mfaRepo, method.ClientID, req.Code, method.BackupCodes); err == nil {
			log.Printf("Backup code verified for: %s", req.Email)

			// Update MFA verified status for backup code
			h.updateMFAVerifiedStatus(tenantDB, tenant.Id)

			response := dto.AuthenticationResponse{
				Success: true,
				Message: "Backup code accepted",
				Method:  "backup_code",
				UserID:  0,
				Email:   "",
			}
			c.JSON(http.StatusOK, response)
			return
		}
	}

	// Verify regular TOTP code
	var totpData struct {
		SecretEncrypted string `json:"secret_encrypted"`
	}
	log.Default().Printf("Unmarshal TOTP method data: %s", string(method.MethodData))
	if err := json.Unmarshal(method.MethodData, &totpData); err != nil {
		log.Printf("Failed to parse TOTP method data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "invalid TOTP configuration"})
		return
	}
	log.Default().Printf("Parsed TOTP method data: %+v", totpData)
	// Decrypt secret
	secret, err := util.DecryptString(totpData.SecretEncrypted)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to verify TOTP"})
		return
	}
	log.Default().Printf("Decrypted TOTP secret for client %s", method.ClientID)
	log.Default().Printf("Secret: %s", secret)
	// Validate TOTP code
	if h.Service.ValidateCodeWithWindow(secret, req.Code, 1) {
		// Update last used timestamp
		//log.Default().Printf("Updating last used timestamp for clientID: %s", client.ID)
		mfaRepo.UpdateLastUsed(user.UserId, "totp")

		log.Printf("TOTP code verified for: %s", req.Email)

		// Update MFA verified status
		//h.updateMFAVerifiedStatus(tenantDB, req.TenantID)

		response := dto.AuthenticationResponse{
			Success: true,
			Message: "TOTP code valid",
			Method:  "TOTP",
			UserID:  user.UserId,
			Email:   user.EmailAddress,
		}
		c.JSON(http.StatusOK, response)
		return
	}

	log.Printf("Invalid TOTP code for: %s", req.Email)
	c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid TOTP code"})
}

// Helper function to safely update MFA verified status
func (h *TOTPHandler) updateMFAVerifiedStatus(tenantDB *gorm.DB, tenantID int) {
	var client models.Client
	if err := tenantDB.Where("tenant_id = ?", tenantID).First(&client).Error; err != nil {
		log.Printf("Failed to find client for MFA verification update: %v", err)
		return // Don't fail the authentication for this
	}

	// Safe way to update MFAVerified
	updates := map[string]interface{}{
		"mfa_verified": true,
		"updated_at":   time.Now(),
	}

	if err := tenantDB.Model(&client).Updates(updates).Error; err != nil {
		log.Printf("Failed to update client mfa_verified status: %v", err)
		// Don't fail the authentication for this, just log the error
	} else {
		log.Printf("Successfully updated MFA verified status for tenant: %s", tenantID)
	}
}

// Helper function to verify backup codes
func (h *TOTPHandler) verifyBackupCode(mfaRepo *repositories.MFARepository, clientID, code string, encryptedCodes pq.StringArray) error {
	log.Default().Printf("Verifying backup code for clientID: %s", clientID)
	// Decrypt and check backup codes
	for i, encryptedCode := range encryptedCodes {
		decryptedCode, err := util.DecryptString(encryptedCode)
		if err != nil {
			continue
		}

		// Compare codes (case insensitive, ignore dashes)
		normalizedInput := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
		normalizedStored := strings.ToUpper(strings.ReplaceAll(decryptedCode, "-", ""))

		if normalizedInput == normalizedStored {
			// Remove used backup code
			newCodes := make(pq.StringArray, 0, len(encryptedCodes)-1)
			for j, c := range encryptedCodes {
				if j != i {
					newCodes = append(newCodes, c)
				}
			}

			// Update backup codes in database
			return mfaRepo.UpdateBackupCodes(clientID, "totp", newCodes)
		}
	}

	return fmt.Errorf("backup code not found")
}

// Helper function to fetch client (shared across TOTP handlers)
func fetchClientForMFA(email string, tenantID int) (*gorm.DB, *models.Client, error) {
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		return nil, nil, err
	}

	tenantDBName, err := config.GetTenantDBName(globalDB, tenantID)
	if err != nil {
		return nil, nil, err
	}

	tenantDB, err := config.ConnectTenantDB(tenantDBName)
	if err != nil {
		return nil, nil, err
	}

	// clientRepo := repositories.NewClientRepository(tenantDB)
	// client, err := clientRepo.GetClientByEmailAndTenant(email, tenantID)
	// if err != nil {
	// 	return nil, nil, err
	// }

	return tenantDB, &models.Client{}, nil
}
func (h *TOTPHandler) DeleteTOTP(c *gin.Context) {
	var req dto.TOTPDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("Removing TOTP Registration for email: %s", req.Email)

	// Get client from database
	tenantDB, client, err := fetchClientForMFA(req.Email, req.OrgID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
		return
	}
	log.Default().Printf("Fetched client: %s", client.Email)
	mfaRepo := repositories.NewMFARepository(tenantDB)

	user := mfaRepo.FindUserDetails(req.Email, req.TenantID)
	log.Default().Printf("Fetched User ID: %d", user.UserId)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if err = tenantDB.Model(&models.UserMFAConfig{}).Where("user_id = ? AND tenant_id = ? AND mfa_detail = ? and status = ?", user.UserId, req.TenantID, "TOTP", "Active").Update("status", "Inactive").Error; err != nil {
		log.Printf("Failed to update UserMFAConfig status: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to update UserMFAConfig status"})
		return
	}

	c.JSON(http.StatusOK, dto.SuccessResponse{Message: "TOTP method removed successfully"})
}
