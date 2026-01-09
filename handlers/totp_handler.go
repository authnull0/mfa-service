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
	db "github.com/authnull0/mfa-service/db"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	services "github.com/authnull0/mfa-service/service"
	util "github.com/authnull0/mfa-service/utils"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]

	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	user := mfaRepo.FindUserDetails(req.Email, tenant.Id)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Block if already enabled
	if mfaRepo.IsTOTPEnabled(user.UserId, tenant.Id) {
		c.JSON(http.StatusConflict, gin.H{"error": "TOTP already enabled"})
		return
	}

	issuer := os.Getenv("WEBAUTHN_RP_NAME")
	if issuer == "" {
		issuer = "AuthSec"
	}

	//Reuse pending secret if exists
	pending, _ := mfaRepo.GetPendingTOTP(user.UserId, tenant.Id)

	var key *otp.Key
	var err error

	if pending != nil {
		log.Default().Printf("Reusing pending TOTP for userID: %d", user.UserId)
		secret, err := util.DecryptString(pending.SecretEnc)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read TOTP secret"})
			return
		}

		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: req.Email,
			Secret:      []byte(secret),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate TOTP"})
			return
		}
	} else {
		log.Default().Printf("Generating new TOTP for userID: %d", user.UserId)
		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: req.Email,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate TOTP"})
			return
		}

		encSecret, _ := util.EncryptString(key.Secret())

		err = mfaRepo.SavePendingTOTP(&models.TOTP{
			UserID:    user.UserId,
			TenantID:  tenant.Id,
			OrgID:     tenant.OrganizationId,
			AppID:     1,
			Status:    "PENDING",
			SecretEnc: encSecret,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save pending TOTP"})
			return
		}
	}

	qrCode, err := h.Service.GenerateQRCode(key, 256)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate QR"})
		return
	}

	c.JSON(http.StatusOK, dto.TOTPSetupResponse{
		QRCode:     base64.StdEncoding.EncodeToString(qrCode),
		Issuer:     issuer,
		Account:    req.Email,
		OTPAuthURL: key.String(),
	})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]

	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	user := mfaRepo.FindUserDetails(req.Email, tenant.Id)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// 🔑 Fetch pending TOTP
	pending, err := mfaRepo.GetPendingTOTP(user.UserId, tenant.Id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no pending TOTP setup"})
		return
	}
	log.Default().Printf("Fetched pending TOTP for userID: %d", user.UserId)
	log.Default().Printf("Pending TOTP details: %+v", pending)
	// 🔍 Decrypt secret
	secret, err := util.DecryptString(pending.SecretEnc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read TOTP secret"})
		return
	}

	if !h.Service.ValidateCode(secret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired OTP"})
		return
	}

	// 🔐 Generate backup codes
	backupCodes, err := h.Service.GenerateBackupCodes(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate backup codes"})
		return
	}

	encryptedCodes := make(pq.StringArray, len(backupCodes))
	for i, code := range backupCodes {
		encryptedCodes[i], _ = util.EncryptString(code)
	}

	// 🚀 Activate TOTP
	err = mfaRepo.ActivateTOTP(user.UserId, tenant.Id, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate TOTP"})
		return
	}

	displayCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		displayCodes[i] = h.Service.FormatBackupCode(code)
	}

	c.JSON(http.StatusOK, dto.TOTPConfirmResponse{
		Success:     true,
		Message:     "TOTP enabled successfully",
		BackupCodes: displayCodes,
	})
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
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
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
	if h.Service.ValidateCode(secret, req.Code) {
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
		log.Printf("Successfully updated MFA verified status for tenant: %d", tenantID)
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
	log.Default().Printf("Delete totp request : %v", req)
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("Removing TOTP Registration for email: %s", req.Email)

	orgname, err := util.GetOrganizationDatabaseName(req.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to get organization database name"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	// // Get client from database
	// tenantDB, client, err := fetchClientForMFA(req.Email, req.OrgID)
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
	// 	return
	// }
	// log.Default().Printf("Fetched client: %s", client.Email)
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
