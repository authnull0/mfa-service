package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	services "github.com/authnull0/mfa-service/service"
	util "github.com/authnull0/mfa-service/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type SMSHandler struct {
	Service *services.SMSService
}

func NewSMSHandler() *SMSHandler {
	return &SMSHandler{
		Service: services.NewSMSService(),
	}
}

// @Summary      Begin SMS Setup
// @Description  Start SMS MFA setup process
// @Tags         SMS
// @Accept       json
// @Produce      json
// @Param        request body dto.SMSSetupRequest true "SMS setup information"
// @Success      200 {object} dto.SMSSetupResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /sms/beginSetup [post]
// BeginSMSSetup initiates SMS MFA setup
func (h *SMSHandler) BeginSMSSetup(c *gin.Context) {
	var req dto.SMSSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("Starting SMS setup for email: %s, phone: %s", req.Email, req.PhoneNumber)

	// Validate phone number
	if !h.Service.ValidatePhoneNumber(req.PhoneNumber) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid phone number format (use +1234567890)"})
		return
	}

	// Get client from database
	tenantDB, client, err := fetchClientForMFA(req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
		return
	}
	log.Default().Printf("Client found: %s", client.Email)
	// Generate verification code
	code, err := h.Service.GenerateCode()
	if err != nil {
		log.Printf("Failed to generate SMS code: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to generate verification code"})
		return
	}

	// Send SMS
	if err := h.Service.SendCode(req.PhoneNumber, code); err != nil {
		log.Printf("Failed to send SMS: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to send SMS code"})
		return
	}

	// Store verification data temporarily (encrypt the code)
	encryptedCode, _ := util.EncryptString(code)

	smsData := map[string]interface{}{
		"phone_number":       req.PhoneNumber,
		"phone_verified":     false,
		"verification_code":  encryptedCode,
		"code_expires_at":    time.Now().Add(5 * time.Minute).UTC(),
		"setup_initiated_at": time.Now().UTC(),
		"attempts_remaining": 3,
	}
	clientId := uuid.New().String()
	// Save as disabled method until confirmation
	mfaRepo := repositories.NewMFARepository(tenantDB)
	err = mfaRepo.EnableMethodWithExpiry(clientId, "sms", smsData, false, time.Now().Add(10*time.Minute))
	if err != nil {
		log.Printf("Failed to save SMS setup data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to save SMS setup"})
		return
	}

	log.Printf("SMS verification code sent to: %s", h.Service.FormatPhoneForDisplay(req.PhoneNumber))

	response := dto.SMSSetupResponse{
		Success:           true,
		Message:           "SMS verification code sent",
		PhoneDisplay:      h.Service.FormatPhoneForDisplay(req.PhoneNumber),
		ExpiresInMinutes:  5,
		AttemptsRemaining: 3,
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Confirm SMS Setup
// @Description  Confirm SMS setup with verification code
// @Tags         SMS
// @Accept       json
// @Produce      json
// @Param        request body dto.SMSConfirmRequest true "SMS confirmation data"
// @Success      200 {object} dto.SMSConfirmResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /sms/confirmSetup [post]
// ConfirmSMSSetup verifies SMS code and enables SMS MFA
func (h *SMSHandler) ConfirmSMSSetup(c *gin.Context) {
	var req dto.SMSConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("Confirming SMS setup for email: %s", req.Email)

	// Get client and SMS method data
	tenantDB, client, err := fetchClientForMFA(req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	method, err := mfaRepo.GetMethod(1, "sms")
	if err != nil {
		log.Printf("SMS setup not found: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "SMS setup not initiated"})
		return
	}

	// Parse SMS data
	var smsData struct {
		PhoneNumber       string    `json:"phone_number"`
		PhoneVerified     bool      `json:"phone_verified"`
		VerificationCode  string    `json:"verification_code"`
		CodeExpiresAt     time.Time `json:"code_expires_at"`
		AttemptsRemaining int       `json:"attempts_remaining"`
	}

	if err := json.Unmarshal(method.MethodData, &smsData); err != nil {
		log.Printf("Failed to parse SMS data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "invalid SMS setup data"})
		return
	}

	// Check if code expired
	if time.Now().After(smsData.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "verification code expired"})
		return
	}

	// Check attempts remaining
	if smsData.AttemptsRemaining <= 0 {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "too many verification attempts"})
		return
	}

	// Decrypt and verify code
	storedCode, err := util.DecryptString(smsData.VerificationCode)
	if err != nil {
		log.Printf("Failed to decrypt verification code: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "verification failed"})
		return
	}

	if req.Code != storedCode {
		// Decrement attempts
		smsData.AttemptsRemaining--
		updatedData, _ := json.Marshal(smsData)
		mfaRepo.UpdateMethodData(client.ID, "sms", updatedData)

		c.JSON(http.StatusBadRequest, gin.H{
			"error":              "invalid verification code",
			"attempts_remaining": smsData.AttemptsRemaining,
		})
		return
	}

	// Code is valid - enable SMS method
	confirmedSMSData := map[string]interface{}{
		"phone_number":   smsData.PhoneNumber,
		"phone_verified": true,
		"confirmed_at":   time.Now().UTC(),
		"country_code":   smsData.PhoneNumber[:3], // Extract country code
	}

	err = mfaRepo.EnableMethod(client.ID, "sms", confirmedSMSData)
	if err != nil {
		log.Printf("Failed to enable SMS method: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to enable SMS MFA"})
		return
	}

	// Update client MFA settings
	updates := map[string]interface{}{
		"mfa_enabled": true,
		"updated_at":  time.Now(),
	}

	if client.MFADefaultMethod == "" {
		updates["mfa_default_method"] = "sms"
	}

	// Add SMS to MFA methods array
	newMethods := client.MFAMethod
	if !contains(newMethods, "sms") {
		newMethods = append(newMethods, "sms")
		updates["mfa_method"] = newMethods
	}

	if err := tenantDB.Model(&client).Updates(updates).Error; err != nil {
		log.Printf("Failed to update client MFA settings: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to update MFA settings"})
		return
	}

	log.Printf("SMS MFA enabled for: %s", req.Email)

	response := dto.SMSConfirmResponse{
		Success:      true,
		Message:      "SMS MFA enabled successfully",
		PhoneDisplay: h.Service.FormatPhoneForDisplay(smsData.PhoneNumber),
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Request SMS Code
// @Description  Request SMS code for authentication
// @Tags         SMS
// @Accept       json
// @Produce      json
// @Param        request body dto.RequestSMSCodeRequest true "SMS code request"
// @Success      200 {object} dto.SMSCodeResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /sms/requestCode [post]
// RequestSMSCode sends a new SMS code for authentication
func (h *SMSHandler) RequestSMSCode(c *gin.Context) {
	var req dto.RequestSMSCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	// Get client and SMS method
	tenantDB, client, err := fetchClientForMFA(req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	method, err := mfaRepo.GetMethod(1, "sms")
	if err != nil || !method.Enabled {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "SMS MFA not enabled"})
		return
	}

	// Parse existing SMS data
	var smsData map[string]interface{}
	json.Unmarshal(method.MethodData, &smsData)

	phoneNumber := smsData["phone_number"].(string)

	// Generate new code
	code, _ := h.Service.GenerateCode()
	encryptedCode, _ := util.EncryptString(code)

	// Send SMS
	if err := h.Service.SendCode(phoneNumber, code); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to send SMS"})
		return
	}

	// Update method data with new code
	smsData["verification_code"] = encryptedCode
	smsData["code_expires_at"] = time.Now().Add(5 * time.Minute).UTC()
	smsData["attempts_remaining"] = 3

	updatedData, _ := json.Marshal(smsData)
	mfaRepo.UpdateMethodData(client.ID, "sms", updatedData)

	response := dto.SMSCodeResponse{
		Success:           true,
		Message:           "SMS code sent",
		PhoneDisplay:      h.Service.FormatPhoneForDisplay(phoneNumber),
		ExpiresInMinutes:  5,
		AttemptsRemaining: 3,
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Verify SMS Code
// @Description  Verify SMS code for authentication
// @Tags         SMS
// @Accept       json
// @Produce      json
// @Param        request body dto.VerifySMSRequest true "SMS verification data"
// @Success      200 {object} dto.AuthenticationResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      401 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /sms/verify [post]
// VerifySMS validates SMS code for authentication
func (h *SMSHandler) VerifySMS(c *gin.Context) {
	var req dto.VerifySMSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("Verifying SMS code for email: %s", req.Email)

	// Get client and SMS method
	tenantDB, client, err := fetchClientForMFA(req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "client not found"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	method, err := mfaRepo.GetMethod(1, "sms")
	if err != nil || !method.Enabled {
		log.Printf("SMS not enabled for client: %s", req.Email)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "SMS MFA not enabled for this account"})
		return
	}

	// For authentication, we need to check if this is a recent code
	// In production, you'd store authentication codes separately from setup codes
	var smsData struct {
		PhoneNumber       string    `json:"phone_number"`
		VerificationCode  string    `json:"verification_code,omitempty"`
		CodeExpiresAt     time.Time `json:"code_expires_at,omitempty"`
		AttemptsRemaining int       `json:"attempts_remaining,omitempty"`
	}

	if err := json.Unmarshal(method.MethodData, &smsData); err != nil {
		log.Printf("Failed to parse SMS data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "invalid SMS configuration"})
		return
	}

	// Check if there's a pending verification code
	if smsData.VerificationCode == "" {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "no SMS code requested. Please request a new code."})
		return
	}

	// Verify the code (similar logic as confirm setup)
	if time.Now().After(smsData.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "SMS code expired"})
		return
	}

	storedCode, err := util.DecryptString(smsData.VerificationCode)
	if err != nil || req.Code != storedCode {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid SMS code"})
		return
	}

	// Update last used timestamp
	mfaRepo.UpdateLastUsed(1, "sms")

	log.Printf("SMS code verified for: %s", req.Email)

	response := dto.AuthenticationResponse{
		Success: true,
		Message: "SMS code valid",
		Method:  "sms",
		UserID:  0,
		Email:   client.Email,
	}

	c.JSON(http.StatusOK, response)
}
