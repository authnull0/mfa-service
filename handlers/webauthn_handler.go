package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/authnull0/mfa-service/config"
	"github.com/authnull0/mfa-service/db"
	session "github.com/authnull0/mfa-service/internal"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

var (
	registrationChallenges = make(map[string][]byte)
	registrationMutex      sync.Mutex
)

var (
	authenticationChallenges = make(map[string][]byte)
	authenticationMutex      sync.Mutex
)

type WebAuthnHandler struct {
	WebAuthn       *webauthn.WebAuthn
	SessionManager *session.SessionManager
}

// @Summary      Begin Registration (MFA Method Discovery)
// @Description  Get available MFA methods for a user
// @Tags         WebAuthn
// @Accept       json
// @Produce      json
// @Param        request body dto.BeginRegistrationRequest true "User information"
// @Success      200 {object} dto.MFAMethodsResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      404 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /beginRegistration [post]
func (h *WebAuthnHandler) BeginRegistration(c *gin.Context) {
	var req dto.BeginRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// 1-3. Database connections (keep existing code)
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect global DB"})
		return
	}

	tenantDBName, err := config.GetTenantDBName(globalDB, req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	tenantDB, err := config.ConnectTenantDB(tenantDBName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}

	// 4-5. User lookup and ClientID generation (keep existing code)
	var user models.Client
	err = tenantDB.Where("email = ? AND tenant_id = ?", req.Email, req.TenantID).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if user.ClientID == "" {
		user.ClientID = uuid.New().String()
		if err := tenantDB.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update user ClientID"})
			return
		}
	}

	// NEW: Check existing MFA methods
	mfaRepo := repositories.NewMFARepository(tenantDB)
	existingMethods, _ := mfaRepo.GetUserMethods(user.ID)

	// NEW: Determine available MFA methods
	availableMethods := []dto.MFAMethod{
		{
			Type:        "webauthn",
			DisplayName: "Biometric/Passkey Authentication",
			Description: "Use your device's biometric or security key",
			Recommended: true,
			Enabled:     hasMethod(existingMethods, "webauthn"),
		},
		{
			Type:        "totp",
			DisplayName: "Authenticator App (TOTP)",
			Description: "Use Google Authenticator, Authy, or similar apps",
			Recommended: false,
			Enabled:     hasMethod(existingMethods, "totp"),
		},
		{
			Type:        "sms",
			DisplayName: "SMS Text Message",
			Description: "Receive verification codes via text message",
			Recommended: false,
			Enabled:     hasMethod(existingMethods, "sms"),
		},
	}

	response := dto.MFAMethodsResponse{
		AvailableMFAMethods: availableMethods,
		UserID:              user.ID,
		Email:               user.Email,
		ExistingMethods:     len(existingMethods),
		Message:             "Select an MFA method to register",
	}

	c.JSON(http.StatusOK, response)
}

// Helper function
func hasMethod(methods []models.MFAMethod, methodType string) bool {
	for _, method := range methods {
		if method.MethodType == methodType && method.Enabled {
			return true
		}
	}
	return false
}

// @Summary      Begin WebAuthn Registration
// @Description  Start WebAuthn credential registration process
// @Tags         WebAuthn
// @Accept       json
// @Produce      json
// @Param        request body dto.BeginRegistrationRequest true "User information"
// @Success      200 {object} dto.WebAuthnOptionsResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /beginAuthRegistration [post]

func (h *WebAuthnHandler) BeginWebAuthnRegistration(c *gin.Context) {
	var req dto.BeginWebAuthnRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// 1-5. Database connections and user lookup (copy from existing function)
	// ... (same database connection and user lookup code)
	// 1-3. Database connections (keep existing code)
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect global DB"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Printf("Start Passkey setup for email: %s, tenant: %s", req.Email, orgname)
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	tenantDBName, err := config.GetTenantDBName(globalDB, tenant.Id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	tenantDB, err = config.ConnectTenantDB(tenantDBName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}

	// 4-5. User lookup and ClientID generation (keep existing code)
	//var user models.User
	var webAuthnUser models.WebAuthnUser
	clientRepo := repositories.NewClientRepository(tenantDB)
	client, err := clientRepo.GetClientByEmailAndTenant(req.Email, tenant.Id)
	if err != nil {
		log.Printf("Client not found: %v", err)
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error: "client not found",
		})
		return
	}
	log.Default().Printf("Fetched User Details : %v", client)
	webAuthnUser.ID = client.UserId
	webAuthnUser.Email = client.EmailAddress
	log.Default().Printf("Populated WebAuthn : %v", webAuthnUser)

	// if user.ClientID == "" {
	// 	user.ClientID = uuid.New().String()
	// 	if err := tenantDB.Save(&user).Error; err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update user ClientID"})
	// 		return
	// 	}
	// }
	// 6. Begin WebAuthn registration
	options, sessionData, err := h.WebAuthn.BeginRegistration(&webAuthnUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to begin registration: " + err.Error(),
		})
		return
	}

	// Save session (your existing code)
	challengeKey := fmt.Sprintf("%s:%s", strconv.Itoa(tenant.Id), req.Email)
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to encode session",
		})
		return
	}
	registrationMutex.Lock()
	registrationChallenges[challengeKey] = sessionBytes
	registrationMutex.Unlock()

	c.JSON(http.StatusOK, options)
}

// @Summary      Finish WebAuthn Registration
// @Description  Complete WebAuthn credential registration
// @Tags         WebAuthn
// @Accept       json
// @Produce      json
// @Param        request body dto.FinishRegistrationRequest true "Registration completion data"
// @Success      200 {object} dto.RegistrationSuccessResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /finishRegistration [post]
func (h *WebAuthnHandler) FinishRegistration(c *gin.Context) {
	log.Println("Starting finish registration...")

	// Parse the request body
	var reqBody dto.FinishRegistrationRequest
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "invalid request: " + err.Error(),
		})
		return
	}

	//log.Printf("Processing registration for email: %s, tenant: %d", reqBody.Email, reqBody.TenantID)

	// 1-3. Database connections (your existing code)
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		log.Printf("Failed to connect to global DB: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to connect global DB",
		})
		return
	}
	orgname := strings.Split(reqBody.Url, ".")[1]
	tenantname := strings.Split(reqBody.Url, ".")[0]
	log.Printf("Finish Registeration Passkey setup for email: %s, tenant: %s", reqBody.Email, orgname)
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	tenantDBName, err := config.GetTenantDBName(globalDB, tenant.Id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	tenantDB, err = config.ConnectTenantDB(tenantDBName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}

	clientRepo := repositories.NewClientRepository(tenantDB)
	client, err := clientRepo.GetClientByEmailAndTenant(reqBody.Email, tenant.Id)
	if err != nil {
		log.Printf("Client not found: %v", err)
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error: "client not found",
		})
		return
	}
	log.Default().Printf("Fetched User Details : %v", client)
	var webAuthnUser models.WebAuthnUser
	webAuthnUser.ID = client.UserId
	webAuthnUser.Email = client.EmailAddress

	// 4. Load existing credentials and set them on the client
	existingCredentials, _ := clientRepo.GetCredentialsByClientID(strconv.Itoa(webAuthnUser.ID))
	webauthnCreds := make([]webauthn.Credential, len(existingCredentials))
	for i, cred := range existingCredentials {
		var aaguidBytes []byte
		if cred.AAGUID != nil {
			aaguidBytes = (*cred.AAGUID)[:]
		}

		webauthnCreds[i] = webauthn.Credential{
			ID:              cred.CredentialID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguidBytes,
				SignCount: uint32(cred.SignCount),
			},
		}
	}

	// Set credentials on the client (using your existing method)
	webAuthnUser.SetCredentials(webauthnCreds)

	// 5. Retrieve and validate session
	challengeKey := fmt.Sprintf("%s:%s", strconv.Itoa(tenant.Id), reqBody.Email)
	registrationMutex.Lock()
	sessionBytes, ok := registrationChallenges[challengeKey]
	registrationMutex.Unlock()

	if !ok {
		log.Printf("No session found for key: %s", challengeKey)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "registration session not found or expired",
		})
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		log.Printf("Failed to decode session data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to decode session data",
		})
		return
	}
	log.Printf("Session Challenge: %s", sessionData.Challenge)
	log.Printf("Session UserID: %s", string(sessionData.UserID))
	log.Printf("WebAuthn UserID: %s", string(webAuthnUser.WebAuthnID()))

	// 6. Create HTTP request with raw credential data for WebAuthn library
	credentialJSON, err := json.Marshal(reqBody.Credential)
	if err != nil {
		log.Printf("Failed to marshal credential: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to process credential",
		})
		return
	}

	// Create a proper HTTP request that the WebAuthn library expects
	req, err := http.NewRequest("POST", "/webauthn/credential", bytes.NewReader(credentialJSON))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to create request",
		})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	log.Printf("Calling WebAuthn.FinishRegistration with Client as WebAuthn user...")

	// 7. Call WebAuthn library using your Client as the WebAuthn user
	credential, err := h.WebAuthn.FinishRegistration(&webAuthnUser, sessionData, req)
	if err != nil {
		log.Printf("WebAuthn registration validation failed: %v", err)
		log.Printf("Error type: %T", err)
		log.Printf("Session UserID: %s", string(sessionData.UserID))
		log.Printf("Client WebAuthnID: %s", string(webAuthnUser.WebAuthnID()))

		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "WebAuthn registration validation failed: " + err.Error(),
		})
		return
	}

	log.Printf("WebAuthn validation successful!")
	log.Printf("Credential ID: %s", hex.EncodeToString(credential.ID))

	// 8. Save credential to database
	var aaguid *uuid.UUID
	if len(credential.Authenticator.AAGUID) == 16 {
		if parsedAAGUID, err := uuid.FromBytes(credential.Authenticator.AAGUID); err == nil {
			aaguid = &parsedAAGUID
		}
	}

	var transports pq.StringArray
	if credential.Transport != nil {
		transports = make(pq.StringArray, len(credential.Transport))
		for i, transport := range credential.Transport {
			transports[i] = string(transport)
		}
	}

	cred := &models.Credential{
		ID:              uuid.New(),
		ClientID:        strconv.Itoa(client.UserId),
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          aaguid,
		SignCount:       int64(credential.Authenticator.SignCount),
		Transports:      transports,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := clientRepo.SaveCredential(cred); err != nil {
		log.Printf("Failed to save credential: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error: "failed to save credential",
		})
		return
	}

	log.Printf("Credential saved to database")

	// 9. Update MFA records
	credentialCount, _ := clientRepo.GetCredentialCountByClientID(strconv.Itoa(client.UserId))

	webauthnData := map[string]interface{}{
		"credential_count":       credentialCount,
		"platform_authenticator": true,
		"attestation_type":       credential.AttestationType,
		"aaguid":                 hex.EncodeToString(credential.Authenticator.AAGUID),
		"latest_credential_id":   hex.EncodeToString(credential.ID),
	}

	if err := mfaRepo.EnableMethod(strconv.Itoa(client.UserId), "webauthn", webauthnData); err != nil {
		log.Printf("Warning: Failed to create MFA method record: %v", err)
	}

	// 10. Update client MFA configuration
	//now := time.Now().UTC()
	// updates := map[string]interface{}{
	// 	"mfa_enabled": true,
	// 	"updated_at":  now,
	// }

	// // Fix for MFAEnrolledAt - since it's time.Time (not pointer), use IsZero()
	// if webAuthnUser.MFAEnrolledAt.IsZero() {
	// 	updates["mfa_enrolled_at"] = now
	// }

	// if client.MFADefaultMethod == "" {
	// 	updates["mfa_default_method"] = "webauthn"
	// }

	// newMethods := client.MFAMethod
	// if !contains(newMethods, "webauthn") {
	// 	newMethods = append(newMethods, "webauthn")
	// 	updates["mfa_method"] = newMethods
	// }

	// if err := tenantDB.Model(&client).Updates(updates).Error; err != nil {
	// 	log.Printf("Failed to update client MFA config: %v", err)
	// 	c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
	// 		Error: "failed to update MFA config",
	// 	})
	// 	return
	// }

	// 11. Cleanup and respond
	registrationMutex.Lock()
	delete(registrationChallenges, challengeKey)
	registrationMutex.Unlock()

	log.Printf("Registration completed successfully for %s", reqBody.Email)
	log.Default().Printf("Updating user MFA Config table...")
	var mfaConfig models.MFAConfig
	if err := tenantDB.Where("name = ? AND tenant_id = ?", "Passkey", tenant.Id).First(&mfaConfig).Error; err == nil {
		log.Printf("Fetched MFA config Details for TOTP: %+v", mfaConfig)

	} else if err != gorm.ErrRecordNotFound {
		log.Printf("Database error checking existing MFA config: %v", err)
	}
	// Build UserMFAConfig record
	userMFAConfig := &models.UserMFAConfig{
		UserID:    client.UserId,
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

	response := dto.RegistrationResponse{
		Success:      true,
		Message:      "WebAuthn registration successful",
		CredentialID: hex.EncodeToString(credential.ID),
	}

	c.JSON(http.StatusOK, response)
}

// Helper function to check if slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// @Summary      Begin WebAuthn Authentication
// @Description  Start WebAuthn authentication process
// @Tags         WebAuthn
// @Accept       json
// @Produce      json
// @Param        request body dto.BeginAuthenticationRequest true "User information"
// @Success      200 {object} dto.WebAuthnOptionsResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      404 {object} dto.ErrorResponse
// @Router       /beginAuthentication [post]
// In handlers/webauthn_handler.go
func (h *WebAuthnHandler) BeginAuthentication(c *gin.Context) {
	log.Println("Starting WebAuthn authentication...")

	var req struct {
		Email string `json:"email" binding:"required"`
		//TenantID int    `json:"tenantId" binding:"required"`
		Url string `json:"url" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	log.Printf("Authentication request for email: %s, tenant: %s", req.Email)

	// Connect to global DB to get tenant DB name
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		log.Printf("Failed to connect to global DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database connection failed"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Printf("Begin autentictaion asskey setup for email: %s, tenant: %s", req.Email, orgname)
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	tenantDBName, err := config.GetTenantDBName(globalDB, tenant.Id)
	if err != nil {
		log.Printf("Invalid tenant ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	// Connect to tenant DB
	tenantDB, err = config.ConnectTenantDB(tenantDBName)
	if err != nil {
		log.Printf("Failed to connect to tenant DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant database connection failed"})
		return
	}

	// Get client
	clientRepo := repositories.NewClientRepository(tenantDB)
	client, err := clientRepo.GetClientByEmailAndTenant(req.Email, tenant.Id)
	if err != nil {
		log.Printf("Client not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}

	// Check if client has MFA enabled
	// if !client.MFAEnabled {
	// 	log.Printf("MFA not enabled for client: %s", client.Email)
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "MFA not enabled for this account"})
	// 	return
	// }

	// FIXED: Load actual credentials instead of just checking count
	dbCredentials, err := clientRepo.GetCredentialsByClientID(strconv.Itoa(client.UserId))
	if err != nil {
		log.Printf("Error loading credentials: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load credentials"})
		return
	}

	if len(dbCredentials) == 0 {
		log.Printf("No WebAuthn credentials found for client: %s", client.EmailAddress)
		c.JSON(http.StatusBadRequest, gin.H{"error": "no WebAuthn credentials registered"})
		return
	}

	log.Printf("Found %d credentials in database for client: %s", len(dbCredentials), client.EmailAddress)

	// Convert database credentials to WebAuthn credentials
	webAuthnCredentials := make([]webauthn.Credential, len(dbCredentials))
	for i, dbCred := range dbCredentials {
		var aaguid []byte
		if dbCred.AAGUID != nil {
			// Convert UUID to [16]byte
			aaguidBytes := (*dbCred.AAGUID)[:]
			copy(aaguid[:], aaguidBytes)
		}

		// Convert transports if they exist
		var transports []protocol.AuthenticatorTransport
		for _, transport := range dbCred.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(transport))
		}

		webAuthnCredentials[i] = webauthn.Credential{
			ID:              dbCred.CredentialID,
			PublicKey:       dbCred.PublicKey,
			AttestationType: dbCred.AttestationType,
			Transport:       transports,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: uint32(dbCred.SignCount),
			},
		}
	}
	var webAuthnUser models.WebAuthnUser
	webAuthnUser.ID = client.UserId
	webAuthnUser.Email = client.EmailAddress
	// CRITICAL: Set credentials in client BEFORE calling BeginLogin
	webAuthnUser.SetCredentials(webAuthnCredentials) // We need to add this method

	log.Printf("Loaded and set %d WebAuthn credentials for client: %s", len(webAuthnCredentials), client.EmailAddress)

	// Now BeginLogin should find the credentials
	assertion, sessionData, err := h.WebAuthn.BeginLogin(&webAuthnUser)
	if err != nil {
		log.Printf("Failed to begin WebAuthn authentication: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to begin authentication: " + err.Error()})
		return
	}

	// Store session data for later verification
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		log.Printf("Failed to marshal session data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session data error"})
		return
	}

	challengeKey := fmt.Sprintf("%d:%s:auth", tenant.Id, req.Email)
	authenticationMutex.Lock()
	authenticationChallenges[challengeKey] = sessionBytes
	authenticationMutex.Unlock()

	log.Printf(" Authentication challenge created for: %s", req.Email)

	// Return the assertion to client
	response := dto.WebAuthnOptionsResponse{
		PublicKey: assertion,
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Finish WebAuthn Authentication
// @Description  Complete WebAuthn authentication
// @Tags         WebAuthn
// @Accept       json
// @Produce      json
// @Param        request body dto.FinishAuthenticationRequest true "Authentication completion data"
// @Success      200 {object} dto.AuthenticationSuccessResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      401 {object} dto.ErrorResponse
// @Router       /finishAuthentication [post]
func (h *WebAuthnHandler) FinishAuthentication(c *gin.Context) {
	log.Println("Starting WebAuthn authentication verification...")

	var req struct {
		Email string `json:"email" binding:"required"`
		//TenantID   int             `json:"tenantId" binding:"required"`
		Url        string          `json:"url" binding:"required"`
		Credential json.RawMessage `json:"credential" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	log.Printf("Authentication verification for email: %s", req.Email)

	// Connect to global DB to get tenant DB name
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		log.Printf("Failed to connect to global DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database connection failed"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Printf("Finish Registeration Passkey setup for email: %s, tenant: %s", req.Email, orgname)
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)
	tenantDBName, err := config.GetTenantDBName(globalDB, tenant.Id)
	if err != nil {
		log.Printf("Invalid tenant ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	// Connect to tenant DB
	tenantDB, err = config.ConnectTenantDB(tenantDBName)
	if err != nil {
		log.Printf("Failed to connect to tenant DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant database connection failed"})
		return
	}

	// Get client
	clientRepo := repositories.NewClientRepository(tenantDB)
	client, err := clientRepo.GetClientByEmailAndTenant(req.Email, tenant.Id)
	if err != nil {
		log.Printf("Client not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}

	// Load credentials (same as in BeginAuthentication)
	dbCredentials, err := clientRepo.GetCredentialsByClientID(strconv.Itoa(client.UserId))
	if err != nil {
		log.Printf("Error loading credentials: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load credentials"})
		return
	}

	if len(dbCredentials) == 0 {
		log.Printf("No WebAuthn credentials found for client: %s", client.EmailAddress)
		c.JSON(http.StatusBadRequest, gin.H{"error": "no WebAuthn credentials registered"})
		return
	}

	// Convert database credentials to WebAuthn credentials
	webAuthnCredentials := make([]webauthn.Credential, len(dbCredentials))
	for i, dbCred := range dbCredentials {
		var aaguid []byte // Fixed: should be [16]byte, not []byte
		if dbCred.AAGUID != nil {
			aaguidBytes := (*dbCred.AAGUID)[:]
			copy(aaguid[:], aaguidBytes)
		}

		var transports []protocol.AuthenticatorTransport
		for _, transport := range dbCred.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(transport))
		}

		webAuthnCredentials[i] = webauthn.Credential{
			ID:              dbCred.CredentialID,
			PublicKey:       dbCred.PublicKey,
			AttestationType: dbCred.AttestationType,
			Transport:       transports,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: uint32(dbCred.SignCount),
			},
		}
	}
	var webAuthnUser models.WebAuthnUser
	webAuthnUser.ID = client.UserId
	webAuthnUser.Email = client.EmailAddress
	// Set credentials in client
	webAuthnUser.SetCredentials(webAuthnCredentials)

	log.Printf("Loaded %d credentials for authentication verification", len(webAuthnCredentials))

	// Retrieve authentication session
	challengeKey := fmt.Sprintf("%s:%s:auth", tenant.Id, req.Email)
	authenticationMutex.Lock()
	sessionBytes, ok := authenticationChallenges[challengeKey]
	authenticationMutex.Unlock()

	if !ok {
		log.Printf("No authentication session found for key: %s", challengeKey)
		c.JSON(http.StatusBadRequest, gin.H{"error": "authentication session not found or expired"})
		return
	}

	// Decode session data
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		log.Printf("Failed to decode session data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid session data"})
		return
	}

	log.Printf("Session data decoded successfully")

	// Create HTTP request with credential data for WebAuthn library
	credentialRequest, err := http.NewRequest("POST", "/finish-authentication",
		bytes.NewReader(req.Credential))
	if err != nil {
		log.Printf("Error creating credential request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process credential"})
		return
	}
	credentialRequest.Header.Set("Content-Type", "application/json")

	log.Printf("Created credential request, calling WebAuthn.FinishLogin")

	// Finish WebAuthn authentication
	credential, err := h.WebAuthn.FinishLogin(&webAuthnUser, sessionData, credentialRequest)
	if err != nil {
		log.Printf("WebAuthn authentication failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "authentication verification failed"})
		return
	}

	log.Printf("WebAuthn authentication successful for credential: %s", hex.EncodeToString(credential.ID))

	// Update credential sign count in database
	if err := clientRepo.UpdateCredentialSignCount(credential.ID, credential.Authenticator.SignCount); err != nil {
		log.Printf("Warning: Failed to update sign count: %v", err)
		// Don't fail the authentication for this, just log the warning
	} else {
		log.Printf("Updated sign count to %d for credential", credential.Authenticator.SignCount)
	}

	// NEW: Update MFA method usage tracking
	//mfaRepo := repositories.NewMFARepository(tenantDB)
	if err := mfaRepo.UpdateLastUsed(1, "webauthn"); err != nil {
		log.Printf("Warning: Failed to update MFA method usage: %v", err)
		// Don't fail authentication for this, just log the warning
	} else {
		log.Printf("Updated WebAuthn MFA method last_used_at timestamp")
	}

	// Clean up authentication session
	authenticationMutex.Lock()
	delete(authenticationChallenges, challengeKey)
	authenticationMutex.Unlock()

	// Fetch the client for this user's tenant
	var clients models.Client
	if err := tenantDB.Where("tenant_id = ?", tenant.Id).First(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find client and project"})
		return
	}
	*clients.MFAVerified = true
	if err := tenantDB.Save(&clients).Error; err != nil {
		log.Printf("Failed to update client mfa_verified status: %v", err)
	}

	log.Printf("Authentication completed successfully for user: %s", req.Email)

	// Return success response to login service
	response := dto.AuthenticationResponse{
		Success:      true,
		Method:       "webauthn",
		Message:      "Authentication successful",
		CredentialID: hex.EncodeToString(credential.ID),
		UserID:       0,
		Email:        client.EmailAddress,
	}

	c.JSON(http.StatusOK, response)
}

func (h *WebAuthnHandler) GetMFAStatus(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
		// TenantID int    `json:"tenantId" binding:"required"`
		// OrgID    int    `json:"orgId" binding:"required"`
		//Password string `json:"password" binding:"required"`
		Url string `json:"url" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	log.Printf("Getting MFA status for email: %s, Org: %s", req.Email, orgname)

	// Get client from database
	// globalDB, err := config.ConnectGlobalDB()
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect global DB"})
	// 	return
	// }

	// tenantDBName, err := config.GetTenantDBName(globalDB, orgname)
	// if err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
	// 	return
	// }

	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	//log.Default().Printf("Connected to tenant DB: %v", tenantDB)
	//clientRepo := repositories.NewClientRepository(tenantDB)
	// client, err := clientRepo.GetClientByEmailAndTenant(req.Email, req.TenantID)
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
	// 	return
	// }
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)
	user, err := h.VerifyUserPassword(req.Email, int(tenant.Id), "", orgname)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Get MFA methods

	methods, _ := mfaRepo.GetUserMFAMethods(user.DomainId)
	log.Default().Printf("Retrieved MFA methods: %v", methods)

	// Format methods for response
	configuredMethods := make([]dto.MFAConfigStatus, 0)
	log.Default().Printf("Configured MFA methods : %v", configuredMethods)

	var defaultMethodName string
	if len(methods) > 0 {
		defaultMethodName = methods[0].Name // first method is default
	}

	for _, method := range methods {
		methodStatus := dto.MFAConfigStatus{
			TenantID:    method.TenantID,
			Name:        method.Name,
			Description: method.Description,
			Status:      method.Status,
			Default:     (method.Name == defaultMethodName),
			// EnrolledAt:  method.EnrolledAt,
			// LastUsed:    method.LastUsedAt,
		}

		// Add method-specific display information
		switch method.Name {
		case "webauthn":
			//credentials, _ := clientRepo.GetCredentialsByClientID(client.ID)
			methodStatus.DisplayName = "Biometric/Passkey Authentication"
			//methodStatus.CredentialCount = len(credentials)

		case "TOTP":
			methodStatus.DisplayName = "Authenticator App (TOTP)"
			//methodStatus.HasBackupCodes = len(method.BackupCodes) > 0

		case "sms":
			methodStatus.DisplayName = "SMS Text Message"
			// Add phone number masking if needed
		}

		configuredMethods = append(configuredMethods, methodStatus)
	}

	// Count enabled methods
	//enabledCount := 0
	var mfaEnabled bool
	// for _, method := range methods {
	// 	if method.Enabled {
	// 		enabledCount++
	// 	}
	// }
	if len(configuredMethods) != 0 {
		//enabledCount = len(configuredMethods)
		mfaEnabled = true
	}

	response := dto.MFAStatusResponse{
		UserID:           user.UserId,
		Email:            user.EmailAddress,
		MFAEnabled:       mfaEnabled,
		MFADefaultMethod: defaultMethodName,
		//MFAEnrolledAt:     &client.MFAEnrolledAt,
		ConfiguredMethods: configuredMethods,
		TotalMethods:      len(configuredMethods),
		//EnabledMethods:    enabledCount,
	}

	c.JSON(http.StatusOK, response)
}

func (h *WebAuthnHandler) VerifyUser(c *gin.Context) {
	log.Default().Println("Verifying user...")
	var req dto.VerifyUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// globalDB, err := config.ConnectGlobalDB()
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect global DB"})
	// 	return
	// }

	// tenantDBName, err := config.GetTenantDBName(globalDB, req.TenantID)
	// if err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
	// 	return
	// }

	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]

	tenantDB := db.GetConnectiontoDatabaseDynamically(orgname)
	if tenantDB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect tenant DB"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)
	tenantIdStr := strconv.Itoa(int(tenant.Id))
	var user models.User
	if err := tenantDB.Where("email_address = ? AND domain_id = ?", req.UserEmail, tenantIdStr).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var configs []models.UserMFAConfig
	if err := tenantDB.Where("org_id = ? AND tenant_id = ? AND user_id = ? AND status = ?", user.OrgID, user.DomainId, user.UserId, "Active").Find(&configs).Error; err != nil {
		//c.JSON(http.StatusNotFound, gin.H{"error": "Failed to retrieve MFA config"})
		return
	}
	result := []dto.UserMfa{}
	for _, cfg := range configs {
		result = append(result, dto.UserMfa{
			MfaType:   cfg.MFAType,
			Name:      cfg.MFADetail,
			Status:    cfg.Status,
			CreatedAt: cfg.CreatedAt,
			UpdatedAt: cfg.CreatedAt,
			//Default:   cfg.IsDefault,
		})
	}

	response := dto.VerifyUserResponse{
		Code:    200,
		Status:  "success",
		Message: "User verified successfully",
		UserMfa: result,
	}

	c.JSON(http.StatusOK, response)
}

func (h *WebAuthnHandler) VerifyUserPassword(email string, tenantID int, password string, tenantDBName string) (*models.User, error) {
	// globalDB, err := config.ConnectGlobalDB()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to connect global db: %w", err)
	// }

	// tenantDBName, err := config.GetTenantDBName(globalDB, tenantID)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get tenant db name: %w", err)
	// }

	tenantDB := db.GetConnectiontoDatabaseDynamically(tenantDBName)
	if tenantDB == nil {
		return nil, fmt.Errorf("failed to connect tenant DB")
	}
	var user models.User
	tenantIDStr := strconv.Itoa(tenantID)
	if err := tenantDB.Where("email_address = ? AND domain_id = ?", email, tenantIDStr).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Compare hashed password
	// match, err := utils.ComparePasswordAndHash(password, user.Password)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to compare password: %w", err)
	// }
	// if !match {
	// 	return nil, fmt.Errorf("invalid credentials")
	// }

	return &user, nil
}
