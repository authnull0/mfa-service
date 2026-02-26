package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/authnull0/mfa-service/config"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
)

type PasskeyHandler struct {
	WebAuthn *webauthn.WebAuthn
}

func NewPasskeyHandler(wa *webauthn.WebAuthn) *PasskeyHandler {
	return &PasskeyHandler{WebAuthn: wa}
}

// ─── BEGIN SETUP ──────────────────────────────────────────────────────────────

// @Summary      Begin Passkey Setup
// @Description  Generates WebAuthn registration options. The returned session_data
//
//	must be stored by the client and echoed back in confirmSetup.
//
// @Tags         Passkey
// @Accept       json
// @Produce      json
// @Param        request body dto.PasskeySetupRequest true "Passkey setup info"
// @Success      200 {object} dto.PasskeySetupResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /mfa/passkey/beginSetup [post]
func (h *PasskeyHandler) BeginSetup(c *gin.Context) {
	var req dto.PasskeySetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("[Passkey] BeginSetup for email: %s", req.Email)

	tenantDB, client, err := fetchClientForMFA(req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}
	log.Default().Printf("Fetched Client : %v", client)
	mfaRepo := repositories.NewMFARepository(tenantDB)
	user := mfaRepo.FindUserDetails(req.Email, req.TenantID)

	waUser := newWebAuthnUser(user.UserId, user.EmailAddress)
	waUser.Credentials = loadCredentials(tenantDB, user.UserId)

	options, sessionData, err := h.WebAuthn.BeginRegistration(waUser)
	if err != nil {
		log.Printf("[Passkey] BeginRegistration error: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to begin passkey setup"})
		return
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		log.Printf("[Passkey] Failed to marshal session data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to process session data"})
		return
	}

	c.JSON(http.StatusOK, dto.PasskeySetupResponse{
		Success:     true,
		Options:     options,
		SessionData: sessionBytes,
	})
}

// ─── CONFIRM SETUP ────────────────────────────────────────────────────────────

// @Summary      Confirm Passkey Setup
// @Description  Validates the authenticator response and stores the credential
//
//	in the passkey_credentials table.
//
// @Tags         Passkey
// @Accept       json
// @Produce      json
// @Param        request body dto.PasskeyConfirmRequest true "Passkey confirmation"
// @Success      200 {object} dto.PasskeyConfirmResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /mfa/passkey/confirmSetup [post]
func (h *PasskeyHandler) ConfirmSetup(c *gin.Context) {
	var req dto.PasskeyConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("[Passkey] ConfirmSetup for email: %s", req.Email)

	tenantDB, client, err := fetchClientForMFA(req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	user := mfaRepo.FindUserDetails(req.Email, req.TenantID)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(req.SessionData, &sessionData); err != nil {
		log.Printf("[Passkey] Failed to unmarshal session data: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid session data"})
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		newJSONReader(req.Credential),
	)
	if err != nil {
		log.Printf("[Passkey] ParseCredentialCreationResponseBody error: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid credential response"})
		return
	}

	waUser := newWebAuthnUser(user.UserId, user.EmailAddress)
	credential, err := h.WebAuthn.CreateCredential(waUser, sessionData, parsedResponse)
	if err != nil {
		log.Printf("[Passkey] CreateCredential error: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "passkey registration failed: " + err.Error()})
		return
	}

	if err := savePasskeyCredential(tenantDB, user.UserId, req.TenantID, credential); err != nil {
		log.Printf("[Passkey] savePasskeyCredential error: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to save passkey"})
		return
	}

	// Mark passkey as an active MFA method via the repo.
	if err := mfaRepo.EnableMethod(client.ID, "passkey", map[string]interface{}{
		"enabled":    true,
		"updated_at": time.Now().UTC(),
	}); err != nil {
		log.Printf("[Passkey] Failed to enable passkey MFA method: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to enable passkey MFA"})
		return
	}

	log.Printf("[Passkey] Passkey registered for: %s", req.Email)

	c.JSON(http.StatusOK, dto.PasskeyConfirmResponse{
		Success: true,
		Message: "Passkey registered successfully",
	})
}

// ─── BEGIN AUTHENTICATION ─────────────────────────────────────────────────────

// @Summary      Begin Passkey Authentication
// @Description  Loads stored credentials and generates an assertion challenge.
//
//	Returns session_data to echo back in verify.
//
// @Tags         Passkey
// @Accept       json
// @Produce      json
// @Param        request body dto.PasskeyAuthRequest true "Passkey auth request"
// @Success      200 {object} dto.PasskeyAuthOptionsResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /mfa/passkey/beginAuthentication [post]
func (h *PasskeyHandler) BeginAuthentication(c *gin.Context) {
	var req dto.PasskeyAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("[Passkey] BeginAuthentication for email: %s", req.Email)

	tenantDB, err := getTenantDB(req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	user := mfaRepo.FindUserDetails(req.Email, req.TenantID)
	waUser := newWebAuthnUser(user.UserId, user.EmailAddress)
	waUser.Credentials = loadCredentials(tenantDB, user.UserId)

	if len(waUser.Credentials) == 0 {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "no passkeys registered for this account"})
		return
	}

	options, sessionData, err := h.WebAuthn.BeginLogin(waUser)
	if err != nil {
		log.Printf("[Passkey] BeginLogin error: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to begin passkey authentication"})
		return
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		log.Printf("[Passkey] Failed to marshal session data: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to process session data"})
		return
	}

	c.JSON(http.StatusOK, dto.PasskeyAuthOptionsResponse{
		Success:     true,
		Options:     options,
		SessionData: sessionBytes,
	})
}

// ─── FINISH AUTHENTICATION ────────────────────────────────────────────────────

// @Summary      Finish Passkey Authentication
// @Description  Verifies the assertion signature against the stored public key
//
//	and updates the sign count.
//
// @Tags         Passkey
// @Accept       json
// @Produce      json
// @Param        request body dto.PasskeyVerifyRequest true "Passkey verify request"
// @Success      200 {object} dto.AuthenticationResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      401 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /mfa/passkey/verify [post]
func (h *PasskeyHandler) FinishAuthentication(c *gin.Context) {
	var req dto.PasskeyVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	log.Printf("[Passkey] FinishAuthentication for email: %s", req.Email)

	tenantDB, err := getTenantDB(req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	user := mfaRepo.FindUserDetails(req.Email, req.TenantID)
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(req.SessionData, &sessionData); err != nil {
		log.Printf("[Passkey] Failed to unmarshal session data: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid session data"})
		return
	}

	waUser := newWebAuthnUser(user.UserId, user.EmailAddress)
	waUser.Credentials = loadCredentials(tenantDB, user.UserId)

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(
		newJSONReader(req.Credential),
	)
	if err != nil {
		log.Printf("[Passkey] ParseCredentialRequestResponseBody error: %v", err)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid credential response"})
		return
	}

	credential, err := h.WebAuthn.ValidateLogin(waUser, sessionData, parsedResponse)
	if err != nil {
		log.Printf("[Passkey] ValidateLogin error: %v", err)
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "passkey verification failed"})
		return
	}

	// Update sign_count — prevents replay attacks with cloned keys.
	if err := updateCredentialSignCount(tenantDB, credential); err != nil {
		log.Printf("[Passkey] Failed to update sign count: %v", err)
	}

	mfaRepo.UpdateLastUsed(user.UserId, "passkey")

	log.Printf("[Passkey] Authentication successful for: %s", req.Email)

	c.JSON(http.StatusOK, dto.AuthenticationResponse{
		Success: true,
		Message: "Passkey authentication successful",
		Method:  "passkey",
		Email:   user.EmailAddress,
	})
}

// ─── webAuthnUser ─────────────────────────────────────────────────────────────
// Simple struct — no longer wraps a Client model.

type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	Credentials []webauthn.Credential
}

// newWebAuthnUser builds the webAuthn user directly from userId and email
// strings — no client struct needed anywhere.
func newWebAuthnUser(userId int, email string) *webAuthnUser {
	return &webAuthnUser{
		id:          []byte(strconv.Itoa(userId)),
		name:        email,
		displayName: email,
	}
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// ─── Tenant DB helper ─────────────────────────────────────────────────────────
// Replicates what fetchClientForMFA did — without the client lookup.

func getTenantDB(tenantID int) (*gorm.DB, error) {
	globalDB, err := config.ConnectGlobalDB()
	if err != nil {
		return nil, err
	}
	tenantDBName, err := config.GetTenantDBName(globalDB, tenantID)
	if err != nil {
		return nil, err
	}
	return config.ConnectTenantDB(tenantDBName)
}

// ─── Credential persistence ───────────────────────────────────────────────────

// loadCredentials fetches all passkey rows for a userId and converts them
// to the []webauthn.Credential slice that go-webauthn requires.
func loadCredentials(db *gorm.DB, userId int) []webauthn.Credential {
	var rows []models.PasskeyCredential
	if err := db.Where("client_id = ?", userId).Find(&rows).Error; err != nil {
		return nil
	}

	creds := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		creds = append(creds, webauthn.Credential{
			ID:              row.CredentialID,
			PublicKey:       row.PublicKey,
			AttestationType: row.AttestationType,
			Transport:       toProtocolTransports(row.Transports),
			Flags: webauthn.CredentialFlags{
				UserVerified:   row.UserVerified,
				BackupEligible: row.BackupEligible,
				BackupState:    row.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    row.AAGUID,
				SignCount: row.SignCount,
			},
		})
	}
	return creds
}

// savePasskeyCredential inserts a new row into passkey_credentials.
// Takes userId and tenantID as plain strings — no client model involved.
func savePasskeyCredential(db *gorm.DB, userId int, tenantID int, cred *webauthn.Credential) error {
	row := models.PasskeyCredential{
		UserID:          userId,
		TenantID:        tenantID,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		Transports:      fromProtocolTransports(cred.Transport),
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
	}
	return db.Create(&row).Error
}

// updateCredentialSignCount updates sign_count and last_used_at for the
// matched credential — prevents replay attacks with cloned authenticators.
func updateCredentialSignCount(db *gorm.DB, cred *webauthn.Credential) error {
	now := time.Now()
	return db.Model(&models.PasskeyCredential{}).
		Where("credential_id = ?", cred.ID).
		Updates(map[string]interface{}{
			"sign_count":   cred.Authenticator.SignCount,
			"last_used_at": now,
			"updated_at":   now,
		}).Error
}

// ─── Transport helpers ────────────────────────────────────────────────────────

func toProtocolTransports(t []string) []protocol.AuthenticatorTransport {
	out := make([]protocol.AuthenticatorTransport, len(t))
	for i, s := range t {
		out[i] = protocol.AuthenticatorTransport(s)
	}
	return out
}

func fromProtocolTransports(t []protocol.AuthenticatorTransport) []string {
	out := make([]string, len(t))
	for i, s := range t {
		out[i] = string(s)
	}
	return out
}

// ─── Utility ──────────────────────────────────────────────────────────────────

func newJSONReader(raw json.RawMessage) io.Reader {
	return bytes.NewReader(raw)
}
