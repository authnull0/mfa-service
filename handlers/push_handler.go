package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/authnull0/mfa-service/db"
	rdb "github.com/authnull0/mfa-service/internal"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	"github.com/authnull0/mfa-service/handlers/providers"
	"github.com/authnull0/mfa-service/notifications"
	repositories "github.com/authnull0/mfa-service/repository"
	util "github.com/authnull0/mfa-service/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const pushChallengeTTL    = 90 * time.Second
const enrollmentTokenTTL  = 7 * 24 * time.Hour
const challengeKeyPrefix  = "mfa:challenge:"

var expoTokenRegex = regexp.MustCompile(`^ExponentPushToken\[.+\]$`)

// pushChallenge is used for the in-memory fallback when Redis is unavailable.
type pushChallenge struct {
	Email       string
	TenantID    int
	OrgID       int
	UserID      int
	Status      string    // "pending" | "approved" | "denied" | "expired"
	ExpiresAt   time.Time
	Provider    string    // "expo" | "duo" | "okta" | "azure_ad"
	ProviderTxid string   // provider-specific transaction/device code ID for polling
}

// fallbackChallenges is the in-memory store used only when Redis is unavailable.
var fallbackChallenges sync.Map // key: challengeID → *pushChallenge

// ── Redis challenge helpers ──────────────────────────────────────────────────

func challengeKey(id string) string { return challengeKeyPrefix + id }

// storeChallenge writes a new challenge to Redis (or in-memory fallback).
func storeChallenge(id string, ch *pushChallenge) {
	if rdb.Redis != nil {
		fields := map[string]interface{}{
			"email":         ch.Email,
			"tenant_id":     ch.TenantID,
			"org_id":        ch.OrgID,
			"user_id":       ch.UserID,
			"status":        ch.Status,
			"expires_at":    ch.ExpiresAt.UTC().Format(time.RFC3339),
			"provider":      ch.Provider,
			"provider_txid": ch.ProviderTxid,
		}
		if err := rdb.Redis.HMSet(challengeKey(id), fields).Err(); err != nil {
			log.Printf("[push] Redis HMSet failed for %s: %v — using in-memory fallback", id, err)
			fallbackChallenges.Store(id, ch)
			return
		}
		rdb.Redis.Expire(challengeKey(id), pushChallengeTTL)
		return
	}
	fallbackChallenges.Store(id, ch)
}

// loadChallenge reads a challenge from Redis (or in-memory fallback).
// Returns nil when not found or expired.
func loadChallenge(id string) *pushChallenge {
	if rdb.Redis != nil {
		vals, err := rdb.Redis.HGetAll(challengeKey(id)).Result()
		if err != nil || len(vals) == 0 {
			return nil
		}
		tenantID, _  := strconv.Atoi(vals["tenant_id"])
		orgID, _     := strconv.Atoi(vals["org_id"])
		userID, _    := strconv.Atoi(vals["user_id"])
		expiresAt, _ := time.Parse(time.RFC3339, vals["expires_at"])
		return &pushChallenge{
			Email:        vals["email"],
			TenantID:     tenantID,
			OrgID:        orgID,
			UserID:       userID,
			Status:       vals["status"],
			ExpiresAt:    expiresAt,
			Provider:     vals["provider"],
			ProviderTxid: vals["provider_txid"],
		}
	}
	val, ok := fallbackChallenges.Load(id)
	if !ok {
		return nil
	}
	return val.(*pushChallenge)
}

// updateChallengeStatus updates only the status field. When Redis is available
// this is a single HSET — no read-modify-write needed.
func updateChallengeStatus(id, status string) {
	if rdb.Redis != nil {
		rdb.Redis.HSet(challengeKey(id), "status", status)
		return
	}
	if val, ok := fallbackChallenges.Load(id); ok {
		val.(*pushChallenge).Status = status
	}
}

type PushHandler struct{}

func NewPushHandler() *PushHandler {
	return &PushHandler{}
}

// BeginSetup sends an enrollment email with a deep-link containing a one-time token.
func (h *PushHandler) BeginSetup(c *gin.Context) {
	var req dto.PushSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "org not found"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
	mfaRepo := repositories.NewMFARepository(tenantDB)

	user := mfaRepo.FindUserDetails(req.Email, req.TenantID)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "user not found"})
		return
	}

	token := randomHexToken(16)
	expiresAt := time.Now().Add(enrollmentTokenTTL)

	setupData := map[string]interface{}{
		"enrollment_token":    token,
		"token_expires_at":    expiresAt.UTC(),
		"setup_initiated_at":  time.Now().UTC(),
	}

	clientID := uuid.New().String()
	if err := mfaRepo.EnableMethodWithExpiryForUser(user.UserId, clientID, "push", setupData, false, expiresAt); err != nil {
		log.Printf("push beginSetup: save token for %s: %v", req.Email, err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to initiate setup"})
		return
	}

	deepLink := fmt.Sprintf(
		"authnull://mfa-push-enroll?token=%s&tenantId=%d&orgId=%d&email=%s",
		token, req.TenantID, req.OrgID, req.Email,
	)
	emailBody := fmt.Sprintf(`
		<p>Hi,</p>
		<p>You have been asked to set up push MFA on your AuthNull app.</p>
		<p>Tap the link below on your mobile device:</p>
		<p><a href="%s">Set up AuthNull Authenticator</a></p>
		<p>This link expires in 7 days.</p>
	`, deepLink)

	if !util.ValidateEmail(req.Email, emailBody, "Set up AuthNull Push MFA") {
		log.Printf("push beginSetup: email failed for %s (token still stored)", req.Email)
	}

	c.JSON(http.StatusOK, dto.PushSetupResponse{
		Success: true,
		Message: "Enrollment email sent",
	})
}

// ConfirmSetup validates the enrollment token and stores the Expo push token.
func (h *PushHandler) ConfirmSetup(c *gin.Context) {
	var req dto.PushConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	if !expoTokenRegex.MatchString(req.ExpoPushToken) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid expo push token format"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "org not found"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
	mfaRepo := repositories.NewMFARepository(tenantDB)

	method, err := mfaRepo.GetMethod(req.UserID, "push")
	if err != nil || method.ID == [16]byte{} {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "push setup not initiated"})
		return
	}

	var setupData struct {
		EnrollmentToken  string    `json:"enrollment_token"`
		TokenExpiresAt   time.Time `json:"token_expires_at"`
	}
	if err := json.Unmarshal(method.MethodData, &setupData); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "invalid setup data"})
		return
	}

	if time.Now().After(setupData.TokenExpiresAt) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "enrollment token expired"})
		return
	}
	if req.EnrollmentToken != setupData.EnrollmentToken {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid enrollment token"})
		return
	}

	now := time.Now().UTC()
	pushData := map[string]interface{}{
		"expo_push_token": req.ExpoPushToken,
		"platform":        req.Platform,
		"device_name":     req.DeviceName,
		"enrolled_at":     now,
	}

	if err := mfaRepo.EnableMethodWithBackupCodes(req.UserID, "push", pushData, nil); err != nil {
		log.Printf("push confirmSetup: enable method for user %d: %v", req.UserID, err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to enable push MFA"})
		return
	}

	// Update Client MFA settings
	updates := map[string]interface{}{
		"mfa_enabled": true,
		"updated_at":  now,
	}
	var client models.Client
	if err := tenantDB.Where("email = ?", req.Email).First(&client).Error; err == nil {
		if client.MFADefaultMethod == "" {
			updates["mfa_default_method"] = "push"
		}
		newMethods := client.MFAMethod
		if !contains(newMethods, "push") {
			newMethods = append(newMethods, "push")
			updates["mfa_method"] = newMethods
		}
		tenantDB.Model(&client).Updates(updates)
	}

	c.JSON(http.StatusOK, dto.PushConfirmResponse{
		Success: true,
		Message: "Push MFA enabled successfully",
	})
}

// Challenge initiates an MFA push for the user via the org's configured provider.
// Returns a challenge ID that the caller polls via Status().
//
// Provider routing:
//   expo      — Authnull Authenticator app via Expo push (default)
//   duo       — Duo Auth API v2 push
//   okta      — Okta Verify push via Factors API
//   azure_ad  — MS Authenticator via Azure AD device code flow
func (h *PushHandler) Challenge(c *gin.Context) {
	var req dto.PushChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "org not found"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)

	// Look up which provider this org uses
	providerRepo := repositories.NewProviderConfigRepository(tenantDB)
	providerCfg, _ := providerRepo.GetProviderConfig(req.OrgID)
	provider := "expo"
	if providerCfg != nil && providerCfg.Provider != "" {
		provider = providerCfg.Provider
	}

	challengeID := uuid.New().String()
	challenge := &pushChallenge{
		Email:     req.Email,
		TenantID:  req.TenantID,
		OrgID:     req.OrgID,
		UserID:    req.UserID,
		Status:    "pending",
		ExpiresAt: time.Now().Add(pushChallengeTTL),
		Provider:  provider,
	}

	switch provider {

	case "duo":
		txid, err := providers.DuoInitiate(req.Email, providers.DuoConfig{
			IKey: providerCfg.IKey,
			SKey: providerCfg.SKey,
			Host: providerCfg.Host,
		})
		if err != nil {
			log.Printf("[push] Duo initiate for %s: %v", req.Email, err)
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "duo initiate failed: " + err.Error()})
			return
		}
		challenge.ProviderTxid = txid

	case "okta":
		txid, err := providers.OktaInitiate(req.Email, providers.OktaConfig{
			Domain:   providerCfg.Domain,
			APIToken: providerCfg.APIToken,
		})
		if err != nil {
			log.Printf("[push] Okta initiate for %s: %v", req.Email, err)
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "okta initiate failed: " + err.Error()})
			return
		}
		challenge.ProviderTxid = txid

	case "azure_ad":
		deviceCode, userCode, err := providers.AzureADInitiate(req.Email, req.Email, providers.AzureADConfig{
			TenantId:     providerCfg.TenantId,
			ClientId:     providerCfg.ClientId,
			ClientSecret: providerCfg.ClientSecret,
		})
		if err != nil {
			log.Printf("[push] Azure AD initiate for %s: %v", req.Email, err)
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "azure_ad initiate failed: " + err.Error()})
			return
		}
		challenge.ProviderTxid = deviceCode
		// userCode is surfaced so the caller can show it to the user if needed
		// (only required when MS Authenticator push is not configured for the tenant)
		log.Printf("[push] Azure AD device flow for %s: user code = %s", req.Email, userCode)

	default: // "expo"
		mfaRepo := repositories.NewMFARepository(tenantDB)
		method, err := mfaRepo.GetMethod(req.UserID, "push")
		if err != nil || !method.Enabled {
			c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "push MFA not enrolled for this user"})
			return
		}
		var pushData struct {
			ExpoPushToken string `json:"expo_push_token"`
		}
		if err := json.Unmarshal(method.MethodData, &pushData); err != nil || pushData.ExpoPushToken == "" {
			c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "no push token registered"})
			return
		}
		go func() {
			_, err := notifications.SendExpoPush(notifications.ExpoPushPayload{
				To:       pushData.ExpoPushToken,
				Priority: "high",
				Data: map[string]interface{}{
					"type":         "platform_mfa",
					"challenge_id": challengeID,
					"email":        req.Email,
					"tenant_id":    req.TenantID,
				},
			})
			if err != nil {
				log.Printf("[push] Expo send to %s: %v", req.Email, err)
				if notifications.IsDeviceNotRegistered(err) {
					mfaRepo.DisableMethod(method.ClientID, "push")
				}
			}
		}()
	}

	storeChallenge(challengeID, challenge)

	c.JSON(http.StatusOK, dto.PushChallengeResponse{
		ChallengeID: challengeID,
		ExpiresIn:   int(pushChallengeTTL.Seconds()),
	})
}

// Respond is called by the mobile app when the user taps Approve or Deny.
func (h *PushHandler) Respond(c *gin.Context) {
	var req dto.PushRespondRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	ch := loadChallenge(req.ChallengeID)
	if ch == nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "challenge not found"})
		return
	}

	if time.Now().After(ch.ExpiresAt) {
		updateChallengeStatus(req.ChallengeID, "expired")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "challenge expired"})
		return
	}

	if ch.Status != "pending" {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "challenge already resolved"})
		return
	}

	newStatus := "denied"
	if req.Approved {
		newStatus = "approved"
	}
	updateChallengeStatus(req.ChallengeID, newStatus)

	orgName, _ := util.GetOrganizationDatabaseName(ch.OrgID)
	if orgName != "" {
		tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
		mfaRepo := repositories.NewMFARepository(tenantDB)
		mfaRepo.UpdateLastUsed(ch.UserID, "push")
	}

	c.JSON(http.StatusOK, dto.PushRespondResponse{Success: true})
}

// Status is polled by the AD sensor / login layer to get the challenge result.
// For Expo (Authnull app): status is updated by the Respond endpoint (user taps approve/deny).
// For Duo / Okta / Azure AD: we poll the provider API inline on each Status call.
func (h *PushHandler) Status(c *gin.Context) {
	var req dto.PushStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	ch := loadChallenge(req.ChallengeID)
	if ch == nil {
		c.JSON(http.StatusOK, dto.PushStatusResponse{Status: "expired"})
		return
	}

	if ch.Status == "pending" && time.Now().After(ch.ExpiresAt) {
		updateChallengeStatus(req.ChallengeID, "expired")
		c.JSON(http.StatusOK, dto.PushStatusResponse{Status: "expired"})
		return
	}

	// For external providers (Duo / Okta / Azure AD), poll the provider API
	// to get the latest status. The result is written back to Redis so
	// subsequent Status calls return the cached result without re-polling.
	if ch.Status == "pending" && ch.ProviderTxid != "" {
		orgName, _ := util.GetOrganizationDatabaseName(ch.OrgID)
		if orgName != "" {
			tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
			providerRepo := repositories.NewProviderConfigRepository(tenantDB)
			cfg, _ := providerRepo.GetProviderConfig(ch.OrgID)

			var polledStatus string
			switch ch.Provider {
			case "duo":
				polledStatus, _ = providers.DuoPoll(ch.ProviderTxid, providers.DuoConfig{
					IKey: cfg.IKey, SKey: cfg.SKey, Host: cfg.Host,
				})
			case "okta":
				polledStatus, _ = providers.OktaPoll(ch.ProviderTxid, providers.OktaConfig{
					Domain: cfg.Domain, APIToken: cfg.APIToken,
				})
			case "azure_ad":
				polledStatus, _ = providers.AzureADPoll(ch.ProviderTxid, providers.AzureADConfig{
					TenantId: cfg.TenantId, ClientId: cfg.ClientId, ClientSecret: cfg.ClientSecret,
				})
			}

			if polledStatus != "" && polledStatus != "pending" {
				updateChallengeStatus(req.ChallengeID, polledStatus)
				ch.Status = polledStatus
			}
		}
	}

	c.JSON(http.StatusOK, dto.PushStatusResponse{Status: ch.Status})
}

func randomHexToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
