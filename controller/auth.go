package controllers

import (
	"net/http"
	"strconv"

	"github.com/authnull0/mfa-service/config"
	"github.com/authnull0/mfa-service/models"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

type RegisterInitiateRequest struct {
	TenantID int    `json:"tenantId" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

// In-memory store for challenge state – for now (can replace with DB/cache later)
var userStore = make(map[string]*webauthn.SessionData)

func RegisterInitiateHandler(w *webauthn.WebAuthn) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterInitiateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Connect to global DB
		globalDB, err := config.ConnectGlobalDB()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to global DB"})
			return
		}

		// Get tenant DB name
		tenantDBName, err := config.GetTenantDBName(globalDB, req.TenantID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		// Connect to tenant DB
		tenantDB, err := config.ConnectTenantDB(tenantDBName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to tenant DB"})
			return
		}

		// Fetch client
		var client models.Client
		if err := tenantDB.Where("email = ?", req.Email).First(&client).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Client not found"})
			return
		}

		// Wrap client in WebAuthn-compatible user
		user := models.NewWebAuthnUser(&client)

		// Generate challenge
		options, sessionData, err := w.BeginRegistration(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create registration challenge"})
			return
		}
		sessionTenantID := strconv.Itoa(req.TenantID)
		// Store session (map key: tenant_id+email)
		userStore[sessionTenantID+"|"+req.Email] = sessionData

		c.JSON(http.StatusOK, options)
	}
}
