package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/authnull0/mfa-service/config"
	"github.com/authnull0/mfa-service/handlers"
	session "github.com/authnull0/mfa-service/internal"
	"github.com/authnull0/mfa-service/routes"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// @title           MFA Service API
// @version         1.0
// @description     Multi-Factor Authentication Service supporting WebAuthn, TOTP, and SMS
// @host      localhost:8080
// @BasePath  /webauthn
func main() {
	handlers.Init()
	// Load .env file if it exists (optional for development)
	godotenv.Load()

	// Validate required environment variables
	if err := validateRequiredEnvVars(); err != nil {
		log.Fatal("Environment validation failed:", err)
	}

	r := gin.Default()

	// Configure CORS dynamically
	r.Use(setupCORS())

	// Get WebAuthn configuration from environment
	rpName := getEnv("WEBAUTHN_RP_NAME", "Default App")
	rpID := getEnv("WEBAUTHN_RP_ID", "localhost")
	origin := getEnv("WEBAUTHN_ORIGIN", "http://localhost:3000")
	port := getEnv("PORT", "8080")

	// Initialize WebAuthn with dynamic configuration
	webAuthn := config.SetupWebAuthn(rpName, rpID, origin)

	// In-memory session manager
	sessionManager := session.NewSessionManager()

	// Create WebAuthn handler
	webAuthnHandler := &handlers.WebAuthnHandler{
		WebAuthn:       webAuthn,
		SessionManager: sessionManager,
	}

	// Register routes
	routes.RegisterRoutes(r, webAuthnHandler)

	// Start server
	log.Printf("Starting %s server on port %s", getEnv("ENVIRONMENT", "development"), port)
	log.Printf("WebAuthn Configuration:")
	log.Printf("RP Name: %s", webAuthn.Config.RPDisplayName)
	log.Printf("RP ID: %s", webAuthn.Config.RPID)
	log.Printf("Origin: %s", webAuthn.Config.RPOrigins)

	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Validate that required environment variables are set
func validateRequiredEnvVars() error {
	required := []string{
		"WEBAUTHN_RP_NAME",
		"WEBAUTHN_RP_ID",
		"WEBAUTHN_ORIGIN",
	}

	for _, env := range required {
		if os.Getenv(env) == "" {
			return fmt.Errorf("required environment variable %s is not set", env)
		}
	}
	return nil
}

// Setup CORS with environment-based configuration
func setupCORS() gin.HandlerFunc {
	corsConfig := cors.DefaultConfig()

	// Get allowed origins from environment
	if origins := getEnv("CORS_ALLOWED_ORIGINS", ""); origins != "" {
		corsConfig.AllowOrigins = strings.Split(origins, ",")
	} else {
		// Default CORS for development
		corsConfig.AllowAllOrigins = true
	}

	// Configure other CORS settings from environment
	if methods := getEnv("CORS_ALLOWED_METHODS", ""); methods != "" {
		corsConfig.AllowMethods = strings.Split(methods, ",")
	}

	if headers := getEnv("CORS_ALLOWED_HEADERS", ""); headers != "" {
		corsConfig.AllowHeaders = strings.Split(headers, ",")
	}

	return cors.New(corsConfig)
}
