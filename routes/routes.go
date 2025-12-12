package routes

import (
	"github.com/authnull0/mfa-service/handlers"
	util "github.com/authnull0/mfa-service/utils"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(router *gin.Engine, webAuthnHandler *handlers.WebAuthnHandler) {
	api := router.Group("/authentication")
	{
		// Debug GET route for testing
		api.GET("/mfa/status", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "GET reached, but should be POST"})
		})
		// WebAuthn Registration
		api.POST("/mfa/status", webAuthnHandler.GetMFAStatus)
		api.POST("/mfa/beginRegistration", webAuthnHandler.BeginRegistration)
		api.POST("/mfa/beginAuthRegistration", webAuthnHandler.BeginWebAuthnRegistration)
		api.POST("/mfa/finishRegistration", webAuthnHandler.FinishRegistration)
		// New authentication route
		api.POST("/mfa/beginAuthentication", webAuthnHandler.BeginAuthentication)
		api.POST("/mfa/finishAuthentication", webAuthnHandler.FinishAuthentication)

		totpHandler := handlers.NewTOTPHandler()
		api.POST("/mfa/totp/beginSetup", totpHandler.BeginTOTPSetup)
		api.POST("/mfa/totp/confirmSetup", totpHandler.ConfirmTOTPSetup)
		api.POST("/mfa/totp/verify", totpHandler.VerifyTOTP)
		api.POST("/mfa/totp/delete", totpHandler.DeleteTOTP)

		smsHandler := handlers.NewSMSHandler()
		api.POST("/mfa/sms/beginSetup", smsHandler.BeginSMSSetup)
		api.POST("/mfa/sms/confirmSetup", smsHandler.ConfirmSMSSetup)
		api.POST("/mfa/sms/requestCode", smsHandler.RequestSMSCode)
		api.POST("/mfa/sms/verify", smsHandler.VerifySMS)
		// WebAuthn Login (Authentication)
		//api.POST("/begin-login", webAuthnHandler.BeginLogin)
		//api.POST("/finish-login", webAuthnHandler.FinishLogin)

		api.POST("/auth/verifyUser", webAuthnHandler.VerifyUser)

		decentralizedHandler := handlers.NewDecentralizedHandler()
		api.POST("/mfa/beginRegisterWallet", decentralizedHandler.BeginRegisterWallet)

		loginHandler := handlers.NewLoginHandler()
		api.POST("/okta/normalLogin", loginHandler.HandleNormalLogin)
		api.GET("/okta/favicon.ico", loginHandler.FaviconHandler)
		api.GET("/okta/getsession", loginHandler.GetSession)
		api.POST("/okta/ssomfa", loginHandler.SsoMfa)
		api.GET("/okta/Logout", loginHandler.LogoutHandler)
		api.POST("/saml/callback", loginHandler.HandleSamlResponse)
		//API to handle emapta saml login request
		api.GET("/emaptasaml/login", util.SamlHandler)
		api.GET("/v1/Logout", loginHandler.SamlLogout)
		api.POST("/backToLogin", loginHandler.BackToLogin)

		// NEW — Entra EAM metadata endpoint
		api.GET("/.well-known/authentication-configuration", func(c *gin.Context) {
			loginHandler.MetadataHandler(c.Writer, c.Request)
		})

		// NEW — Entra EAM dummy MFA endpoint
		api.GET("/auth/external-mfa", func(ctx *gin.Context) {
			loginHandler.ExternalMFAHandler(ctx.Writer, ctx.Request)
		})

		api.GET("/oauth2/v1/keys", func(c *gin.Context) {
			loginHandler.JwksHandler(c.Writer, c.Request)
		})
	}
}
