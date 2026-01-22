package dto

type NormalLoginRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Url       string `json:"url"`
	RequestID string `json:"requestId"`
	Factor    string `json:"factor" binding:"required"`
}

type NormalLoginResponse struct {
	Code             int    `json:"code"`
	Message          string `json:"message"`
	Status           string `json:"status"`
	FirstLogin       string `json:"first_login"`
	AccessToken      string `json:"access_token"`
	SsoMfa           bool   `json:"sso_mfa"`
	Url              string `json:"url"`
	UserWalletStatus string `json:"wallet_status"`
}
type GetSessionFromRedisRequest struct {
	Key string `json:"key"`
}

type GetSessionResponse struct {
	Validation bool   `json:"validation"`
	Code       int    `json:"code"`
	Message    string `json:"message"`
	Status     string `json:"status"`
	User       string `json:"user"`
	UserRole   string `json:"userRole"`
}
type HandleSamlResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type BackToSamlLoginRequest struct {
	Email string `json:"email" validate:"required,email"`
	Token string `json:"token" validate:"required"`
	Url   string `json:"url" validate:"required"`
}

type BackToSamlLoginResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type SsoMfaRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Token     string `json:"token" validate:"required"`
	Url       string `json:"url" validate:"required"`
	RequestID string `json:"requestId"`
}

type SsoMfaResponse struct {
	Code       int    `json:"code"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	FirstLogin string `json:"first_login"`
	Data       bool   `json:"data"`
}
type DoAuthnResponse struct {
	IsValid   bool   `json:"isValid"`
	Message   string `json:"message"`
	Status    string `json:"status"`
	Code      int    `json:"code"`
	RequestID string `json:"requestId"`
	SsoUrl    string `json:"ssoUrl"`
	Stage     int    `json:"stage"`
}
type EntraAuthRequest struct {
	Version       string `json:"version"`
	RequestID     string `json:"requestId"`
	Username      string `json:"username"`
	ClientApp     string `json:"clientApp"`
	TransactionID string `json:"transactionId"`
}

type EntraAuthResponse struct {
	Authenticated bool   `json:"authenticated"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
}

// ---------------------------
// Metadata (required by Entra)
// ---------------------------
type Metadata struct {
	// Standard OIDC Required Fields
	Issuer                           string   `json:"issuer"`                                // REQUIRED: The URL of your service.
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`                // REQUIRED: The URL Entra ID redirects the user to for authentication.
	JwksURI                          string   `json:"jwks_uri"`                              // REQUIRED: Where Entra ID finds your public keys for signature validation.
	ResponseTypesSupported           []string `json:"response_types_supported"`              // REQUIRED: Must include "id_token" for EAM.
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"` // REQUIRED: Must include "RS256".
	SubjectTypesSupported            []string `json:"subject_types_supported"`               // REQUIRED: Must include "public".
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`            // Optional, but usually "openid" is included.

	// Custom EAM Fields
	Version                string `json:"version"`                // EAM-specific
	AuthenticationMode     string `json:"authenticationMode"`     // EAM-specific: "Synchronous"
	AuthenticationEndpoint string `json:"authenticationEndpoint"` // EAM-specific: Your POST endpoint URL.
}
type OrgLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type OrgLoginResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Token   string `json:"token"`
}
