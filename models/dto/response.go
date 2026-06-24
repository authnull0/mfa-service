package dto

import (
	"time"

	"github.com/authnull0/mfa-service/models"
)

// SMSCodeResponse for SMS code request response
type SMSCodeResponse struct {
	Success           bool   `json:"success" example:"true"`
	Message           string `json:"message" example:"SMS code sent"`
	PhoneDisplay      string `json:"phone_display" example:"+123***7890"`
	ExpiresInMinutes  int    `json:"expires_in_minutes" example:"5"`
	AttemptsRemaining int    `json:"attempts_remaining" example:"3"`
}
type ErrorResponse struct {
	Error string `json:"error" example:"Error description"`
}

type SuccessResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"Operation successful"`
}

type AuthenticationResponse struct {
	Success      bool   `json:"success" example:"true"`
	Method       string `json:"method" example:"totp"`
	Message      string `json:"message" example:"Authentication successful"`
	CredentialID string `json:"credential_id,omitempty" example:"52825709ae6899bcc58140b5"`
	UserID       int    `json:"user_id"`
	Email        string `json:"email" example:"john@example.com"`
}

type MFAMethodsResponse struct {
	AvailableMFAMethods []MFAMethod `json:"available_mfa_methods"`
	UserID              string      `json:"user_id" example:"ff334e26-5fda-4c84-aa1e-56f888029fe0"`
	Email               string      `json:"email" example:"john@example.com"`
	ExistingMethods     int         `json:"existing_methods" example:"1"`
	Message             string      `json:"message" example:"Select an MFA method to register"`
}

type MFAMethod struct {
	Type        string `json:"type" example:"webauthn"`
	DisplayName string `json:"display_name" example:"Biometric/Passkey Authentication"`
	Description string `json:"description" example:"Use your device's biometric or security key"`
	Recommended bool   `json:"recommended" example:"true"`
	Enabled     bool   `json:"enabled" example:"false"`
}

type MFAStatusResponse struct {
	UserID           int        `json:"user_id" example:"ff334e26-5fda-4c84-aa1e-56f888029fe0"`
	Email            string     `json:"email" example:"john@example.com"`
	MFAEnabled       bool       `json:"mfa_enabled" example:"true"`
	MFADefaultMethod string     `json:"mfa_default_method" example:"webauthn"`
	MFAEnrolledAt    *time.Time `json:"mfa_enrolled_at"`
	// ConfiguredMethods []MFAMethodStatus `json:"configured_methods"`
	ConfiguredMethods []MFAConfigStatus `json:"configured_methods"`
	TotalMethods      int               `json:"total_methods" example:"2"`
	//EnabledMethods    int               `json:"enabled_methods" example:"2"`
}

type MFAMethodStatus struct {
	Type            string     `json:"type" example:"webauthn"`
	DisplayName     string     `json:"display_name" example:"Biometric/Passkey Authentication"`
	Enabled         bool       `json:"enabled" example:"true"`
	Verified        bool       `json:"verified" example:"true"`
	EnrolledAt      *time.Time `json:"enrolled_at"`
	LastUsed        *time.Time `json:"last_used"`
	CredentialCount int        `json:"credential_count,omitempty" example:"1"`
	HasBackupCodes  bool       `json:"has_backup_codes,omitempty" example:"true"`
}

type TOTPSetupResponse struct {
	Secret      string `json:"secret"`
	QRCode      string `json:"qr_code"`
	ManualEntry string `json:"manual_entry"`
	Issuer      string `json:"issuer"`
	Account     string `json:"account"`
	OTPAuthURL  string `json:"otpauth_url"`
}

type TOTPConfirmResponse struct {
	Success     bool     `json:"success" example:"true"`
	Message     string   `json:"message" example:"TOTP enabled successfully"`
	BackupCodes []string `json:"backup_codes" example:"ABCD-EFGH,1234-5678"`
}

type SMSSetupResponse struct {
	Success           bool   `json:"success" example:"true"`
	Message           string `json:"message" example:"SMS verification code sent"`
	PhoneDisplay      string `json:"phone_display" example:"+123***7890"`
	ExpiresInMinutes  int    `json:"expires_in_minutes" example:"5"`
	AttemptsRemaining int    `json:"attempts_remaining" example:"3"`
}

type SMSConfirmResponse struct {
	Success      bool   `json:"success" example:"true"`
	Message      string `json:"message" example:"SMS MFA enabled successfully"`
	PhoneDisplay string `json:"phone_display" example:"+123***7890"`
}

type RegistrationResponse struct {
	Success      bool   `json:"success" example:"true"`
	Message      string `json:"message" example:"Registration successful"`
	CredentialID string `json:"credential_id" example:"52825709ae6899bcc58140b5"`
}

type WebAuthnOptionsResponse struct {
	PublicKey interface{} `json:"publicKey"`
}

type VerifyUserResponse struct {
	Code    int       `json:"code"`
	Status  string    `json:"status"`
	Message string    `json:"message"`
	UserMfa []UserMfa `json:"user_mfa"`
}
type UserMfa struct {
	MfaType   int       `json:"mfaType"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	//Default   bool      `json:"is_default"`
	Status string `json:"status"`
}

type MFAConfigStatus struct {
	TenantID    int    `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	DisplayName string `json:"display_name,omitempty" example:"Biometric/Passkey Authentication"`
	Default     bool   `json:"is_default"`
}

type UserMFAMethodsResponse struct {
	DefaultMethod models.MFAConfig   `json:"default_method"`
	Methods       []models.MFAConfig `json:"methods"`
}

// --- Push MFA ---

type PushSetupResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type PushConfirmResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type PushChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	ExpiresIn   int    `json:"expiresIn"`
}

type PushRespondResponse struct {
	Success bool `json:"success"`
}

type PushStatusResponse struct {
	Status string `json:"status"`
}

// --- AD MFA Provider Config ---

type SetMFAProviderResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Status  string `json:"status"`
}

type GetMFAProviderResponse struct {
	Message  string `json:"message"`
	Code     int    `json:"code"`
	Status   string `json:"status"`
	Provider string `json:"provider"`
	Host     string `json:"host,omitempty"`   // Duo only, non-secret
	Domain   string `json:"domain,omitempty"` // Okta only, non-secret
}

type DeleteMFAProviderResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Status  string `json:"status"`
}

// GetProviderConfigResponse is the internal response consumed by ad-service.
// Returns decrypted credentials — only accessible from internal network.
type GetProviderConfigResponse struct {
	Provider string `json:"provider"`
	// Duo
	IKey     string `json:"ikey,omitempty"`
	SKey     string `json:"skey,omitempty"`
	Host     string `json:"host,omitempty"`
	// Okta
	Domain   string `json:"domain,omitempty"`
	APIToken string `json:"apiToken,omitempty"`
	// Azure AD
	TenantId     string `json:"tenantId,omitempty"`
	ClientId     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}
