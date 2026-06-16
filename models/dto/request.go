package dto

type TOTPSetupRequest struct {
	Email string `json:"email" binding:"required" example:"john@example.com"`
	//TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	Url string `json:"url" binding:"required"`
}

type TOTPConfirmRequest struct {
	Email string `json:"email" binding:"required" example:"john@example.com"`
	// TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	// OrgID    int    `json:"orgId" binding:"required" example:"1"`
	Secret string `json:"secret" binding:"required" example:"JBSWY3DPEHPK3PXP"`
	Code   string `json:"code" binding:"required" example:"123456"`
	Url    string `json:"url" binding:"required"`
}

type TOTPVerifyRequest struct {
	Email string `json:"email" binding:"required" example:"john@example.com"`
	// TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	Url  string `json:"url" binding:"required"`
	Code string `json:"code" binding:"required" example:"123456"`
}

type SMSSetupRequest struct {
	Email       string `json:"email" binding:"required" example:"john@example.com"`
	TenantID    int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	PhoneNumber string `json:"phone_number" binding:"required" example:"+1234567890"`
}

// SMSConfirmRequest for confirming SMS setup with verification code
type SMSConfirmRequest struct {
	Email    string `json:"email" binding:"required" example:"john@example.com"`
	TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	Code     string `json:"code" binding:"required" example:"123456"`
}

// RequestSMSCodeRequest for requesting SMS code during authentication
type RequestSMSCodeRequest struct {
	Email    string `json:"email" binding:"required" example:"john@example.com"`
	TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
}

// VerifySMSRequest for verifying SMS code during authentication
type VerifySMSRequest struct {
	Email    string `json:"email" binding:"required" example:"john@example.com"`
	TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	Code     string `json:"code" binding:"required" example:"123456"`
}
type WebAuthnCredentialRequest struct {
	Email      string                 `json:"email" binding:"required" example:"john@example.com"`
	TenantID   int                    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	Credential WebAuthnCredentialData `json:"credential" binding:"required"`
}

type WebAuthnCredentialData struct {
	ID       string           `json:"id" example:"credential_id_here"`
	RawID    string           `json:"rawId" example:"base64url_encoded_raw_id"`
	Type     string           `json:"type" example:"public-key"`
	Response WebAuthnResponse `json:"response"`
}

type WebAuthnResponse struct {
	AttestationObject string  `json:"attestationObject,omitempty" example:"base64url_encoded_attestation"`
	ClientDataJSON    string  `json:"clientDataJSON" example:"base64url_encoded_client_data"`
	AuthenticatorData string  `json:"authenticatorData,omitempty" example:"base64url_encoded_auth_data"`
	Signature         string  `json:"signature,omitempty" example:"base64url_encoded_signature"`
	UserHandle        *string `json:"userHandle,omitempty" example:"base64url_encoded_user_handle"`
}

type VerifyUserRequest struct {
	// OrgID     int    `json:"orgId" binding:"required"`
	// TenantID  int    `json:"tenantId" binding:"required"`
	Url       string `json:"url" binding:"required"`
	UserEmail string `json:"userEmail" binding:"required"`
}
type RegisterWalletSetupRequest struct {
	Email string `json:"email" binding:"required" example:"john@example.com"`
	// OrgID    int    `json:"orgId" binding:"required" example:"1"`
	// TenantID int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	Url string `json:"url" binding:"required"`
}
type RegisterWalletSetupResponse struct {
	Email     string `json:"email" binding:"required" example:"john@example.com"`
	TenantID  int    `json:"tenantId" binding:"required" example:"855f81db-1567-413d-8b24-8db3a07f6bd9"`
	WalletKey string `json:"walletKey" binding:"required" example:"unique_wallet_key_here"`
	Message   string `json:"message" binding:"required" example:"Wallet registration initiated"`
}
type TOTPDeleteRequest struct {
	Email    string `json:"email" binding:"required" example:"john@example.com"`
	OrgID    int    `json:"orgId" binding:"required"`
	TenantID int    `json:"tenantId" binding:"required"`
}

// --- Push MFA ---

type PushSetupRequest struct {
	Email    string `json:"email" binding:"required"`
	TenantID int    `json:"tenantId" binding:"required"`
	OrgID    int    `json:"orgId" binding:"required"`
}

type PushConfirmRequest struct {
	Email           string `json:"email" binding:"required"`
	TenantID        int    `json:"tenantId" binding:"required"`
	OrgID           int    `json:"orgId" binding:"required"`
	UserID          int    `json:"userId" binding:"required"`
	EnrollmentToken string `json:"enrollmentToken" binding:"required"`
	ExpoPushToken   string `json:"expoPushToken" binding:"required"`
	Platform        string `json:"platform"`
	DeviceName      string `json:"deviceName"`
}

type PushChallengeRequest struct {
	Email    string `json:"email" binding:"required"`
	UserID   int    `json:"userId" binding:"required"`
	TenantID int    `json:"tenantId" binding:"required"`
	OrgID    int    `json:"orgId" binding:"required"`
}

type PushRespondRequest struct {
	ChallengeID string `json:"challengeId" binding:"required"`
	Approved    bool   `json:"approved"`
}

type PushStatusRequest struct {
	ChallengeID string `json:"challengeId" binding:"required"`
}

// --- AD MFA Provider Config ---

type SetMFAProviderRequest struct {
	OrgId    int    `json:"orgId" binding:"required"`
	Provider string `json:"provider" binding:"required"`
	// Duo
	IKey     string `json:"ikey,omitempty"`
	SKey     string `json:"skey,omitempty"`
	Host     string `json:"host,omitempty"`
	// Okta
	Domain   string `json:"domain,omitempty"`
	APIToken string `json:"apiToken,omitempty"`
	// Azure AD (MS Authenticator)
	TenantId     string `json:"tenantId,omitempty"`
	ClientId     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

type GetMFAProviderRequest struct {
	OrgId int `json:"orgId" binding:"required"`
}

type DeleteMFAProviderRequest struct {
	OrgId int `json:"orgId" binding:"required"`
}

type GetProviderConfigRequest struct {
	OrgId int `json:"orgId" binding:"required"`
}
