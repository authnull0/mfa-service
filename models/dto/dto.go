package dto

import "github.com/go-webauthn/webauthn/protocol"

type BeginRegistrationRequest struct {
	TenantID int    `json:"tenantId" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

type InitiateRegistrationResponse struct {
	UserID  string      `json:"user_id"`
	Options interface{} `json:"options"` // this will be PublicKeyCredentialCreationOptions
}

type FinishRegistrationRequest struct {
	Email      string                              `json:"email" binding:"required"`
	TenantID   int                                 `json:"tenantId" binding:"required"`
	Credential protocol.CredentialCreationResponse `json:"credential" binding:"required"`
}
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
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
