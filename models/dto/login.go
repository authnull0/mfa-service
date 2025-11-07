package dto

type NormalLoginRequest struct {
	Username string `json:"username"`
	//Password  string `json:"password"`
	Url       string `json:"url"`
	RequestID string `json:"requestId"`
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
