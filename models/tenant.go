package models

import "time"

// type Tenant struct {
// 	ID         string `gorm:"primaryKey"`
// 	TenantID   string
// 	TenantDB   string
// 	Email      string
// 	Username   string
// 	Password   string
// 	Provider   string
// 	ProviderID string
// 	Name       string
// 	Avatar     string
// 	Source     string
// 	Status     string
// }

type Tenant struct {
	Id                     int       `json:"id" gorm:"primary_key"`
	TenantName             string    `json:"tenant_name"`
	AdminEmail             string    `json:"admin_email"`
	SiteURL                string    `json:"site_url"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
	OrganizationId         int       `json:"organization_id"`
	Status                 string    `json:"status"`
	AuthenticationMethod   string    `json:"authentication_method"`
	PlatformMfa            int       `json:"platform_mfa"`
	MfaDevices             int       `json:"mfa_devices"`
	AuthenticationPolicy   int       `json:"authentication_policy"`
	SsoMfa                 int       `json:"sso_mfa"`
	SsoMfaEndUser          int       `json:"sso_mfa_enduser"`
	AdminMfaCache          int       `json:"admin_mfa_cache"`
	EndUserMfaCache        int       `json:"enduser_mfa_cache"`
	EntityAuthentication   int       `json:"entity_authentication"`
	ConnectionMode         int       `json:"connection_mode"`
	CredentialStore        int       `json:"credential_store"`
	CredentialShareMode    int       `json:"credential_share_mode"`
	CredentialMode         int       `json:"credential_mode"`
	VaultFlag              string    `json:"vault_flag"`
	DefaultIssuer          string    `json:"default_issuer"`
	IsDITEnabled           string    `json:"is_dit_enabled"`
	TimeZone               string    `json:"time_zone"`
	LogOutputName          string    `json:"log_output_name"`
	ImageUrl               string    `json:"image_url"`
	SessionRecordingKey    string    `json:"session_recording_key"`
	SessionRecordingSecret string    `json:"session_recording_secret"`
	SessionRecordingRegion string    `json:"session_recording_region"`
	BucketName             string    `json:"bucket_name"`
	DisableRootAccess      bool      `json:"disable_root_access"`
}

func (Tenant) TableName() string {
	return "did.tenants"
}

type User struct {
	UserId           int    `gorm:"column:user_id;primary_key"`
	EmailAddress     string `gorm:"column:email_address"`
	PhoneNumber      string `gorm:"column:phone_number"`
	LogOnName        string `gorm:"column:logon_name"`
	City             string `gorm:"column:city"`
	Country          string `gorm:"column:country"`
	Industry         string `gorm:"column:industry"`
	Organization     string `gorm:"column:organization"`
	CompanyHeadcount string `gorm:"column:company_headcount"`
	FirstName        string `gorm:"column:firstname"`
	LastName         string `gorm:"column:lastname"`
	Address          string `gorm:"column:address"`
	Password         string `gorm:"column:user_password"`
	DomainId         string `gorm:"column:domain_id"`
	Status           string `gorm:"column:status"`
	OtpMethod        string `gorm:"column:otp_method"`
	Metadata         string `gorm:"column:metadata"`
	Dn               string `gorm:"column:dn"`
	UserRoleID       int    `gorm:"column:user_role_id"`
	OrgID            int    `gorm:"column:org_id"`
	FirstLogin       string `gorm:"column:first_login"`
}

func (User) TableName() string {
	return "did.users"
}

type Organization struct {
	Id                   uint      `json:"id" gorm:"primary_key"`
	OrganizationName     string    `json:"organization_name"`
	AdminEmail           string    `json:"admin_email"`
	SiteURL              string    `json:"site_url"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Status               string    `json:"status"`
	DatabaseStatus       string    `json:"database_status"`
	DatabaseName         string    `json:"database_name"`
	AuthenticationMethod string    `json:"authentication_method"`
}

func (Organization) TableName() string {
	return "did.organizations"
}

type UserMFAConfig struct {
	UserID    int       `json:"user_id"`
	TenantID  int       `json:"tenant_id"`
	OrgID     int       `json:"org_id"`
	AppID     int       `json:"app_id"`
	MFAType   int       `json:"mfa_type"`
	MFADetail string    `json:"mfa_detail"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	//IsDefault bool      `json:"is_default"`
}

func (UserMFAConfig) TableName() string {
	return "did.user_mfa_config"
}

type UserWallets struct {
	Id                 int    `gorm:"column:id;primary_key"`
	DomainId           int    `gorm:"column:domain_id"`
	WalletURL          string `gorm:"column:wallet_url"`
	UserId             int    `gorm:"column:user_id"`
	Status             string `gorm:"column:status"`
	WalletKey          string `gorm:"column:wallet_key"`
	RegisteredCountry  string `gorm:"column:registered_country"`
	RegisteredState    string `gorm:"column:registered_state"`
	RegisteredCity     string `gorm:"column:registered_city"`
	DeviceID           string `gorm:"column:device_id"`
	Coord              string `gorm:"column:coord"`
	BiometricProtected bool   `gorm:"column:biometric_protected"`
	DeviceOS           string `gorm:"column:device_os"`
	Network            string `gorm:"column:network"`
	DeviceToken        string `gorm:"column:device_token"`
}

func (UserWallets) TableName() string {
	return "did.user_wallets"
}

type AuthenticationMethod struct {
	Id                   int    `gorm:"column:id;primary_key"`
	OrgId                int    `gorm:"column:org_id"`
	AuthenticationMethod string `gorm:"column:authentication_method"`
	SSOUrl               string `gorm:"column:sso_url"`
	ModuleName           string `gorm:"module_name"`
	SingleSignOnUrl      string `gorm:"column:single_sign_on_url"`
	SingleLogoutUrl      string `gorm:"column:single_logout_url"`
	MetadataUrl          string `gorm:"column:metadata_url"`
	APIKey               string `gorm:"column:api_key"`
}

func (AuthenticationMethod) TableName() string {
	return "did.authentication_methods"
}
