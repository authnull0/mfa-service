package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AzureADConfig holds decrypted Azure AD app registration credentials.
// The app must be registered in the customer's Azure AD tenant with:
//   - Supported account types: Accounts in this organizational directory only
//   - API permissions: openid, profile, email (delegated)
//   - Authentication: "Allow public client flows" enabled (for device code flow)
type AzureADConfig struct {
	TenantId     string // Azure AD tenant ID (GUID)
	ClientId     string // App registration client ID (GUID)
	ClientSecret string // App registration client secret
}

// AzureADInitiate starts a Device Authorization Grant flow for the given user.
// The flow works as follows:
//  1. We POST to /oauth2/v2.0/devicecode to get a device_code and user_code.
//  2. We return the device_code as the txid (stored in Redis).
//  3. The user is notified to open https://microsoft.com/devicelogin and enter user_code,
//     OR — if they have the Microsoft Authenticator app — they receive a push notification
//     automatically (when "passwordless phone sign-in" is enabled for the tenant).
//  4. AzureADPoll polls /oauth2/v2.0/token until the user approves, denies, or times out.
//
// Note: Full MS Authenticator push (without user entering a code) requires the tenant to
// have Microsoft Authenticator push notifications configured via Entra ID Authentication
// Methods policy and the user to have "passwordless phone sign-in" enabled.
func AzureADInitiate(email, loginHint string, cfg AzureADConfig) (deviceCode string, userCode string, err error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", cfg.TenantId)

	body := url.Values{}
	body.Set("client_id", cfg.ClientId)
	body.Set("scope", "openid profile email")
	if loginHint != "" {
		body.Set("login_hint", loginHint)
	}

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("azure_ad devicecode: %w", err)
	}
	defer res.Body.Close()

	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return "", "", fmt.Errorf("azure_ad devicecode: HTTP %d: %s", res.StatusCode, string(data))
	}

	var result struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Message         string `json:"message"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", "", fmt.Errorf("azure_ad devicecode: parse: %w", err)
	}

	return result.DeviceCode, result.UserCode, nil
}

// AzureADPoll polls the Azure AD token endpoint with the device_code to check
// if the user has completed MFA. Returns "pending", "approved", or "denied".
//
// Poll interval must be at least `interval` seconds (from devicecode response).
// We default to polling every 5 seconds from the Status handler.
func AzureADPoll(deviceCode string, cfg AzureADConfig) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantId)

	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	body.Set("client_id", cfg.ClientId)
	body.Set("client_secret", cfg.ClientSecret)
	body.Set("device_code", deviceCode)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "pending", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "pending", nil // transient error — keep polling
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)

	// Success: got a token
	if res.StatusCode == 200 {
		var token struct {
			IDToken string `json:"id_token"`
		}
		if json.Unmarshal(data, &token) == nil && token.IDToken != "" {
			return "approved", nil
		}
		return "approved", nil
	}

	// Error responses use RFC 6749 error codes
	var errResp struct {
		Error string `json:"error"`
	}
	json.Unmarshal(data, &errResp)

	switch errResp.Error {
	case "authorization_pending":
		return "pending", nil
	case "authorization_declined":
		return "denied", nil
	case "expired_token":
		return "denied", nil // challenge expired
	case "slow_down":
		return "pending", nil // still waiting, back off
	default:
		return "pending", nil
	}
}
