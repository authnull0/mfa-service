package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OktaConfig holds decrypted Okta credentials.
type OktaConfig struct {
	Domain   string // e.g. "authnull.okta.com" (no scheme)
	APIToken string // Okta API token (SSWS token)
}

// OktaInitiate triggers an Okta Verify push for the given email address
// and returns an Okta transaction ID.
//
// Flow:
//   1. Look up the user by email to get the Okta userId.
//   2. List the user's enrolled factors; find the first "push" factor.
//   3. POST /api/v1/users/{userId}/factors/{factorId}/verify → returns transactionId.
func OktaInitiate(email string, cfg OktaConfig) (txid string, err error) {
	userID, factorID, err := oktaFindPushFactor(email, cfg)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("/api/v1/users/%s/factors/%s/verify", userID, factorID)
	resp, err := oktaRequest(http.MethodPost, cfg, path, `{}`)
	if err != nil {
		return "", fmt.Errorf("okta initiate verify: %w", err)
	}

	var result struct {
		FactorResult  string `json:"factorResult"`  // "WAITING" on success
		ExpiresAt     string `json:"expiresAt"`
		Links         struct {
			Poll struct {
				Href string `json:"href"`
			} `json:"poll"`
		} `json:"_links"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("okta initiate: parse: %w", err)
	}
	if result.FactorResult == "" {
		return "", fmt.Errorf("okta initiate: unexpected response (no factorResult)")
	}

	// Extract transaction ID from poll href:
	// https://domain/api/v1/users/{uid}/factors/{fid}/transactions/{txid}
	href := result.Links.Poll.Href
	parts := strings.Split(href, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("okta initiate: cannot parse txid from poll href: %s", href)
	}
	txid = parts[len(parts)-1]
	// Encode userID + factorID into txid so Poll can use them
	return fmt.Sprintf("%s|%s|%s", userID, factorID, txid), nil
}

// OktaPoll checks the status of an Okta push challenge.
// txid format: "{userId}|{factorId}|{transactionId}" (as stored by OktaInitiate).
// Returns "pending", "approved", or "denied".
func OktaPoll(txid string, cfg OktaConfig) (string, error) {
	parts := strings.SplitN(txid, "|", 3)
	if len(parts) != 3 {
		return "pending", fmt.Errorf("okta poll: invalid txid format")
	}
	userID, factorID, transactionID := parts[0], parts[1], parts[2]

	path := fmt.Sprintf("/api/v1/users/%s/factors/%s/transactions/%s",
		userID, factorID, transactionID)
	resp, err := oktaRequest(http.MethodGet, cfg, path, "")
	if err != nil {
		return "pending", fmt.Errorf("okta poll: %w", err)
	}

	var result struct {
		FactorResult string `json:"factorResult"` // "SUCCESS" | "REJECTED" | "WAITING" | "TIMEOUT"
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "pending", nil
	}

	switch result.FactorResult {
	case "SUCCESS":
		return "approved", nil
	case "REJECTED", "TIMEOUT":
		return "denied", nil
	default:
		return "pending", nil
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// oktaFindPushFactor looks up the Okta userId for the given email and returns
// the first enrolled Okta Verify push factor.
func oktaFindPushFactor(email string, cfg OktaConfig) (userID, factorID string, err error) {
	resp, err := oktaRequest(http.MethodGet, cfg,
		"/api/v1/users/"+email, "")
	if err != nil {
		return "", "", fmt.Errorf("okta user lookup: %w", err)
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp, &user); err != nil || user.ID == "" {
		return "", "", fmt.Errorf("okta user lookup: user not found for %s", email)
	}

	resp, err = oktaRequest(http.MethodGet, cfg,
		fmt.Sprintf("/api/v1/users/%s/factors", user.ID), "")
	if err != nil {
		return "", "", fmt.Errorf("okta list factors: %w", err)
	}

	var factors []struct {
		ID           string `json:"id"`
		FactorType   string `json:"factorType"`
		Provider     string `json:"provider"`
		Status       string `json:"status"`
	}
	if err := json.Unmarshal(resp, &factors); err != nil {
		return "", "", fmt.Errorf("okta list factors: parse: %w", err)
	}

	for _, f := range factors {
		if f.FactorType == "push" && f.Provider == "OKTA" && f.Status == "ACTIVE" {
			return user.ID, f.ID, nil
		}
	}
	return "", "", fmt.Errorf("okta: no active Okta Verify push factor for %s", email)
}

func oktaRequest(method string, cfg OktaConfig, path, body string) ([]byte, error) {
	baseURL := "https://" + cfg.Domain

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "SSWS "+cfg.APIToken)
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("okta API %s %s → %d: %s", method, path, res.StatusCode, string(data))
	}
	return data, nil
}
