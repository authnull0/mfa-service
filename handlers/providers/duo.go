// Package providers implements MFA provider adapters.
// Each adapter exposes two operations:
//   Initiate — trigger a push/challenge, return a provider transaction ID
//   Poll     — check whether the user approved or denied
package providers

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DuoConfig holds decrypted Duo Auth API v2 credentials.
type DuoConfig struct {
	IKey string // Integration key
	SKey string // Secret key
	Host string // API hostname, e.g. "api-XXXXXXXX.duosecurity.com"
}

// DuoInitiate sends a push notification to the user via Duo Auth API v2
// and returns Duo's transaction ID (txid). The txid is stored in Redis
// and used by DuoPoll on subsequent Status calls.
//
// Duo push is asynchronous: Duo returns a txid immediately and the user
// approves/denies on their Duo Mobile app. We poll DuoPoll for the result.
func DuoInitiate(email string, cfg DuoConfig) (txid string, err error) {
	params := url.Values{}
	params.Set("username", email)
	params.Set("factor", "push")
	params.Set("device", "auto")
	params.Set("async", "1")

	resp, err := duoRequest(http.MethodPost, cfg, "/auth/v2/auth", params)
	if err != nil {
		return "", fmt.Errorf("duo initiate: %w", err)
	}

	var result struct {
		Stat     string `json:"stat"`
		Response struct {
			Txid string `json:"txid"`
		} `json:"response"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("duo initiate: parse response: %w", err)
	}
	if result.Stat != "OK" {
		return "", fmt.Errorf("duo initiate: %s", result.Message)
	}
	return result.Response.Txid, nil
}

// DuoPoll checks the status of a Duo async auth transaction.
// Returns "pending", "approved", or "denied".
func DuoPoll(txid string, cfg DuoConfig) (string, error) {
	params := url.Values{}
	params.Set("txid", txid)

	resp, err := duoRequest(http.MethodGet, cfg, "/auth/v2/auth_status", params)
	if err != nil {
		return "pending", fmt.Errorf("duo poll: %w", err)
	}

	var result struct {
		Stat     string `json:"stat"`
		Response struct {
			Result string `json:"result"` // "allow" | "deny" | "waiting"
		} `json:"response"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "pending", fmt.Errorf("duo poll: parse: %w", err)
	}
	if result.Stat != "OK" {
		return "pending", nil
	}

	switch result.Response.Result {
	case "allow":
		return "approved", nil
	case "deny":
		return "denied", nil
	default:
		return "pending", nil
	}
}

// ── Duo request signing ───────────────────────────────────────────────────────
//
// Duo Auth API uses HMAC-SHA1 with a canonical string:
//   date\nMETHOD\nhost\npath\nparams_sorted
// Authorization: Basic base64(ikey + ":" + hmac_hex)

func duoRequest(method string, cfg DuoConfig, path string, params url.Values) ([]byte, error) {
	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
	host := strings.ToLower(cfg.Host)

	// Sort params for canonical form
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(params.Get(k)))
	}
	paramStr := strings.Join(parts, "&")

	canon := strings.Join([]string{date, method, host, path, paramStr}, "\n")

	mac := hmac.New(sha1.New, []byte(cfg.SKey))
	mac.Write([]byte(canon))
	sig := fmt.Sprintf("%x", mac.Sum(nil))

	auth := base64.StdEncoding.EncodeToString([]byte(cfg.IKey + ":" + sig))

	var reqURL string
	var body io.Reader
	if method == http.MethodGet {
		reqURL = "https://" + host + path + "?" + paramStr
	} else {
		reqURL = "https://" + host + path
		body = strings.NewReader(paramStr)
	}

	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Date", date)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}
