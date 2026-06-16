package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const expoPushURL = "https://exp.host/--/api/v2/push/send"

type ExpoPushPayload struct {
	To       string                 `json:"to"`
	Title    string                 `json:"title,omitempty"`
	Body     string                 `json:"body,omitempty"`
	Sound    string                 `json:"sound,omitempty"`
	Priority string                 `json:"priority,omitempty"`
	Data     map[string]interface{} `json:"data"`
}

type expoPushTicket struct {
	Status  string                 `json:"status"`
	ID      string                 `json:"id,omitempty"`
	Message string                 `json:"message,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

var expoPushClient = &http.Client{Timeout: 30 * time.Second}

func SendExpoPush(payload ExpoPushPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("expo push marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, expoPushURL, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("expo push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	if token := os.Getenv("EXPO_ACCESS_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := expoPushClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("expo push send: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expo push http %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data []expoPushTicket `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("expo push response parse: %w", err)
	}
	if len(result.Data) == 0 {
		return "", fmt.Errorf("expo push: empty ticket list")
	}

	ticket := result.Data[0]
	if ticket.Status == "error" {
		errCode, _ := ticket.Details["error"].(string)
		return "", &PushError{Message: ticket.Message, Code: errCode}
	}

	return ticket.ID, nil
}

type PushError struct {
	Message string
	Code    string
}

func (e *PushError) Error() string {
	return fmt.Sprintf("expo push error %s: %s", e.Code, e.Message)
}

func IsDeviceNotRegistered(err error) bool {
	if pe, ok := err.(*PushError); ok {
		return pe.Code == "DeviceNotRegistered"
	}
	return false
}
