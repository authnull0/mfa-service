package services

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"github.com/twilio/twilio-go"
	api "github.com/twilio/twilio-go/rest/api/v2010"
)

type TOTPService struct{}

func NewTOTPService() *TOTPService {
	return &TOTPService{}
}

// Generate a new TOTP secret for a user
func (s *TOTPService) GenerateSecret(accountName, issuer string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		SecretSize:  32, // 32 bytes = 256 bits
	})
}

// Validate a TOTP code with time window (allows for clock skew)
func (s *TOTPService) ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// Validate with custom time window
func (s *TOTPService) ValidateCodeWithWindow(secret, code string, window int) bool {
	// Check current time and ±window periods (30-second intervals)
	now := time.Now()
	for i := -window; i <= window; i++ {
		t := now.Add(time.Duration(i) * 30 * time.Second)

		// FIX: Handle both return values from ValidateCustom
		valid, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
			Period:    30,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})

		// Return true if validation succeeds and no error
		if err == nil && valid {
			return true
		}
	}
	return false
}

// Generate QR code PNG data
func (s *TOTPService) GenerateQRCode(key *otp.Key, size int) ([]byte, error) {
	return qrcode.Encode(key.String(), qrcode.Medium, size)
}

// Generate backup codes
func (s *TOTPService) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := s.generateRandomCode(8)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func (s *TOTPService) generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length/2) // hex encoding doubles the length
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(bytes)), nil
}

// Format backup code for display (e.g., "ABCD-EFGH")
func (s *TOTPService) FormatBackupCode(code string) string {
	if len(code) != 8 {
		return code
	}
	return fmt.Sprintf("%s-%s", code[:4], code[4:])
}

type SMSService struct {
	client *twilio.RestClient
}

func NewSMSService() *SMSService {
	accountSid := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")

	if accountSid == "" || authToken == "" {
		log.Println("  Twilio credentials not set, SMS service will use mock mode")
		return &SMSService{client: nil} // Mock mode
	}

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})

	return &SMSService{client: client}
}

// Generate a 6-digit SMS code
func (s *SMSService) GenerateCode() (string, error) {
	// Generate 6-digit code
	max := big.NewInt(999999)
	min := big.NewInt(100000)

	n, err := rand.Int(rand.Reader, max.Sub(max, min).Add(max, big.NewInt(1)))
	if err != nil {
		return "", err
	}

	code := fmt.Sprintf("%06d", n.Add(n, min).Int64())
	return code, nil
}

// Send SMS code
func (s *SMSService) SendCode(phoneNumber, code string) error {
	fromNumber := os.Getenv("TWILIO_FROM_NUMBER")
	if fromNumber == "" {
		fromNumber = "+1234567890" // Default for testing
	}

	message := fmt.Sprintf("Your AuthSec verification code is: %s. This code expires in 5 minutes.", code)

	// Mock mode for testing
	if s.client == nil {
		log.Printf("[MOCK SMS] To: %s, Code: %s", phoneNumber, code)
		return nil
	}

	// Real SMS sending
	params := &api.CreateMessageParams{}
	params.SetTo(phoneNumber)
	params.SetFrom(fromNumber)
	params.SetBody(message)

	_, err := s.client.Api.CreateMessage(params)
	if err != nil {
		log.Printf("Failed to send SMS: %v", err)
		return err
	}

	log.Printf("SMS sent to %s", phoneNumber)
	return nil
}

// Validate phone number format
func (s *SMSService) ValidatePhoneNumber(phoneNumber string) bool {
	// Basic E.164 format validation
	if len(phoneNumber) < 10 || len(phoneNumber) > 15 {
		return false
	}

	if phoneNumber[0] != '+' {
		return false
	}

	// Check if rest are digits
	for _, char := range phoneNumber[1:] {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// Format phone number for display (mask middle digits)
func (s *SMSService) FormatPhoneForDisplay(phoneNumber string) string {
	if len(phoneNumber) < 8 {
		return phoneNumber
	}

	// +1234567890 -> +123***7890
	start := phoneNumber[:4]
	end := phoneNumber[len(phoneNumber)-4:]
	return start + "***" + end
}
