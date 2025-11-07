package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/authnull0/mfa-service/models/dto"
	"golang.org/x/crypto/argon2"
)

var encryptionKey []byte

// GetEncryptionKey returns the encryption key, generating one if needed
func GetEncryptionKey() []byte {
	if encryptionKey != nil {
		return encryptionKey
	}

	keyHex := os.Getenv("TOTP_ENCRYPTION_KEY")
	if keyHex == "" {
		// Auto-generate a secure key for development
		log.Println(" TOTP_ENCRYPTION_KEY not set, generating a random key...")
		generatedKey := generateSecureKey()
		keyHex = hex.EncodeToString(generatedKey)
		log.Printf(" Generated key (set this in production): TOTP_ENCRYPTION_KEY=%s", keyHex)
		log.Println(" This key will change on server restart! Set TOTP_ENCRYPTION_KEY environment variable for persistence.")
		encryptionKey = generatedKey
		return encryptionKey
	}

	// Decode hex key from environment
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatalf(" Invalid TOTP_ENCRYPTION_KEY format: %v", err)
	}

	if len(key) != 32 {
		log.Fatalf(" TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters), got %d bytes", len(key))
	}

	encryptionKey = key
	log.Println("Using TOTP encryption key from environment variable")
	return encryptionKey
}

// generateSecureKey creates a cryptographically secure 32-byte key
func generateSecureKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf(" Failed to generate secure key: %v", err)
	}
	return key
}

// Rest of your existing encryption functions...
func EncryptString(plaintext string) (string, error) {
	key := GetEncryptionKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptString(ciphertext string) (string, error) {
	key := GetEncryptionKey()

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
func ComparePasswordAndHash(password, encodedHash string) (match bool, err error) {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
func decodeHash(encodedHash string) (p *dto.Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, err
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, err
	}

	p = &dto.Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}
