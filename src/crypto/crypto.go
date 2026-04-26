package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidKey is returned when the encryption key is invalid
	ErrInvalidKey = errors.New("invalid encryption key")

	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrKeyNotLoaded is returned when trying to encrypt/decrypt before loading key
	ErrKeyNotLoaded = errors.New("encryption key not loaded")
)

// Argon2id parameters (OWASP recommended)
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltLen       = 16
)

// KeyManager manages the master encryption key
type KeyManager struct {
	key     []byte
	keyPath string
	mu      sync.RWMutex
}

// NewKeyManager creates a new key manager
func NewKeyManager(keyPath string) *KeyManager {
	return &KeyManager{
		keyPath: keyPath,
	}
}

// LoadOrCreateKey loads the master key from file or creates a new one
func (km *KeyManager) LoadOrCreateKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Ensure key directory exists
	keyDir := filepath.Dir(km.keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}

	// Try to load existing key
	if data, err := os.ReadFile(km.keyPath); err == nil && len(data) == 32 {
		km.key = data
		return nil
	}

	// Generate new key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	// Save key with restrictive permissions
	if err := os.WriteFile(km.keyPath, key, 0600); err != nil {
		return fmt.Errorf("saving key: %w", err)
	}

	km.key = key
	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func (km *KeyManager) Encrypt(plaintext []byte) (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.key == nil {
		return "", ErrKeyNotLoaded
	}

	block, err := aes.NewCipher(km.key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt and append nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Return base64 encoded
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM
func (km *KeyManager) Decrypt(encoded string) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.key == nil {
		return nil, ErrKeyNotLoaded
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	block, err := aes.NewCipher(km.key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (string, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Encode as: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		Argon2Memory, Argon2Time, Argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))

	return encoded, nil
}

// VerifyPassword verifies a password against an Argon2id hash
func VerifyPassword(password, encoded string) bool {
	// Parse the encoded hash
	var memory, time uint32
	var threads uint8
	var saltB64, hashB64 string

	_, err := fmt.Sscanf(encoded, "$argon2id$v=19$m=%d,t=%d,p=%d$%s",
		&memory, &time, &threads, &saltB64)
	if err != nil {
		return false
	}

	// Split salt and hash (they're separated by $)
	parts := splitLast(saltB64, '$')
	if len(parts) != 2 {
		return false
	}
	saltB64, hashB64 = parts[0], parts[1]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	// Constant-time comparison
	if len(computedHash) != len(expectedHash) {
		return false
	}
	var result byte
	for i := range computedHash {
		result |= computedHash[i] ^ expectedHash[i]
	}
	return result == 0
}

// GenerateToken generates a cryptographically secure random token
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// HashToken hashes a token using SHA-256
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// splitLast splits a string by the last occurrence of sep
func splitLast(s string, sep byte) []string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
