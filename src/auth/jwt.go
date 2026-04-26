package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidToken is returned when a token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpiredToken is returned when a token has expired
	ErrExpiredToken = errors.New("token expired")

	// ErrKeyNotLoaded is returned when JWT key is not loaded
	ErrKeyNotLoaded = errors.New("JWT key not loaded")
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeAPI     TokenType = "api"
)

// Claims represents JWT claims
type Claims struct {
	jwt.RegisteredClaims
	UserID    int64     `json:"uid"`
	UserType  string    `json:"utype"`
	TokenType TokenType `json:"ttype"`
	Scopes    []string  `json:"scopes,omitempty"`
	TeamID    int64     `json:"tid,omitempty"`
}

// JWTManager manages JWT token operations
type JWTManager struct {
	secretKey []byte
	keyPath   string
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(keyPath string) *JWTManager {
	return &JWTManager{
		keyPath: keyPath,
	}
}

// LoadOrCreateKey loads the JWT signing key from file or creates a new one
func (m *JWTManager) LoadOrCreateKey() error {
	// Ensure key directory exists
	keyDir := filepath.Dir(m.keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}

	// Try to load existing key
	if data, err := os.ReadFile(m.keyPath); err == nil && len(data) >= 32 {
		m.secretKey = data
		return nil
	}

	// Generate new key (256 bits / 32 bytes)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	// Save key with restrictive permissions
	if err := os.WriteFile(m.keyPath, key, 0600); err != nil {
		return fmt.Errorf("saving key: %w", err)
	}

	m.secretKey = key
	return nil
}

// GenerateAccessToken generates an access token for a user
func (m *JWTManager) GenerateAccessToken(userID int64, userType string, scopes []string, duration time.Duration) (string, error) {
	if m.secretKey == nil {
		return "", ErrKeyNotLoaded
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "cassecrets",
			Subject:   fmt.Sprintf("%s:%d", userType, userID),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
		UserID:    userID,
		UserType:  userType,
		TokenType: TokenTypeAccess,
		Scopes:    scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// GenerateRefreshToken generates a refresh token for a user
func (m *JWTManager) GenerateRefreshToken(userID int64, userType string, duration time.Duration) (string, error) {
	if m.secretKey == nil {
		return "", ErrKeyNotLoaded
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "cassecrets",
			Subject:   fmt.Sprintf("%s:%d", userType, userID),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
		UserID:    userID,
		UserType:  userType,
		TokenType: TokenTypeRefresh,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// GenerateAPIToken generates a long-lived API token
func (m *JWTManager) GenerateAPIToken(userID int64, userType string, scopes []string, expiry time.Time) (string, error) {
	if m.secretKey == nil {
		return "", ErrKeyNotLoaded
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "cassecrets",
			Subject:  fmt.Sprintf("%s:%d", userType, userID),
			IssuedAt: jwt.NewNumericDate(now),
			ID:       generateTokenID(),
		},
		UserID:    userID,
		UserType:  userType,
		TokenType: TokenTypeAPI,
		Scopes:    scopes,
	}

	// Set expiry only if provided (zero time means no expiry)
	if !expiry.IsZero() {
		claims.ExpiresAt = jwt.NewNumericDate(expiry)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// ValidateToken validates a JWT token and returns the claims
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	if m.secretKey == nil {
		return nil, ErrKeyNotLoaded
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// HasScope checks if the claims include a specific scope
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the claims include any of the specified scopes
func (c *Claims) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if c.HasScope(scope) {
			return true
		}
	}
	return false
}

// generateTokenID generates a unique token ID
func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
