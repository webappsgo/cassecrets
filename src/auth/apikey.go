package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/casapps/cassecrets/src/crypto"
)

const (
	// API key prefixes
	APIKeyPrefixApp   = "cassecrets_"
	APIKeyPrefixAdmin = "adm_"
	APIKeyPrefixUser  = "key_"
)

// APIKey represents an API key
type APIKey struct {
	ID        int64     `json:"id"`
	KeyPrefix string    `json:"key_prefix"`
	Name      string    `json:"name"`
	OwnerType string    `json:"owner_type"`
	OwnerID   int64     `json:"owner_id"`
	Scopes    []string  `json:"scopes,omitempty"`
	RateLimit int       `json:"rate_limit,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	UseCount  int       `json:"use_count"`
}

// APIKeyRepository handles API key storage operations
type APIKeyRepository struct {
	db *sql.DB
}

// NewAPIKeyRepository creates a new API key repository
func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// CreateKey creates a new API key and returns the full key (only returned once)
func (r *APIKeyRepository) CreateKey(ownerType string, ownerID int64, name string, scopes []string, expiresAt time.Time) (*APIKey, string, error) {
	// Generate random key
	keyBytes := make([]byte, 24)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", fmt.Errorf("generating key: %w", err)
	}

	// Determine prefix based on owner type
	var prefix string
	switch ownerType {
	case "admin":
		prefix = APIKeyPrefixAdmin
	case "user":
		prefix = APIKeyPrefixUser
	default:
		prefix = APIKeyPrefixApp
	}

	// Create full key
	fullKey := prefix + base64.RawURLEncoding.EncodeToString(keyBytes)

	// Create hash for storage
	keyHash := crypto.HashToken(fullKey)

	// Get prefix for display (first 8 chars after prefix)
	keyPrefix := fullKey[:len(prefix)+8] + "..."

	// Convert scopes to JSON
	scopesJSON, _ := json.Marshal(scopes)

	var expiresAtUnix sql.NullInt64
	if !expiresAt.IsZero() {
		expiresAtUnix.Int64 = expiresAt.Unix()
		expiresAtUnix.Valid = true
	}

	query := `
		INSERT INTO api_keys (key_hash, key_prefix, name, owner_type, owner_id, scopes, enabled, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, strftime('%s', 'now'), ?)
	`

	result, err := r.db.Exec(query, keyHash, keyPrefix, name, ownerType, ownerID, string(scopesJSON), expiresAtUnix)
	if err != nil {
		return nil, "", fmt.Errorf("inserting API key: %w", err)
	}

	id, _ := result.LastInsertId()

	apiKey := &APIKey{
		ID:        id,
		KeyPrefix: keyPrefix,
		Name:      name,
		OwnerType: ownerType,
		OwnerID:   ownerID,
		Scopes:    scopes,
		Enabled:   true,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	return apiKey, fullKey, nil
}

// ValidateKey validates an API key and returns the key info if valid
func (r *APIKeyRepository) ValidateKey(key string) (*APIKey, error) {
	keyHash := crypto.HashToken(key)

	query := `
		SELECT id, key_prefix, name, owner_type, owner_id, scopes, rate_limit, enabled, created_at, expires_at, last_used, use_count
		FROM api_keys
		WHERE key_hash = ? AND enabled = 1
	`

	var apiKey APIKey
	var scopesJSON string
	var createdAt int64
	var expiresAt, lastUsed sql.NullInt64
	var rateLimit sql.NullInt64

	err := r.db.QueryRow(query, keyHash).Scan(
		&apiKey.ID, &apiKey.KeyPrefix, &apiKey.Name, &apiKey.OwnerType, &apiKey.OwnerID,
		&scopesJSON, &rateLimit, &apiKey.Enabled, &createdAt, &expiresAt, &lastUsed, &apiKey.UseCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying API key: %w", err)
	}

	// Check expiration
	if expiresAt.Valid && expiresAt.Int64 < time.Now().Unix() {
		return nil, nil
	}

	// Parse scopes
	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &apiKey.Scopes)
	}

	// Convert timestamps
	apiKey.CreatedAt = time.Unix(createdAt, 0)
	if expiresAt.Valid {
		apiKey.ExpiresAt = time.Unix(expiresAt.Int64, 0)
	}
	if lastUsed.Valid {
		apiKey.LastUsed = time.Unix(lastUsed.Int64, 0)
	}
	if rateLimit.Valid {
		apiKey.RateLimit = int(rateLimit.Int64)
	}

	// Update last used and use count
	r.db.Exec("UPDATE api_keys SET last_used = strftime('%s', 'now'), use_count = use_count + 1 WHERE id = ?", apiKey.ID)

	return &apiKey, nil
}

// GetByID retrieves an API key by ID
func (r *APIKeyRepository) GetByID(id int64) (*APIKey, error) {
	query := `
		SELECT id, key_prefix, name, owner_type, owner_id, scopes, rate_limit, enabled, created_at, expires_at, last_used, use_count
		FROM api_keys
		WHERE id = ?
	`

	var apiKey APIKey
	var scopesJSON string
	var createdAt int64
	var expiresAt, lastUsed sql.NullInt64
	var rateLimit sql.NullInt64

	err := r.db.QueryRow(query, id).Scan(
		&apiKey.ID, &apiKey.KeyPrefix, &apiKey.Name, &apiKey.OwnerType, &apiKey.OwnerID,
		&scopesJSON, &rateLimit, &apiKey.Enabled, &createdAt, &expiresAt, &lastUsed, &apiKey.UseCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying API key: %w", err)
	}

	// Parse scopes
	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &apiKey.Scopes)
	}

	// Convert timestamps
	apiKey.CreatedAt = time.Unix(createdAt, 0)
	if expiresAt.Valid {
		apiKey.ExpiresAt = time.Unix(expiresAt.Int64, 0)
	}
	if lastUsed.Valid {
		apiKey.LastUsed = time.Unix(lastUsed.Int64, 0)
	}
	if rateLimit.Valid {
		apiKey.RateLimit = int(rateLimit.Int64)
	}

	return &apiKey, nil
}

// ListByOwner lists all API keys for an owner
func (r *APIKeyRepository) ListByOwner(ownerType string, ownerID int64) ([]*APIKey, error) {
	query := `
		SELECT id, key_prefix, name, owner_type, owner_id, scopes, rate_limit, enabled, created_at, expires_at, last_used, use_count
		FROM api_keys
		WHERE owner_type = ? AND owner_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, ownerType, ownerID)
	if err != nil {
		return nil, fmt.Errorf("querying API keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var apiKey APIKey
		var scopesJSON string
		var createdAt int64
		var expiresAt, lastUsed sql.NullInt64
		var rateLimit sql.NullInt64

		err := rows.Scan(
			&apiKey.ID, &apiKey.KeyPrefix, &apiKey.Name, &apiKey.OwnerType, &apiKey.OwnerID,
			&scopesJSON, &rateLimit, &apiKey.Enabled, &createdAt, &expiresAt, &lastUsed, &apiKey.UseCount,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning API key: %w", err)
		}

		if scopesJSON != "" {
			json.Unmarshal([]byte(scopesJSON), &apiKey.Scopes)
		}

		apiKey.CreatedAt = time.Unix(createdAt, 0)
		if expiresAt.Valid {
			apiKey.ExpiresAt = time.Unix(expiresAt.Int64, 0)
		}
		if lastUsed.Valid {
			apiKey.LastUsed = time.Unix(lastUsed.Int64, 0)
		}
		if rateLimit.Valid {
			apiKey.RateLimit = int(rateLimit.Int64)
		}

		keys = append(keys, &apiKey)
	}

	return keys, nil
}

// Delete deletes an API key
func (r *APIKeyRepository) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM api_keys WHERE id = ?", id)
	return err
}

// Disable disables an API key
func (r *APIKeyRepository) Disable(id int64) error {
	_, err := r.db.Exec("UPDATE api_keys SET enabled = 0 WHERE id = ?", id)
	return err
}

// Enable enables an API key
func (r *APIKeyRepository) Enable(id int64) error {
	_, err := r.db.Exec("UPDATE api_keys SET enabled = 1 WHERE id = ?", id)
	return err
}

// UpdateName updates the name of an API key
func (r *APIKeyRepository) UpdateName(id int64, name string) error {
	_, err := r.db.Exec("UPDATE api_keys SET name = ? WHERE id = ?", name, id)
	return err
}

// UpdateScopes updates the scopes of an API key
func (r *APIKeyRepository) UpdateScopes(id int64, scopes []string) error {
	scopesJSON, _ := json.Marshal(scopes)
	_, err := r.db.Exec("UPDATE api_keys SET scopes = ? WHERE id = ?", string(scopesJSON), id)
	return err
}

// RotateKey creates a new key and disables the old one
func (r *APIKeyRepository) RotateKey(id int64) (*APIKey, string, error) {
	// Get the old key
	oldKey, err := r.GetByID(id)
	if err != nil || oldKey == nil {
		return nil, "", fmt.Errorf("key not found")
	}

	// Create new key with same settings
	newKey, fullKey, err := r.CreateKey(oldKey.OwnerType, oldKey.OwnerID, oldKey.Name+" (rotated)", oldKey.Scopes, oldKey.ExpiresAt)
	if err != nil {
		return nil, "", err
	}

	// Disable old key
	r.Disable(id)

	return newKey, fullKey, nil
}

// CleanupExpiredKeys removes expired API keys
func (r *APIKeyRepository) CleanupExpiredKeys() (int64, error) {
	now := time.Now().Unix()
	result, err := r.db.Exec("DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < ?", now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// HasScope checks if an API key has a specific scope
func (k *APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// GetPrefix returns the appropriate prefix based on owner type
func GetAPIKeyPrefix(ownerType string) string {
	switch ownerType {
	case "admin":
		return APIKeyPrefixAdmin
	case "user":
		return APIKeyPrefixUser
	default:
		return APIKeyPrefixApp
	}
}

// ParseKeyPrefix extracts owner type from key prefix
func ParseKeyPrefix(key string) string {
	switch {
	case strings.HasPrefix(key, APIKeyPrefixAdmin):
		return "admin"
	case strings.HasPrefix(key, APIKeyPrefixUser):
		return "user"
	case strings.HasPrefix(key, APIKeyPrefixApp):
		return "app"
	default:
		return ""
	}
}
