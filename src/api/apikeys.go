package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/repository"
)

// APIKeysHandler handles API key endpoints
type APIKeysHandler struct {
	apiKeyRepo  *auth.APIKeyRepository
	auditRepo   *repository.AuditRepository
	rateLimiter *auth.RateLimiter
}

// NewAPIKeysHandler creates a new API keys handler
func NewAPIKeysHandler(cfg *Config) *APIKeysHandler {
	return &APIKeysHandler{
		apiKeyRepo:  cfg.APIKeyRepo,
		auditRepo:   cfg.AuditRepo,
		rateLimiter: cfg.RateLimiter,
	}
}

// CreateAPIKeyRequest represents an API key creation request
type CreateAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn int      `json:"expires_in,omitempty"` // Duration in days
}

// APIKeyResponse represents an API key response
type APIKeyResponse struct {
	ID        int64      `json:"id"`
	KeyPrefix string     `json:"key_prefix"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes,omitempty"`
	RateLimit int        `json:"rate_limit,omitempty"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	UseCount  int        `json:"use_count"`
	Key       string     `json:"key,omitempty"` // Only returned on creation
}

// List lists API keys for the current user
func (h *APIKeysHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	keys, err := h.apiKeyRepo.ListByOwner(claims.UserType, claims.UserID)
	if err != nil {
		writeInternalError(w, "Failed to list API keys")
		return
	}

	results := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		results[i] = APIKeyResponse{
			ID:        k.ID,
			KeyPrefix: k.KeyPrefix,
			Name:      k.Name,
			Scopes:    k.Scopes,
			RateLimit: k.RateLimit,
			Enabled:   k.Enabled,
			CreatedAt: k.CreatedAt,
			UseCount:  k.UseCount,
		}
		if !k.ExpiresAt.IsZero() {
			results[i].ExpiresAt = &k.ExpiresAt
		}
		if !k.LastUsed.IsZero() {
			results[i].LastUsed = &k.LastUsed
		}
	}

	writeSuccess(w, results)
}

// Create creates a new API key
func (h *APIKeysHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	clientIP := auth.GetClientIP(r)

	// Rate limiting
	if h.rateLimiter != nil && !h.rateLimiter.Allow("api_key_create", clientIP) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many API key creation attempts")
		return
	}

	var req CreateAPIKeyRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeBadRequest(w, "Name is required")
		return
	}

	// Default scopes
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"secrets:read"}
	}

	// Calculate expiration
	var expiresAt time.Time
	if req.ExpiresIn > 0 {
		expiresAt = time.Now().AddDate(0, 0, req.ExpiresIn)
	}

	apiKey, fullKey, err := h.apiKeyRepo.CreateKey(claims.UserType, claims.UserID, req.Name, req.Scopes, expiresAt)
	if err != nil {
		writeInternalError(w, "Failed to create API key")
		return
	}

	// Log creation
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("api_key_created", claims.UserID, claims.UserType, req.Name, clientIP, r.UserAgent(), true, "")
	}

	response := APIKeyResponse{
		ID:        apiKey.ID,
		KeyPrefix: apiKey.KeyPrefix,
		Name:      apiKey.Name,
		Scopes:    apiKey.Scopes,
		Enabled:   apiKey.Enabled,
		CreatedAt: apiKey.CreatedAt,
		UseCount:  0,
		Key:       fullKey, // Only returned on creation
	}
	if !expiresAt.IsZero() {
		response.ExpiresAt = &expiresAt
	}

	writeCreated(w, response)
}

// Get retrieves an API key
func (h *APIKeysHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get key ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid API key ID")
		return
	}

	apiKey, err := h.apiKeyRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get API key")
		return
	}
	if apiKey == nil {
		writeNotFound(w, "API key not found")
		return
	}

	// Verify ownership
	if apiKey.OwnerID != claims.UserID || apiKey.OwnerType != claims.UserType {
		writeForbidden(w, "Access denied")
		return
	}

	response := APIKeyResponse{
		ID:        apiKey.ID,
		KeyPrefix: apiKey.KeyPrefix,
		Name:      apiKey.Name,
		Scopes:    apiKey.Scopes,
		RateLimit: apiKey.RateLimit,
		Enabled:   apiKey.Enabled,
		CreatedAt: apiKey.CreatedAt,
		UseCount:  apiKey.UseCount,
	}
	if !apiKey.ExpiresAt.IsZero() {
		response.ExpiresAt = &apiKey.ExpiresAt
	}
	if !apiKey.LastUsed.IsZero() {
		response.LastUsed = &apiKey.LastUsed
	}

	writeSuccess(w, response)
}

// Delete deletes an API key
func (h *APIKeysHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get key ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid API key ID")
		return
	}

	// Verify ownership
	apiKey, err := h.apiKeyRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get API key")
		return
	}
	if apiKey == nil {
		writeNotFound(w, "API key not found")
		return
	}

	if apiKey.OwnerID != claims.UserID || apiKey.OwnerType != claims.UserType {
		writeForbidden(w, "Access denied")
		return
	}

	if err := h.apiKeyRepo.Delete(id); err != nil {
		writeInternalError(w, "Failed to delete API key")
		return
	}

	// Log deletion
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("api_key_deleted", claims.UserID, claims.UserType, apiKey.Name, auth.GetClientIP(r), r.UserAgent(), true, "")
	}

	writeSuccess(w, map[string]string{
		"message": "API key deleted successfully",
	})
}

// Rotate rotates an API key
func (h *APIKeysHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get key ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid API key ID")
		return
	}

	// Verify ownership
	oldKey, err := h.apiKeyRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get API key")
		return
	}
	if oldKey == nil {
		writeNotFound(w, "API key not found")
		return
	}

	if oldKey.OwnerID != claims.UserID || oldKey.OwnerType != claims.UserType {
		writeForbidden(w, "Access denied")
		return
	}

	// Rotate the key
	newKey, fullKey, err := h.apiKeyRepo.RotateKey(id)
	if err != nil {
		writeInternalError(w, "Failed to rotate API key")
		return
	}

	// Log rotation
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("api_key_rotated", claims.UserID, claims.UserType, oldKey.Name, auth.GetClientIP(r), r.UserAgent(), true, "")
	}

	response := APIKeyResponse{
		ID:        newKey.ID,
		KeyPrefix: newKey.KeyPrefix,
		Name:      newKey.Name,
		Scopes:    newKey.Scopes,
		Enabled:   newKey.Enabled,
		CreatedAt: newKey.CreatedAt,
		UseCount:  0,
		Key:       fullKey, // Return the new key
	}
	if !newKey.ExpiresAt.IsZero() {
		response.ExpiresAt = &newKey.ExpiresAt
	}

	writeSuccess(w, response)
}

// Enable enables an API key
func (h *APIKeysHandler) Enable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get key ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid API key ID")
		return
	}

	// Verify ownership
	apiKey, err := h.apiKeyRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get API key")
		return
	}
	if apiKey == nil {
		writeNotFound(w, "API key not found")
		return
	}

	if apiKey.OwnerID != claims.UserID || apiKey.OwnerType != claims.UserType {
		writeForbidden(w, "Access denied")
		return
	}

	if err := h.apiKeyRepo.Enable(id); err != nil {
		writeInternalError(w, "Failed to enable API key")
		return
	}

	writeSuccess(w, map[string]string{
		"message": "API key enabled successfully",
	})
}

// Disable disables an API key
func (h *APIKeysHandler) Disable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get key ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid API key ID")
		return
	}

	// Verify ownership
	apiKey, err := h.apiKeyRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get API key")
		return
	}
	if apiKey == nil {
		writeNotFound(w, "API key not found")
		return
	}

	if apiKey.OwnerID != claims.UserID || apiKey.OwnerType != claims.UserType {
		writeForbidden(w, "Access denied")
		return
	}

	if err := h.apiKeyRepo.Disable(id); err != nil {
		writeInternalError(w, "Failed to disable API key")
		return
	}

	writeSuccess(w, map[string]string{
		"message": "API key disabled successfully",
	})
}
