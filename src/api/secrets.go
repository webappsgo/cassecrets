package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/models"
	"github.com/casapps/cassecrets/src/repository"
)

// SecretsHandler handles secret endpoints
type SecretsHandler struct {
	secretRepo  *repository.SecretRepository
	teamRepo    *repository.TeamRepository
	auditRepo   *repository.AuditRepository
	rateLimiter *auth.RateLimiter
}

// NewSecretsHandler creates a new secrets handler
func NewSecretsHandler(cfg *Config) *SecretsHandler {
	return &SecretsHandler{
		secretRepo:  cfg.SecretRepo,
		teamRepo:    cfg.TeamRepo,
		auditRepo:   cfg.AuditRepo,
		rateLimiter: cfg.RateLimiter,
	}
}

// SecretRequest represents a secret create/update request
type SecretRequest struct {
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecretResponse represents a secret response
type SecretResponse struct {
	ID          int64             `json:"id"`
	TeamID      int64             `json:"team_id"`
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Value       string            `json:"value,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   int64             `json:"created_by"`
	UpdatedBy   int64             `json:"updated_by"`
}

// SecretVersionResponse represents a secret version
type SecretVersionResponse struct {
	Version   int       `json:"version"`
	Value     string    `json:"value,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy int64     `json:"created_by"`
}

// List lists secrets for a team
func (h *SecretsHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID from query or path
	teamID := getQueryInt64(r, "team_id", 0)
	if teamID == 0 {
		// Try to get from path
		teamIDStr := getPathParam(r, "team_id")
		if teamIDStr != "" {
			teamID, _ = strconv.ParseInt(teamIDStr, 10, 64)
		}
	}

	if teamID == 0 {
		writeBadRequest(w, "Team ID is required")
		return
	}

	// Check team membership
	if !h.hasTeamAccess(claims.UserID, teamID) {
		writeForbidden(w, "Access denied to team")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:read") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// List secrets
	secrets, err := h.secretRepo.ListByTeam(teamID)
	if err != nil {
		writeInternalError(w, "Failed to list secrets")
		return
	}

	// Convert to response format (without values for list)
	results := make([]SecretResponse, len(secrets))
	for i, s := range secrets {
		results[i] = SecretResponse{
			ID:          s.ID,
			TeamID:      s.TeamID,
			Path:        s.Path,
			Type:        string(s.Type),
			Description: s.Description,
			Tags:        s.Tags,
			Metadata:    s.Metadata,
			Version:     s.Version,
			CreatedAt:   s.CreatedAt,
			UpdatedAt:   s.UpdatedAt,
			CreatedBy:   s.CreatedBy,
			UpdatedBy:   s.UpdatedBy,
		}
	}

	writeSuccess(w, results)
}

// Get retrieves a single secret
func (h *SecretsHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get secret ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid secret ID")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:read") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// Get secret
	secret, err := h.secretRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get secret")
		return
	}
	if secret == nil {
		writeNotFound(w, "Secret not found")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, secret.TeamID) {
		writeForbidden(w, "Access denied to secret")
		return
	}

	// Log access
	if h.auditRepo != nil {
		h.auditRepo.LogSecretRead(secret.ID, secret.Path, secret.TeamID, claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent())
	}

	writeSuccess(w, SecretResponse{
		ID:          secret.ID,
		TeamID:      secret.TeamID,
		Path:        secret.Path,
		Type:        string(secret.Type),
		Value:       secret.Value,
		Description: secret.Description,
		Tags:        secret.Tags,
		Metadata:    secret.Metadata,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
	})
}

// GetByPath retrieves a secret by path
func (h *SecretsHandler) GetByPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	teamID := getQueryInt64(r, "team_id", 0)
	path := getQueryString(r, "path", "")

	if teamID == 0 || path == "" {
		writeBadRequest(w, "Team ID and path are required")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, teamID) {
		writeForbidden(w, "Access denied to team")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:read") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// Get secret
	secret, err := h.secretRepo.GetByPath(teamID, path)
	if err != nil {
		writeInternalError(w, "Failed to get secret")
		return
	}
	if secret == nil {
		writeNotFound(w, "Secret not found")
		return
	}

	// Log access
	if h.auditRepo != nil {
		h.auditRepo.LogSecretRead(secret.ID, secret.Path, secret.TeamID, claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent())
	}

	writeSuccess(w, SecretResponse{
		ID:          secret.ID,
		TeamID:      secret.TeamID,
		Path:        secret.Path,
		Type:        string(secret.Type),
		Value:       secret.Value,
		Description: secret.Description,
		Tags:        secret.Tags,
		Metadata:    secret.Metadata,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
	})
}

// Create creates a new secret
func (h *SecretsHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID from query or path
	teamID := getQueryInt64(r, "team_id", 0)
	if teamID == 0 {
		teamIDStr := getPathParam(r, "team_id")
		if teamIDStr != "" {
			teamID, _ = strconv.ParseInt(teamIDStr, 10, 64)
		}
	}

	if teamID == 0 {
		writeBadRequest(w, "Team ID is required")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, teamID) {
		writeForbidden(w, "Access denied to team")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:write") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	var req SecretRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Path == "" || req.Value == "" {
		writeBadRequest(w, "Path and value are required")
		return
	}

	// Validate path
	if !isValidSecretPath(req.Path) {
		writeBadRequest(w, "Invalid secret path format")
		return
	}

	// Default type
	if req.Type == "" {
		req.Type = "string"
	}

	// Create secret
	secret := &models.Secret{
		TeamID:      teamID,
		Path:        req.Path,
		Type:        models.SecretType(req.Type),
		Value:       req.Value,
		Description: req.Description,
		Tags:        req.Tags,
		Metadata:    req.Metadata,
		CreatedBy:   claims.UserID,
		UpdatedBy:   claims.UserID,
	}

	if err := h.secretRepo.Create(secret); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeConflict(w, "Secret with this path already exists")
			return
		}
		writeInternalError(w, "Failed to create secret")
		return
	}

	// Log creation
	if h.auditRepo != nil {
		h.auditRepo.LogSecretCreate(secret.ID, secret.Path, secret.TeamID, claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent())
	}

	writeCreated(w, SecretResponse{
		ID:          secret.ID,
		TeamID:      secret.TeamID,
		Path:        secret.Path,
		Type:        string(secret.Type),
		Description: secret.Description,
		Tags:        secret.Tags,
		Metadata:    secret.Metadata,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
	})
}

// Update updates an existing secret
func (h *SecretsHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT or PATCH required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get secret ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid secret ID")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:write") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// Get existing secret
	secret, err := h.secretRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get secret")
		return
	}
	if secret == nil {
		writeNotFound(w, "Secret not found")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, secret.TeamID) {
		writeForbidden(w, "Access denied to secret")
		return
	}

	var req SecretRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	// Update fields
	if req.Value != "" {
		secret.Value = req.Value
	}
	if req.Description != "" {
		secret.Description = req.Description
	}
	if req.Tags != nil {
		secret.Tags = req.Tags
	}
	if req.Metadata != nil {
		secret.Metadata = req.Metadata
	}
	secret.UpdatedBy = claims.UserID

	if err := h.secretRepo.Update(secret); err != nil {
		writeInternalError(w, "Failed to update secret")
		return
	}

	// Log update
	if h.auditRepo != nil {
		h.auditRepo.LogSecretUpdate(secret.ID, secret.Path, secret.TeamID, claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent())
	}

	writeSuccess(w, SecretResponse{
		ID:          secret.ID,
		TeamID:      secret.TeamID,
		Path:        secret.Path,
		Type:        string(secret.Type),
		Description: secret.Description,
		Tags:        secret.Tags,
		Metadata:    secret.Metadata,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
	})
}

// Delete deletes a secret
func (h *SecretsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get secret ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid secret ID")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:delete") && !claims.HasScope("secrets:write") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// Get existing secret
	secret, err := h.secretRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get secret")
		return
	}
	if secret == nil {
		writeNotFound(w, "Secret not found")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, secret.TeamID) {
		writeForbidden(w, "Access denied to secret")
		return
	}

	if err := h.secretRepo.Delete(id); err != nil {
		writeInternalError(w, "Failed to delete secret")
		return
	}

	// Log deletion
	if h.auditRepo != nil {
		h.auditRepo.LogSecretDelete(secret.ID, secret.Path, secret.TeamID, claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent())
	}

	writeSuccess(w, map[string]string{
		"message": "Secret deleted successfully",
	})
}

// GetVersions lists all versions of a secret
func (h *SecretsHandler) GetVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get secret ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid secret ID")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:read") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// Get secret to check access
	secret, err := h.secretRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get secret")
		return
	}
	if secret == nil {
		writeNotFound(w, "Secret not found")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, secret.TeamID) {
		writeForbidden(w, "Access denied to secret")
		return
	}

	// Get versions
	versions, err := h.secretRepo.GetVersions(id)
	if err != nil {
		writeInternalError(w, "Failed to get versions")
		return
	}

	// Convert to response (without values unless specifically requested)
	includeValues := getQueryBool(r, "include_values", false)
	results := make([]SecretVersionResponse, len(versions))
	for i, v := range versions {
		results[i] = SecretVersionResponse{
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
		}
		if includeValues {
			results[i].Value = v.Value
		}
	}

	writeSuccess(w, results)
}

// Rollback rolls back to a previous version
func (h *SecretsHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get secret ID from path
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid secret ID")
		return
	}

	// Get version from query or body
	version := getQueryInt(r, "version", 0)
	if version == 0 {
		var req struct {
			Version int `json:"version"`
		}
		if err := parseJSON(r, &req); err == nil {
			version = req.Version
		}
	}

	if version == 0 {
		writeBadRequest(w, "Version is required")
		return
	}

	// Check scope
	if !claims.HasScope("secrets:write") && !claims.HasScope("*") {
		writeForbidden(w, "Insufficient permissions")
		return
	}

	// Get secret to check access
	secret, err := h.secretRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get secret")
		return
	}
	if secret == nil {
		writeNotFound(w, "Secret not found")
		return
	}

	// Check team access
	if !h.hasTeamAccess(claims.UserID, secret.TeamID) {
		writeForbidden(w, "Access denied to secret")
		return
	}

	// Rollback
	if err := h.secretRepo.Rollback(id, version, claims.UserID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeNotFound(w, "Version not found")
			return
		}
		writeInternalError(w, "Failed to rollback")
		return
	}

	// Get updated secret
	secret, _ = h.secretRepo.GetByID(id)

	// Log rollback
	if h.auditRepo != nil {
		h.auditRepo.LogSecretUpdate(secret.ID, secret.Path, secret.TeamID, claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent())
	}

	writeSuccess(w, SecretResponse{
		ID:          secret.ID,
		TeamID:      secret.TeamID,
		Path:        secret.Path,
		Type:        string(secret.Type),
		Description: secret.Description,
		Tags:        secret.Tags,
		Metadata:    secret.Metadata,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
	})
}

// hasTeamAccess checks if a user has access to a team
func (h *SecretsHandler) hasTeamAccess(userID, teamID int64) bool {
	if h.teamRepo == nil {
		return true // No team repo means no access control
	}

	// Check if user is a member of the team
	members, err := h.teamRepo.GetMembers(teamID)
	if err != nil {
		return false
	}

	for _, m := range members {
		if m.UserID == userID {
			return true
		}
	}

	return false
}

// isValidSecretPath validates secret path format
func isValidSecretPath(path string) bool {
	if path == "" || len(path) > 512 {
		return false
	}

	// Path should start with /
	if path[0] != '/' {
		return false
	}

	// No double slashes
	if strings.Contains(path, "//") {
		return false
	}

	// Only allowed characters
	for _, c := range path {
		if !isValidPathChar(c) {
			return false
		}
	}

	return true
}

func isValidPathChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '/' || c == '-' || c == '_' || c == '.'
}
