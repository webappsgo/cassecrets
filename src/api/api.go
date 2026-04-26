package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/repository"
)

// API holds all API handlers and dependencies
type API struct {
	Auth        *AuthHandler
	Secrets     *SecretsHandler
	Teams       *TeamsHandler
	Users       *UsersHandler
	APIKeys     *APIKeysHandler
	rateLimiter *auth.RateLimiter
}

// Config holds API configuration
type Config struct {
	JWTManager     *auth.JWTManager
	SessionManager *auth.SessionManager
	APIKeyRepo     *auth.APIKeyRepository
	Authenticator  *auth.Authenticator
	RateLimiter    *auth.RateLimiter
	SecretRepo     *repository.SecretRepository
	TeamRepo       *repository.TeamRepository
	UserRepo       *repository.UserRepository
	AuditRepo      *repository.AuditRepository
}

// New creates a new API instance
func New(cfg *Config) *API {
	return &API{
		Auth:        NewAuthHandler(cfg),
		Secrets:     NewSecretsHandler(cfg),
		Teams:       NewTeamsHandler(cfg),
		Users:       NewUsersHandler(cfg),
		APIKeys:     NewAPIKeysHandler(cfg),
		rateLimiter: cfg.RateLimiter,
	}
}

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorInfo  `json:"error,omitempty"`
	Meta    *MetaInfo   `json:"meta,omitempty"`
}

// ErrorInfo represents error details
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MetaInfo represents pagination and other metadata
type MetaInfo struct {
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeSuccess writes a successful response
func writeSuccess(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

// writeSuccessWithMeta writes a successful response with metadata
func writeSuccessWithMeta(w http.ResponseWriter, data interface{}, meta *MetaInfo) {
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// writeCreated writes a created response
func writeCreated(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusCreated, Response{
		Success: true,
		Data:    data,
	})
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, Response{
		Success: false,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
		},
	})
}

// writeBadRequest writes a 400 error
func writeBadRequest(w http.ResponseWriter, message string) {
	writeError(w, http.StatusBadRequest, "BAD_REQUEST", message)
}

// writeUnauthorized writes a 401 error
func writeUnauthorized(w http.ResponseWriter, message string) {
	writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", message)
}

// writeForbidden writes a 403 error
func writeForbidden(w http.ResponseWriter, message string) {
	writeError(w, http.StatusForbidden, "FORBIDDEN", message)
}

// writeNotFound writes a 404 error
func writeNotFound(w http.ResponseWriter, message string) {
	writeError(w, http.StatusNotFound, "NOT_FOUND", message)
}

// writeConflict writes a 409 error
func writeConflict(w http.ResponseWriter, message string) {
	writeError(w, http.StatusConflict, "CONFLICT", message)
}

// writeInternalError writes a 500 error
func writeInternalError(w http.ResponseWriter, message string) {
	writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", message)
}

// parseJSON parses JSON from request body
func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// getPathParam extracts a path parameter (simple implementation)
// In production, use a router that provides this
func getPathParam(r *http.Request, name string) string {
	// This is a placeholder - actual implementation depends on router
	return r.PathValue(name)
}

// getQueryInt gets an integer query parameter with default
func getQueryInt(r *http.Request, name string, defaultVal int) int {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return i
}

// getQueryInt64 gets an int64 query parameter with default
func getQueryInt64(r *http.Request, name string, defaultVal int64) int64 {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultVal
	}
	return i
}

// getQueryString gets a string query parameter with default
func getQueryString(r *http.Request, name, defaultVal string) string {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	return val
}

// getQueryBool gets a boolean query parameter with default
func getQueryBool(r *http.Request, name string, defaultVal bool) bool {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "yes"
}
