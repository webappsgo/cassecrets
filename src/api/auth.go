package api

import (
	"net/http"
	"time"

	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/repository"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	jwtManager     *auth.JWTManager
	sessionManager *auth.SessionManager
	apiKeyRepo     *auth.APIKeyRepository
	userRepo       *repository.UserRepository
	auditRepo      *repository.AuditRepository
	rateLimiter    *auth.RateLimiter
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(cfg *Config) *AuthHandler {
	return &AuthHandler{
		jwtManager:     cfg.JWTManager,
		sessionManager: cfg.SessionManager,
		apiKeyRepo:     cfg.APIKeyRepo,
		userRepo:       cfg.UserRepo,
		auditRepo:      cfg.AuditRepo,
		rateLimiter:    cfg.RateLimiter,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	User         *UserInfo `json:"user"`
}

// UserInfo represents user information in responses
type UserInfo struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	UserType  string `json:"user_type"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	clientIP := auth.GetClientIP(r)

	// Rate limiting
	if h.rateLimiter != nil && !h.rateLimiter.Allow("login", clientIP) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many login attempts")
		return
	}

	var req LoginRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeBadRequest(w, "Email and password are required")
		return
	}

	// Authenticate user
	user, err := h.userRepo.Authenticate(req.Email, req.Password)
	if err != nil || user == nil {
		// Log failed attempt
		if h.auditRepo != nil {
			h.auditRepo.LogAuth("login_failed", 0, "user", req.Email, clientIP, r.UserAgent(), false, "Invalid credentials")
		}
		writeUnauthorized(w, "Invalid email or password")
		return
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		writeError(w, http.StatusForbidden, "ACCOUNT_LOCKED", "Account is temporarily locked")
		return
	}

	// Generate tokens
	accessToken, err := h.jwtManager.GenerateAccessToken(user.ID, "user", []string{"secrets:read", "secrets:write"}, 15*time.Minute)
	if err != nil {
		writeInternalError(w, "Failed to generate access token")
		return
	}

	refreshToken, err := h.jwtManager.GenerateRefreshToken(user.ID, "user", 7*24*time.Hour)
	if err != nil {
		writeInternalError(w, "Failed to generate refresh token")
		return
	}

	// Record successful login
	h.userRepo.RecordLoginSuccess(user.ID, clientIP)

	// Log successful login
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("login", user.ID, "user", req.Email, clientIP, r.UserAgent(), true, "")
	}

	writeSuccess(w, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes
		User: &UserInfo{
			ID:       user.ID,
			Email:    user.Email,
			Name:     user.Name,
			UserType: "user",
		},
	})
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	clientIP := auth.GetClientIP(r)

	// Rate limiting
	if h.rateLimiter != nil && !h.rateLimiter.Allow("register", clientIP) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many registration attempts")
		return
	}

	var req RegisterRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		writeBadRequest(w, "Email, password, and name are required")
		return
	}

	// Check password strength
	if len(req.Password) < 8 {
		writeBadRequest(w, "Password must be at least 8 characters")
		return
	}

	// Create user
	user, err := h.userRepo.Create(req.Email, req.Password, req.Name)
	if err != nil {
		if err.Error() == "email already exists" {
			writeConflict(w, "Email already registered")
			return
		}
		writeInternalError(w, "Failed to create user")
		return
	}

	// Log registration
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("register", user.ID, "user", req.Email, clientIP, r.UserAgent(), true, "")
	}

	// Generate tokens
	accessToken, err := h.jwtManager.GenerateAccessToken(user.ID, "user", []string{"secrets:read", "secrets:write"}, 15*time.Minute)
	if err != nil {
		writeInternalError(w, "Failed to generate access token")
		return
	}

	refreshToken, err := h.jwtManager.GenerateRefreshToken(user.ID, "user", 7*24*time.Hour)
	if err != nil {
		writeInternalError(w, "Failed to generate refresh token")
		return
	}

	writeCreated(w, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
		User: &UserInfo{
			ID:       user.ID,
			Email:    user.Email,
			Name:     user.Name,
			UserType: "user",
		},
	})
}

// Refresh handles token refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	var req RefreshRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeBadRequest(w, "Refresh token is required")
		return
	}

	// Validate refresh token
	claims, err := h.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		writeUnauthorized(w, "Invalid or expired refresh token")
		return
	}

	if claims.TokenType != auth.TokenTypeRefresh {
		writeUnauthorized(w, "Invalid token type")
		return
	}

	// Get user to ensure they still exist and are active
	user, err := h.userRepo.GetByID(claims.UserID)
	if err != nil || user == nil {
		writeUnauthorized(w, "User not found")
		return
	}

	// Generate new access token
	accessToken, err := h.jwtManager.GenerateAccessToken(user.ID, "user", []string{"secrets:read", "secrets:write"}, 15*time.Minute)
	if err != nil {
		writeInternalError(w, "Failed to generate access token")
		return
	}

	writeSuccess(w, map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   900,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	// Get claims from context
	claims := auth.GetClaimsFromContext(r.Context())
	if claims != nil && h.auditRepo != nil {
		h.auditRepo.LogAuth("logout", claims.UserID, claims.UserType, "", auth.GetClientIP(r), r.UserAgent(), true, "")
	}

	// For JWT-based auth, logout is handled client-side by discarding tokens
	// Server-side we just acknowledge the request
	writeSuccess(w, map[string]string{
		"message": "Logged out successfully",
	})
}

// Me returns the current user's information
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	user, err := h.userRepo.GetByID(claims.UserID)
	if err != nil || user == nil {
		writeNotFound(w, "User not found")
		return
	}

	writeSuccess(w, UserInfo{
		ID:       user.ID,
		Email:    user.Email,
		Name:     user.Name,
		UserType: "user",
	})
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword handles password change
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeBadRequest(w, "Current and new passwords are required")
		return
	}

	if len(req.NewPassword) < 8 {
		writeBadRequest(w, "New password must be at least 8 characters")
		return
	}

	// Verify current password
	user, err := h.userRepo.GetByID(claims.UserID)
	if err != nil || user == nil {
		writeNotFound(w, "User not found")
		return
	}

	// Authenticate with current password
	_, err = h.userRepo.Authenticate(user.Email, req.CurrentPassword)
	if err != nil {
		writeUnauthorized(w, "Current password is incorrect")
		return
	}

	// Update password
	if err := h.userRepo.UpdatePassword(claims.UserID, req.NewPassword); err != nil {
		writeInternalError(w, "Failed to update password")
		return
	}

	// Log password change
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("password_change", claims.UserID, claims.UserType, user.Email, auth.GetClientIP(r), r.UserAgent(), true, "")
	}

	writeSuccess(w, map[string]string{
		"message": "Password changed successfully",
	})
}
