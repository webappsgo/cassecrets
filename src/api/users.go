package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/repository"
)

// UsersHandler handles user endpoints
type UsersHandler struct {
	userRepo    *repository.UserRepository
	teamRepo    *repository.TeamRepository
	auditRepo   *repository.AuditRepository
	rateLimiter *auth.RateLimiter
}

// NewUsersHandler creates a new users handler
func NewUsersHandler(cfg *Config) *UsersHandler {
	return &UsersHandler{
		userRepo:    cfg.UserRepo,
		teamRepo:    cfg.TeamRepo,
		auditRepo:   cfg.AuditRepo,
		rateLimiter: cfg.RateLimiter,
	}
}

// UserResponse represents a user response
type UserResponse struct {
	ID            int64      `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastLogin     *time.Time `json:"last_login,omitempty"`
}

// UpdateUserRequest represents a user update request
type UpdateUserRequest struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// Get retrieves user information
func (h *UsersHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get user ID from path or use current user
	idStr := getPathParam(r, "id")
	var userID int64
	if idStr == "" || idStr == "me" {
		userID = claims.UserID
	} else {
		var err error
		userID, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeBadRequest(w, "Invalid user ID")
			return
		}
	}

	// Only allow viewing own profile unless admin
	if userID != claims.UserID && claims.UserType != "admin" {
		writeForbidden(w, "Cannot view other users' profiles")
		return
	}

	user, err := h.userRepo.GetByID(userID)
	if err != nil {
		writeInternalError(w, "Failed to get user")
		return
	}
	if user == nil {
		writeNotFound(w, "User not found")
		return
	}

	writeSuccess(w, UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		LastLogin:     user.LastLogin,
	})
}

// Update updates user information
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT or PATCH required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get user ID from path or use current user
	idStr := getPathParam(r, "id")
	var userID int64
	if idStr == "" || idStr == "me" {
		userID = claims.UserID
	} else {
		var err error
		userID, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeBadRequest(w, "Invalid user ID")
			return
		}
	}

	// Only allow updating own profile unless admin
	if userID != claims.UserID && claims.UserType != "admin" {
		writeForbidden(w, "Cannot update other users' profiles")
		return
	}

	var req UpdateUserRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	user, err := h.userRepo.GetByID(userID)
	if err != nil {
		writeInternalError(w, "Failed to get user")
		return
	}
	if user == nil {
		writeNotFound(w, "User not found")
		return
	}

	// Update fields
	if req.Name != "" {
		user.Name = req.Name
	}
	// Email changes might require verification
	if req.Email != "" && req.Email != user.Email {
		// For now, just update it. In production, you'd want to verify the new email
		user.Email = req.Email
		user.EmailVerified = false
	}

	if err := h.userRepo.Update(user); err != nil {
		writeInternalError(w, "Failed to update user")
		return
	}

	writeSuccess(w, UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		LastLogin:     user.LastLogin,
	})
}

// Delete deletes a user account
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get user ID from path or use current user
	idStr := getPathParam(r, "id")
	var userID int64
	if idStr == "" || idStr == "me" {
		userID = claims.UserID
	} else {
		var err error
		userID, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeBadRequest(w, "Invalid user ID")
			return
		}
	}

	// Only allow deleting own account unless admin
	if userID != claims.UserID && claims.UserType != "admin" {
		writeForbidden(w, "Cannot delete other users' accounts")
		return
	}

	// Check if user owns any teams
	teams, err := h.teamRepo.ListByUser(userID)
	if err != nil {
		writeInternalError(w, "Failed to check user's teams")
		return
	}

	for _, team := range teams {
		if team.OwnerID == userID {
			writeBadRequest(w, "Cannot delete account while owning teams. Transfer ownership first.")
			return
		}
	}

	if err := h.userRepo.Delete(userID); err != nil {
		writeInternalError(w, "Failed to delete user")
		return
	}

	// Log deletion
	if h.auditRepo != nil {
		h.auditRepo.LogAuth("account_deleted", userID, claims.UserType, "", auth.GetClientIP(r), r.UserAgent(), true, "")
	}

	writeSuccess(w, map[string]string{
		"message": "Account deleted successfully",
	})
}

// ListTeams lists teams the user belongs to
func (h *UsersHandler) ListTeams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	teams, err := h.teamRepo.ListByUser(claims.UserID)
	if err != nil {
		writeInternalError(w, "Failed to list teams")
		return
	}

	results := make([]TeamResponse, len(teams))
	for i, t := range teams {
		results[i] = TeamResponse{
			ID:          t.ID,
			Name:        t.Name,
			Slug:        t.Slug,
			Description: t.Description,
			OwnerID:     t.OwnerID,
			CreatedAt:   t.CreatedAt,
			UpdatedAt:   t.UpdatedAt,
		}
	}

	writeSuccess(w, results)
}
