package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/models"
	"github.com/casapps/cassecrets/src/repository"
)

// TeamsHandler handles team endpoints
type TeamsHandler struct {
	teamRepo    *repository.TeamRepository
	userRepo    *repository.UserRepository
	auditRepo   *repository.AuditRepository
	rateLimiter *auth.RateLimiter
}

// NewTeamsHandler creates a new teams handler
func NewTeamsHandler(cfg *Config) *TeamsHandler {
	return &TeamsHandler{
		teamRepo:    cfg.TeamRepo,
		userRepo:    cfg.UserRepo,
		auditRepo:   cfg.AuditRepo,
		rateLimiter: cfg.RateLimiter,
	}
}

// TeamRequest represents a team create/update request
type TeamRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
}

// TeamResponse represents a team response
type TeamResponse struct {
	ID          int64             `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Description string            `json:"description,omitempty"`
	OwnerID     int64             `json:"owner_id"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	MemberCount int               `json:"member_count,omitempty"`
	Role        string            `json:"role,omitempty"`
}

// TeamMemberRequest represents a member add/update request
type TeamMemberRequest struct {
	UserID int64  `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}

// TeamMemberResponse represents a team member
type TeamMemberResponse struct {
	UserID    int64     `json:"user_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	JoinedAt  time.Time `json:"joined_at"`
}

// InvitationRequest represents a team invitation request
type InvitationRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// InvitationResponse represents a team invitation
type InvitationResponse struct {
	ID        int64     `json:"id"`
	TeamID    int64     `json:"team_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Token     string    `json:"token,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// List lists teams for the current user
func (h *TeamsHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// List teams for user
	teams, err := h.teamRepo.ListByUser(claims.UserID)
	if err != nil {
		writeInternalError(w, "Failed to list teams")
		return
	}

	// Convert to response format
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

// Get retrieves a single team
func (h *TeamsHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID or slug from path
	idOrSlug := getPathParam(r, "id")
	if idOrSlug == "" {
		idOrSlug = getPathParam(r, "slug")
	}

	if idOrSlug == "" {
		writeBadRequest(w, "Team ID or slug is required")
		return
	}

	var team *models.Team
	var err error

	// Try as ID first
	if id, parseErr := strconv.ParseInt(idOrSlug, 10, 64); parseErr == nil {
		team, err = h.teamRepo.GetByID(id)
	} else {
		team, err = h.teamRepo.GetBySlug(idOrSlug)
	}

	if err != nil {
		writeInternalError(w, "Failed to get team")
		return
	}
	if team == nil {
		writeNotFound(w, "Team not found")
		return
	}

	// Check if user is a member
	role := h.getUserRole(claims.UserID, team.ID)
	if role == "" {
		writeForbidden(w, "Access denied to team")
		return
	}

	// Get member count
	members, _ := h.teamRepo.GetMembers(team.ID)

	writeSuccess(w, TeamResponse{
		ID:          team.ID,
		Name:        team.Name,
		Slug:        team.Slug,
		Description: team.Description,
		OwnerID:     team.OwnerID,
		CreatedAt:   team.CreatedAt,
		UpdatedAt:   team.UpdatedAt,
		MemberCount: len(members),
		Role:        role,
	})
}

// Create creates a new team
func (h *TeamsHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	var req TeamRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeBadRequest(w, "Team name is required")
		return
	}

	// Generate slug if not provided
	if req.Slug == "" {
		req.Slug = generateSlug(req.Name)
	}

	// Validate slug
	if !isValidSlug(req.Slug) {
		writeBadRequest(w, "Invalid slug format")
		return
	}

	// Create team
	team := &models.Team{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		OwnerID:     claims.UserID,
	}

	if err := h.teamRepo.Create(team); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeConflict(w, "Team with this slug already exists")
			return
		}
		writeInternalError(w, "Failed to create team")
		return
	}

	// Log creation
	if h.auditRepo != nil {
		h.auditRepo.LogEntry(models.AuditCategoryTeam, models.AuditActionCreate,
			claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent(),
			map[string]interface{}{"team_id": team.ID, "team_name": team.Name})
	}

	writeCreated(w, TeamResponse{
		ID:          team.ID,
		Name:        team.Name,
		Slug:        team.Slug,
		Description: team.Description,
		OwnerID:     team.OwnerID,
		CreatedAt:   team.CreatedAt,
		UpdatedAt:   team.UpdatedAt,
		MemberCount: 1,
		Role:        string(models.TeamRoleOwner),
	})
}

// Update updates a team
func (h *TeamsHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT or PATCH required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Get team
	team, err := h.teamRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get team")
		return
	}
	if team == nil {
		writeNotFound(w, "Team not found")
		return
	}

	// Check if user is owner or admin
	role := h.getUserRole(claims.UserID, team.ID)
	if role != string(models.TeamRoleOwner) && role != string(models.TeamRoleAdmin) {
		writeForbidden(w, "Admin or owner access required")
		return
	}

	var req TeamRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	// Update fields
	if req.Name != "" {
		team.Name = req.Name
	}
	if req.Description != "" {
		team.Description = req.Description
	}

	if err := h.teamRepo.Update(team); err != nil {
		writeInternalError(w, "Failed to update team")
		return
	}

	writeSuccess(w, TeamResponse{
		ID:          team.ID,
		Name:        team.Name,
		Slug:        team.Slug,
		Description: team.Description,
		OwnerID:     team.OwnerID,
		CreatedAt:   team.CreatedAt,
		UpdatedAt:   team.UpdatedAt,
	})
}

// Delete deletes a team
func (h *TeamsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Get team
	team, err := h.teamRepo.GetByID(id)
	if err != nil {
		writeInternalError(w, "Failed to get team")
		return
	}
	if team == nil {
		writeNotFound(w, "Team not found")
		return
	}

	// Only owner can delete
	if team.OwnerID != claims.UserID {
		writeForbidden(w, "Only team owner can delete the team")
		return
	}

	if err := h.teamRepo.Delete(id); err != nil {
		writeInternalError(w, "Failed to delete team")
		return
	}

	// Log deletion
	if h.auditRepo != nil {
		h.auditRepo.LogEntry(models.AuditCategoryTeam, models.AuditActionDelete,
			claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent(),
			map[string]interface{}{"team_id": team.ID, "team_name": team.Name})
	}

	writeSuccess(w, map[string]string{
		"message": "Team deleted successfully",
	})
}

// ListMembers lists team members
func (h *TeamsHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Check membership
	role := h.getUserRole(claims.UserID, id)
	if role == "" {
		writeForbidden(w, "Access denied to team")
		return
	}

	// Get members
	members, err := h.teamRepo.GetMembers(id)
	if err != nil {
		writeInternalError(w, "Failed to get members")
		return
	}

	// Get user details for each member
	results := make([]TeamMemberResponse, 0, len(members))
	for _, m := range members {
		user, _ := h.userRepo.GetByID(m.UserID)
		if user != nil {
			results = append(results, TeamMemberResponse{
				UserID:   m.UserID,
				Email:    user.Email,
				Name:     user.Name,
				Role:     string(m.Role),
				JoinedAt: m.JoinedAt,
			})
		}
	}

	writeSuccess(w, results)
}

// AddMember adds a member to a team
func (h *TeamsHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	idStr := getPathParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Check if user is owner or admin
	role := h.getUserRole(claims.UserID, id)
	if role != string(models.TeamRoleOwner) && role != string(models.TeamRoleAdmin) {
		writeForbidden(w, "Admin or owner access required")
		return
	}

	var req TeamMemberRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	// Get user ID from request
	var userID int64
	if req.UserID != 0 {
		userID = req.UserID
	} else if req.Email != "" {
		user, _ := h.userRepo.GetByEmail(req.Email)
		if user == nil {
			writeNotFound(w, "User not found")
			return
		}
		userID = user.ID
	} else {
		writeBadRequest(w, "User ID or email is required")
		return
	}

	// Default role
	if req.Role == "" {
		req.Role = string(models.TeamRoleMember)
	}

	// Validate role
	if !isValidRole(req.Role) {
		writeBadRequest(w, "Invalid role")
		return
	}

	// Add member
	if err := h.teamRepo.AddMember(id, userID, models.TeamRole(req.Role)); err != nil {
		if strings.Contains(err.Error(), "already") {
			writeConflict(w, "User is already a member")
			return
		}
		writeInternalError(w, "Failed to add member")
		return
	}

	user, _ := h.userRepo.GetByID(userID)

	writeCreated(w, TeamMemberResponse{
		UserID:   userID,
		Email:    user.Email,
		Name:     user.Name,
		Role:     req.Role,
		JoinedAt: time.Now(),
	})
}

// UpdateMember updates a member's role
func (h *TeamsHandler) UpdateMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT or PATCH required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	teamIDStr := getPathParam(r, "id")
	teamID, err := strconv.ParseInt(teamIDStr, 10, 64)
	if err != nil || teamID == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Get user ID
	userIDStr := getPathParam(r, "user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || userID == 0 {
		writeBadRequest(w, "Invalid user ID")
		return
	}

	// Check if user is owner or admin
	role := h.getUserRole(claims.UserID, teamID)
	if role != string(models.TeamRoleOwner) && role != string(models.TeamRoleAdmin) {
		writeForbidden(w, "Admin or owner access required")
		return
	}

	var req TeamMemberRequest
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Role == "" {
		writeBadRequest(w, "Role is required")
		return
	}

	if !isValidRole(req.Role) {
		writeBadRequest(w, "Invalid role")
		return
	}

	// Cannot change owner role directly
	if req.Role == string(models.TeamRoleOwner) {
		writeBadRequest(w, "Cannot assign owner role directly; use transfer ownership")
		return
	}

	if err := h.teamRepo.UpdateMemberRole(teamID, userID, models.TeamRole(req.Role)); err != nil {
		writeInternalError(w, "Failed to update member")
		return
	}

	writeSuccess(w, map[string]string{
		"message": "Member role updated successfully",
	})
}

// RemoveMember removes a member from a team
func (h *TeamsHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	teamIDStr := getPathParam(r, "id")
	teamID, err := strconv.ParseInt(teamIDStr, 10, 64)
	if err != nil || teamID == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Get user ID
	userIDStr := getPathParam(r, "user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || userID == 0 {
		writeBadRequest(w, "Invalid user ID")
		return
	}

	// Check if user is owner or admin (or removing self)
	role := h.getUserRole(claims.UserID, teamID)
	if role != string(models.TeamRoleOwner) && role != string(models.TeamRoleAdmin) && claims.UserID != userID {
		writeForbidden(w, "Admin or owner access required")
		return
	}

	// Get team to check owner
	team, _ := h.teamRepo.GetByID(teamID)
	if team != nil && team.OwnerID == userID {
		writeBadRequest(w, "Cannot remove team owner; transfer ownership first")
		return
	}

	if err := h.teamRepo.RemoveMember(teamID, userID); err != nil {
		writeInternalError(w, "Failed to remove member")
		return
	}

	writeSuccess(w, map[string]string{
		"message": "Member removed successfully",
	})
}

// TransferOwnership transfers team ownership
func (h *TeamsHandler) TransferOwnership(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		writeUnauthorized(w, "Not authenticated")
		return
	}

	// Get team ID
	teamIDStr := getPathParam(r, "id")
	teamID, err := strconv.ParseInt(teamIDStr, 10, 64)
	if err != nil || teamID == 0 {
		writeBadRequest(w, "Invalid team ID")
		return
	}

	// Get team
	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		writeInternalError(w, "Failed to get team")
		return
	}
	if team == nil {
		writeNotFound(w, "Team not found")
		return
	}

	// Only owner can transfer
	if team.OwnerID != claims.UserID {
		writeForbidden(w, "Only team owner can transfer ownership")
		return
	}

	var req struct {
		NewOwnerID int64 `json:"new_owner_id"`
	}
	if err := parseJSON(r, &req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.NewOwnerID == 0 {
		writeBadRequest(w, "New owner ID is required")
		return
	}

	// Check if new owner is a member
	newOwnerRole := h.getUserRole(req.NewOwnerID, teamID)
	if newOwnerRole == "" {
		writeBadRequest(w, "New owner must be a team member")
		return
	}

	if err := h.teamRepo.TransferOwnership(teamID, req.NewOwnerID); err != nil {
		writeInternalError(w, "Failed to transfer ownership")
		return
	}

	// Log transfer
	if h.auditRepo != nil {
		h.auditRepo.LogEntry(models.AuditCategoryTeam, models.AuditActionUpdate,
			claims.UserID, claims.UserType, auth.GetClientIP(r), r.UserAgent(),
			map[string]interface{}{"team_id": team.ID, "action": "transfer_ownership", "new_owner_id": req.NewOwnerID})
	}

	writeSuccess(w, map[string]string{
		"message": "Ownership transferred successfully",
	})
}

// getUserRole gets the user's role in a team
func (h *TeamsHandler) getUserRole(userID, teamID int64) string {
	members, err := h.teamRepo.GetMembers(teamID)
	if err != nil {
		return ""
	}

	for _, m := range members {
		if m.UserID == userID {
			return string(m.Role)
		}
	}

	return ""
}

// generateSlug generates a URL-safe slug from a name
func generateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	return slug
}

// isValidSlug validates a slug format
func isValidSlug(slug string) bool {
	if slug == "" || len(slug) > 64 {
		return false
	}
	return regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`).MatchString(slug) || len(slug) == 1
}

// isValidRole validates a team role
func isValidRole(role string) bool {
	switch models.TeamRole(role) {
	case models.TeamRoleOwner, models.TeamRoleAdmin, models.TeamRoleMember, models.TeamRoleViewer:
		return true
	}
	return false
}
