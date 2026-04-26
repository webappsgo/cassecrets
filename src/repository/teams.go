package repository

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/casapps/cassecrets/src/crypto"
	"github.com/casapps/cassecrets/src/models"
)

// TeamsRepository handles team storage operations
type TeamsRepository struct {
	db *sql.DB
}

// NewTeamsRepository creates a new teams repository
func NewTeamsRepository(db *sql.DB) *TeamsRepository {
	return &TeamsRepository{db: db}
}

// Create creates a new team
func (r *TeamsRepository) Create(team *models.Team) error {
	// Generate slug from name if not provided
	if team.Slug == "" {
		team.Slug = generateSlug(team.Name)
	}

	query := `
		INSERT INTO teams (name, slug, description, owner_id, created_at, updated_at, settings)
		VALUES (?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'), ?)
	`

	result, err := r.db.Exec(query, team.Name, team.Slug, team.Description, team.OwnerID, team.Settings)
	if err != nil {
		return fmt.Errorf("inserting team: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert id: %w", err)
	}

	team.ID = id

	// Add owner as a team member with owner role
	memberQuery := `
		INSERT INTO team_members (team_id, user_id, role, joined_at)
		VALUES (?, ?, 'owner', strftime('%s', 'now'))
	`
	_, err = r.db.Exec(memberQuery, team.ID, team.OwnerID)
	if err != nil {
		return fmt.Errorf("adding owner as member: %w", err)
	}

	return nil
}

// GetByID retrieves a team by ID
func (r *TeamsRepository) GetByID(id int64) (*models.Team, error) {
	query := `
		SELECT id, name, slug, description, owner_id, created_at, updated_at, settings
		FROM teams
		WHERE id = ?
	`

	team := &models.Team{}
	var createdAt, updatedAt int64
	var description, settings sql.NullString

	err := r.db.QueryRow(query, id).Scan(
		&team.ID, &team.Name, &team.Slug, &description, &team.OwnerID,
		&createdAt, &updatedAt, &settings,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying team: %w", err)
	}

	team.CreatedAt = time.Unix(createdAt, 0)
	team.UpdatedAt = time.Unix(updatedAt, 0)
	if description.Valid {
		team.Description = description.String
	}
	if settings.Valid {
		team.Settings = settings.String
	}

	return team, nil
}

// GetBySlug retrieves a team by slug
func (r *TeamsRepository) GetBySlug(slug string) (*models.Team, error) {
	query := `
		SELECT id, name, slug, description, owner_id, created_at, updated_at, settings
		FROM teams
		WHERE slug = ?
	`

	team := &models.Team{}
	var createdAt, updatedAt int64
	var description, settings sql.NullString

	err := r.db.QueryRow(query, slug).Scan(
		&team.ID, &team.Name, &team.Slug, &description, &team.OwnerID,
		&createdAt, &updatedAt, &settings,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying team: %w", err)
	}

	team.CreatedAt = time.Unix(createdAt, 0)
	team.UpdatedAt = time.Unix(updatedAt, 0)
	if description.Valid {
		team.Description = description.String
	}
	if settings.Valid {
		team.Settings = settings.String
	}

	return team, nil
}

// ListByUser lists all teams a user is a member of
func (r *TeamsRepository) ListByUser(userID int64) ([]*models.Team, error) {
	query := `
		SELECT t.id, t.name, t.slug, t.description, t.owner_id, t.created_at, t.updated_at, t.settings
		FROM teams t
		INNER JOIN team_members tm ON t.id = tm.team_id
		WHERE tm.user_id = ?
		ORDER BY t.name ASC
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("querying teams: %w", err)
	}
	defer rows.Close()

	var teams []*models.Team
	for rows.Next() {
		team := &models.Team{}
		var createdAt, updatedAt int64
		var description, settings sql.NullString

		err := rows.Scan(
			&team.ID, &team.Name, &team.Slug, &description, &team.OwnerID,
			&createdAt, &updatedAt, &settings,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning team: %w", err)
		}

		team.CreatedAt = time.Unix(createdAt, 0)
		team.UpdatedAt = time.Unix(updatedAt, 0)
		if description.Valid {
			team.Description = description.String
		}
		if settings.Valid {
			team.Settings = settings.String
		}

		teams = append(teams, team)
	}

	return teams, nil
}

// Update updates a team
func (r *TeamsRepository) Update(team *models.Team) error {
	query := `
		UPDATE teams
		SET name = ?, slug = ?, description = ?, settings = ?, updated_at = strftime('%s', 'now')
		WHERE id = ?
	`

	_, err := r.db.Exec(query, team.Name, team.Slug, team.Description, team.Settings, team.ID)
	return err
}

// Delete deletes a team and all associated data
func (r *TeamsRepository) Delete(id int64) error {
	// Delete in order: policies, secrets, members, invitations, team
	queries := []string{
		"DELETE FROM policy_assignments WHERE policy_id IN (SELECT id FROM acl_policies WHERE team_id = ?)",
		"DELETE FROM acl_policies WHERE team_id = ?",
		"DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE team_id = ?)",
		"DELETE FROM secrets WHERE team_id = ?",
		"DELETE FROM team_invitations WHERE team_id = ?",
		"DELETE FROM team_members WHERE team_id = ?",
		"DELETE FROM teams WHERE id = ?",
	}

	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback()

	for _, q := range queries {
		if _, err := tx.Exec(q, id); err != nil {
			return fmt.Errorf("executing delete: %w", err)
		}
	}

	return tx.Commit()
}

// TransferOwnership transfers team ownership to another user
func (r *TeamsRepository) TransferOwnership(teamID, newOwnerID int64) error {
	// Start transaction
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current owner
	var currentOwnerID int64
	err = tx.QueryRow("SELECT owner_id FROM teams WHERE id = ?", teamID).Scan(&currentOwnerID)
	if err != nil {
		return fmt.Errorf("getting current owner: %w", err)
	}

	// Update team owner
	_, err = tx.Exec("UPDATE teams SET owner_id = ?, updated_at = strftime('%s', 'now') WHERE id = ?", newOwnerID, teamID)
	if err != nil {
		return fmt.Errorf("updating team owner: %w", err)
	}

	// Update old owner's role to admin
	_, err = tx.Exec("UPDATE team_members SET role = 'admin' WHERE team_id = ? AND user_id = ?", teamID, currentOwnerID)
	if err != nil {
		return fmt.Errorf("updating old owner role: %w", err)
	}

	// Update new owner's role to owner (or insert if not a member)
	result, err := tx.Exec("UPDATE team_members SET role = 'owner' WHERE team_id = ? AND user_id = ?", teamID, newOwnerID)
	if err != nil {
		return fmt.Errorf("updating new owner role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// New owner wasn't a member, add them
		_, err = tx.Exec("INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, 'owner', strftime('%s', 'now'))", teamID, newOwnerID)
		if err != nil {
			return fmt.Errorf("adding new owner as member: %w", err)
		}
	}

	return tx.Commit()
}

// AddMember adds a user to a team
func (r *TeamsRepository) AddMember(teamID, userID, invitedBy int64, role string) error {
	if role == "" {
		role = models.TeamRoleMember
	}

	query := `
		INSERT INTO team_members (team_id, user_id, role, invited_by, joined_at)
		VALUES (?, ?, ?, ?, strftime('%s', 'now'))
	`

	_, err := r.db.Exec(query, teamID, userID, role, invitedBy)
	return err
}

// RemoveMember removes a user from a team
func (r *TeamsRepository) RemoveMember(teamID, userID int64) error {
	// Check if user is owner - owners cannot be removed
	var role string
	err := r.db.QueryRow("SELECT role FROM team_members WHERE team_id = ? AND user_id = ?", teamID, userID).Scan(&role)
	if err != nil {
		return fmt.Errorf("checking member role: %w", err)
	}
	if role == models.TeamRoleOwner {
		return fmt.Errorf("cannot remove team owner")
	}

	_, err = r.db.Exec("DELETE FROM team_members WHERE team_id = ? AND user_id = ?", teamID, userID)
	return err
}

// UpdateMemberRole updates a member's role
func (r *TeamsRepository) UpdateMemberRole(teamID, userID int64, role string) error {
	// Cannot change owner's role
	var currentRole string
	err := r.db.QueryRow("SELECT role FROM team_members WHERE team_id = ? AND user_id = ?", teamID, userID).Scan(&currentRole)
	if err != nil {
		return fmt.Errorf("checking current role: %w", err)
	}
	if currentRole == models.TeamRoleOwner {
		return fmt.Errorf("cannot change owner's role")
	}

	_, err = r.db.Exec("UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?", role, teamID, userID)
	return err
}

// GetMembers lists all members of a team
func (r *TeamsRepository) GetMembers(teamID int64) ([]*models.TeamMember, error) {
	query := `
		SELECT id, team_id, user_id, role, invited_by, joined_at
		FROM team_members
		WHERE team_id = ?
		ORDER BY joined_at ASC
	`

	rows, err := r.db.Query(query, teamID)
	if err != nil {
		return nil, fmt.Errorf("querying members: %w", err)
	}
	defer rows.Close()

	var members []*models.TeamMember
	for rows.Next() {
		member := &models.TeamMember{}
		var joinedAt int64
		var invitedBy sql.NullInt64

		err := rows.Scan(&member.ID, &member.TeamID, &member.UserID, &member.Role, &invitedBy, &joinedAt)
		if err != nil {
			return nil, fmt.Errorf("scanning member: %w", err)
		}

		member.JoinedAt = time.Unix(joinedAt, 0)
		if invitedBy.Valid {
			member.InvitedBy = invitedBy.Int64
		}

		members = append(members, member)
	}

	return members, nil
}

// GetMember gets a specific member's info
func (r *TeamsRepository) GetMember(teamID, userID int64) (*models.TeamMember, error) {
	query := `
		SELECT id, team_id, user_id, role, invited_by, joined_at
		FROM team_members
		WHERE team_id = ? AND user_id = ?
	`

	member := &models.TeamMember{}
	var joinedAt int64
	var invitedBy sql.NullInt64

	err := r.db.QueryRow(query, teamID, userID).Scan(
		&member.ID, &member.TeamID, &member.UserID, &member.Role, &invitedBy, &joinedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying member: %w", err)
	}

	member.JoinedAt = time.Unix(joinedAt, 0)
	if invitedBy.Valid {
		member.InvitedBy = invitedBy.Int64
	}

	return member, nil
}

// CreateInvitation creates a team invitation
func (r *TeamsRepository) CreateInvitation(teamID int64, email string, role string, invitedBy int64, expiresIn time.Duration) (*models.TeamInvitation, error) {
	// Generate token
	token, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	tokenHash := crypto.HashToken(token)
	expiresAt := time.Now().Add(expiresIn)

	query := `
		INSERT INTO team_invitations (team_id, email, token_hash, role, invited_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, strftime('%s', 'now'), ?)
	`

	result, err := r.db.Exec(query, teamID, email, tokenHash, role, invitedBy, expiresAt.Unix())
	if err != nil {
		return nil, fmt.Errorf("inserting invitation: %w", err)
	}

	id, _ := result.LastInsertId()

	return &models.TeamInvitation{
		ID:        id,
		TeamID:    teamID,
		Email:     email,
		TokenHash: token, // Return the unhashed token to send to user
		Role:      role,
		InvitedBy: invitedBy,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}, nil
}

// GetInvitationByToken retrieves an invitation by token
func (r *TeamsRepository) GetInvitationByToken(token string) (*models.TeamInvitation, error) {
	tokenHash := crypto.HashToken(token)

	query := `
		SELECT id, team_id, email, role, invited_by, created_at, expires_at, accepted_at
		FROM team_invitations
		WHERE token_hash = ?
	`

	inv := &models.TeamInvitation{}
	var createdAt, expiresAt int64
	var acceptedAt sql.NullInt64

	err := r.db.QueryRow(query, tokenHash).Scan(
		&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.InvitedBy,
		&createdAt, &expiresAt, &acceptedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying invitation: %w", err)
	}

	inv.CreatedAt = time.Unix(createdAt, 0)
	inv.ExpiresAt = time.Unix(expiresAt, 0)
	if acceptedAt.Valid {
		inv.AcceptedAt = time.Unix(acceptedAt.Int64, 0)
	}

	return inv, nil
}

// AcceptInvitation marks an invitation as accepted and adds user to team
func (r *TeamsRepository) AcceptInvitation(invitationID, userID int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback()

	// Get invitation details
	var teamID int64
	var role string
	var invitedBy int64
	err = tx.QueryRow("SELECT team_id, role, invited_by FROM team_invitations WHERE id = ?", invitationID).Scan(&teamID, &role, &invitedBy)
	if err != nil {
		return fmt.Errorf("getting invitation: %w", err)
	}

	// Mark invitation as accepted
	_, err = tx.Exec("UPDATE team_invitations SET accepted_at = strftime('%s', 'now') WHERE id = ?", invitationID)
	if err != nil {
		return fmt.Errorf("updating invitation: %w", err)
	}

	// Add user to team
	_, err = tx.Exec("INSERT INTO team_members (team_id, user_id, role, invited_by, joined_at) VALUES (?, ?, ?, ?, strftime('%s', 'now'))", teamID, userID, role, invitedBy)
	if err != nil {
		return fmt.Errorf("adding member: %w", err)
	}

	return tx.Commit()
}

// DeleteInvitation deletes an invitation
func (r *TeamsRepository) DeleteInvitation(id int64) error {
	_, err := r.db.Exec("DELETE FROM team_invitations WHERE id = ?", id)
	return err
}

// generateSlug creates a URL-safe slug from a name
func generateSlug(name string) string {
	// Convert to lowercase
	slug := strings.ToLower(name)

	// Replace spaces and special characters with hyphens
	reg := regexp.MustCompile(`[^a-z0-9]+`)
	slug = reg.ReplaceAllString(slug, "-")

	// Remove leading/trailing hyphens
	slug = strings.Trim(slug, "-")

	return slug
}
