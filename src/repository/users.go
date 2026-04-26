package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/casapps/cassecrets/src/crypto"
	"github.com/casapps/cassecrets/src/models"
)

// UsersRepository handles user storage operations
type UsersRepository struct {
	db *sql.DB
}

// NewUsersRepository creates a new users repository
func NewUsersRepository(db *sql.DB) *UsersRepository {
	return &UsersRepository{db: db}
}

// Create creates a new user
func (r *UsersRepository) Create(user *models.User) error {
	// Hash the password
	hashedPassword, err := crypto.HashPassword(user.Password)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	query := `
		INSERT INTO users (username, email, password, display_name, avatar_url, role, enabled, verified, created_at, updated_at, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'), ?)
	`

	result, err := r.db.Exec(query, user.Username, user.Email, hashedPassword, user.DisplayName, user.AvatarURL, user.Role, user.Enabled, user.Verified, user.Metadata)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert id: %w", err)
	}

	user.ID = id
	user.Password = ""
	return nil
}

// GetByID retrieves a user by ID
func (r *UsersRepository) GetByID(id int64) (*models.User, error) {
	query := `
		SELECT id, username, email, password, display_name, avatar_url, role, enabled, verified, created_at, updated_at, last_login, failed_attempts, locked_until, metadata
		FROM users
		WHERE id = ?
	`

	return r.scanUser(r.db.QueryRow(query, id))
}

// GetByUsername retrieves a user by username
func (r *UsersRepository) GetByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password, display_name, avatar_url, role, enabled, verified, created_at, updated_at, last_login, failed_attempts, locked_until, metadata
		FROM users
		WHERE username = ?
	`

	return r.scanUser(r.db.QueryRow(query, username))
}

// GetByEmail retrieves a user by email
func (r *UsersRepository) GetByEmail(email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password, display_name, avatar_url, role, enabled, verified, created_at, updated_at, last_login, failed_attempts, locked_until, metadata
		FROM users
		WHERE email = ?
	`

	return r.scanUser(r.db.QueryRow(query, email))
}

// scanUser scans a user row
func (r *UsersRepository) scanUser(row *sql.Row) (*models.User, error) {
	user := &models.User{}
	var createdAt, updatedAt int64
	var lastLogin, lockedUntil sql.NullInt64
	var email, displayName, avatarURL, metadata sql.NullString

	err := row.Scan(
		&user.ID, &user.Username, &email, &user.Password, &displayName, &avatarURL,
		&user.Role, &user.Enabled, &user.Verified, &createdAt, &updatedAt,
		&lastLogin, &user.FailedAttempts, &lockedUntil, &metadata,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning user: %w", err)
	}

	user.CreatedAt = time.Unix(createdAt, 0)
	user.UpdatedAt = time.Unix(updatedAt, 0)
	if email.Valid {
		user.Email = email.String
	}
	if displayName.Valid {
		user.DisplayName = displayName.String
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if lastLogin.Valid {
		user.LastLogin = time.Unix(lastLogin.Int64, 0)
	}
	if lockedUntil.Valid {
		user.LockedUntil = time.Unix(lockedUntil.Int64, 0)
	}
	if metadata.Valid {
		user.Metadata = metadata.String
	}

	return user, nil
}

// Update updates a user
func (r *UsersRepository) Update(user *models.User) error {
	query := `
		UPDATE users
		SET username = ?, email = ?, display_name = ?, avatar_url = ?, role = ?, enabled = ?, verified = ?, updated_at = strftime('%s', 'now'), metadata = ?
		WHERE id = ?
	`

	_, err := r.db.Exec(query, user.Username, user.Email, user.DisplayName, user.AvatarURL, user.Role, user.Enabled, user.Verified, user.Metadata, user.ID)
	return err
}

// UpdatePassword updates a user's password
func (r *UsersRepository) UpdatePassword(userID int64, newPassword string) error {
	hashedPassword, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	_, err = r.db.Exec("UPDATE users SET password = ?, updated_at = strftime('%s', 'now') WHERE id = ?", hashedPassword, userID)
	return err
}

// Delete deletes a user
func (r *UsersRepository) Delete(id int64) error {
	// Remove from all teams first
	_, err := r.db.Exec("DELETE FROM team_members WHERE user_id = ?", id)
	if err != nil {
		return fmt.Errorf("removing from teams: %w", err)
	}

	// Delete user sessions
	_, err = r.db.Exec("DELETE FROM user_sessions WHERE user_id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting sessions: %w", err)
	}

	// Delete user
	_, err = r.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// VerifyPassword verifies a user's password
func (r *UsersRepository) VerifyPassword(user *models.User, password string) bool {
	return crypto.VerifyPassword(password, user.Password)
}

// RecordLoginSuccess records a successful login
func (r *UsersRepository) RecordLoginSuccess(userID int64) error {
	query := `
		UPDATE users
		SET last_login = strftime('%s', 'now'), failed_attempts = 0, locked_until = NULL
		WHERE id = ?
	`
	_, err := r.db.Exec(query, userID)
	return err
}

// RecordLoginFailure records a failed login attempt
func (r *UsersRepository) RecordLoginFailure(userID int64) error {
	// Increment failed attempts
	_, err := r.db.Exec("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", userID)
	if err != nil {
		return err
	}

	// Lock account after 5 failed attempts (15 minute lockout)
	_, err = r.db.Exec(`
		UPDATE users
		SET locked_until = strftime('%s', 'now') + 900
		WHERE id = ? AND failed_attempts >= 5
	`, userID)
	return err
}

// IsLocked checks if a user account is locked
func (r *UsersRepository) IsLocked(userID int64) (bool, error) {
	var lockedUntil sql.NullInt64
	err := r.db.QueryRow("SELECT locked_until FROM users WHERE id = ?", userID).Scan(&lockedUntil)
	if err != nil {
		return false, err
	}

	if !lockedUntil.Valid {
		return false, nil
	}

	return time.Now().Unix() < lockedUntil.Int64, nil
}

// List lists all users with pagination
func (r *UsersRepository) List(limit, offset int) ([]*models.User, error) {
	query := `
		SELECT id, username, email, password, display_name, avatar_url, role, enabled, verified, created_at, updated_at, last_login, failed_attempts, locked_until, metadata
		FROM users
		ORDER BY username ASC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		var createdAt, updatedAt int64
		var lastLogin, lockedUntil sql.NullInt64
		var email, displayName, avatarURL, metadata sql.NullString

		err := rows.Scan(
			&user.ID, &user.Username, &email, &user.Password, &displayName, &avatarURL,
			&user.Role, &user.Enabled, &user.Verified, &createdAt, &updatedAt,
			&lastLogin, &user.FailedAttempts, &lockedUntil, &metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}

		user.CreatedAt = time.Unix(createdAt, 0)
		user.UpdatedAt = time.Unix(updatedAt, 0)
		if email.Valid {
			user.Email = email.String
		}
		if displayName.Valid {
			user.DisplayName = displayName.String
		}
		if avatarURL.Valid {
			user.AvatarURL = avatarURL.String
		}
		if lastLogin.Valid {
			user.LastLogin = time.Unix(lastLogin.Int64, 0)
		}
		if lockedUntil.Valid {
			user.LockedUntil = time.Unix(lockedUntil.Int64, 0)
		}
		if metadata.Valid {
			user.Metadata = metadata.String
		}

		// Don't expose password hash
		user.Password = ""
		users = append(users, user)
	}

	return users, nil
}

// Count returns the total number of users
func (r *UsersRepository) Count() (int, error) {
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// SetVerified marks a user as email verified
func (r *UsersRepository) SetVerified(userID int64) error {
	_, err := r.db.Exec("UPDATE users SET verified = 1, updated_at = strftime('%s', 'now') WHERE id = ?", userID)
	return err
}

// SetEnabled enables or disables a user
func (r *UsersRepository) SetEnabled(userID int64, enabled bool) error {
	_, err := r.db.Exec("UPDATE users SET enabled = ?, updated_at = strftime('%s', 'now') WHERE id = ?", enabled, userID)
	return err
}
