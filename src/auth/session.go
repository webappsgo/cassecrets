package auth

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/casapps/cassecrets/src/crypto"
)

const (
	// Session cookie names
	AdminSessionCookie = "admin_session"
	UserSessionCookie  = "user_session"

	// Session durations
	AdminSessionDuration = 30 * 24 * time.Hour
	UserSessionDuration  = 7 * 24 * time.Hour
)

// Session represents a user session
type Session struct {
	ID         string
	UserType   string
	UserID     int64
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastActive time.Time
}

// SessionManager manages user sessions
type SessionManager struct {
	serverDB *sql.DB
	usersDB  *sql.DB
}

// NewSessionManager creates a new session manager
func NewSessionManager(serverDB, usersDB *sql.DB) *SessionManager {
	return &SessionManager{
		serverDB: serverDB,
		usersDB:  usersDB,
	}
}

// CreateAdminSession creates a new admin session
func (m *SessionManager) CreateAdminSession(adminID int64, ip, userAgent string) (*Session, error) {
	token, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(AdminSessionDuration)

	query := `
		INSERT INTO admin_sessions (id, admin_id, ip_address, user_agent, created_at, expires_at, last_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err = m.serverDB.Exec(query, token, adminID, ip, userAgent, now.Unix(), expiresAt.Unix(), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return &Session{
		ID:         token,
		UserType:   "admin",
		UserID:     adminID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		LastActive: now,
	}, nil
}

// CreateUserSession creates a new user session
func (m *SessionManager) CreateUserSession(userID int64, ip, userAgent string) (*Session, error) {
	token, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(UserSessionDuration)

	query := `
		INSERT INTO user_sessions (id, user_id, ip_address, user_agent, created_at, expires_at, last_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err = m.usersDB.Exec(query, token, userID, ip, userAgent, now.Unix(), expiresAt.Unix(), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return &Session{
		ID:         token,
		UserType:   "user",
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		LastActive: now,
	}, nil
}

// GetAdminSession retrieves and validates an admin session
func (m *SessionManager) GetAdminSession(token string) (*Session, error) {
	query := `
		SELECT id, admin_id, ip_address, user_agent, created_at, expires_at, last_active
		FROM admin_sessions
		WHERE id = ? AND expires_at > ?
	`

	var session Session
	var createdAt, expiresAt, lastActive int64
	var userAgent sql.NullString

	err := m.serverDB.QueryRow(query, token, time.Now().Unix()).Scan(
		&session.ID, &session.UserID, &session.IPAddress, &userAgent,
		&createdAt, &expiresAt, &lastActive,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying session: %w", err)
	}

	session.UserType = "admin"
	session.CreatedAt = time.Unix(createdAt, 0)
	session.ExpiresAt = time.Unix(expiresAt, 0)
	session.LastActive = time.Unix(lastActive, 0)
	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}

	// Update last active
	m.serverDB.Exec("UPDATE admin_sessions SET last_active = ? WHERE id = ?", time.Now().Unix(), token)

	return &session, nil
}

// GetUserSession retrieves and validates a user session
func (m *SessionManager) GetUserSession(token string) (*Session, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, created_at, expires_at, last_active
		FROM user_sessions
		WHERE id = ? AND expires_at > ?
	`

	var session Session
	var createdAt, expiresAt, lastActive int64
	var userAgent sql.NullString

	err := m.usersDB.QueryRow(query, token, time.Now().Unix()).Scan(
		&session.ID, &session.UserID, &session.IPAddress, &userAgent,
		&createdAt, &expiresAt, &lastActive,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying session: %w", err)
	}

	session.UserType = "user"
	session.CreatedAt = time.Unix(createdAt, 0)
	session.ExpiresAt = time.Unix(expiresAt, 0)
	session.LastActive = time.Unix(lastActive, 0)
	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}

	// Update last active
	m.usersDB.Exec("UPDATE user_sessions SET last_active = ? WHERE id = ?", time.Now().Unix(), token)

	return &session, nil
}

// DeleteAdminSession deletes an admin session
func (m *SessionManager) DeleteAdminSession(token string) error {
	_, err := m.serverDB.Exec("DELETE FROM admin_sessions WHERE id = ?", token)
	return err
}

// DeleteUserSession deletes a user session
func (m *SessionManager) DeleteUserSession(token string) error {
	_, err := m.usersDB.Exec("DELETE FROM user_sessions WHERE id = ?", token)
	return err
}

// DeleteAllAdminSessions deletes all sessions for an admin
func (m *SessionManager) DeleteAllAdminSessions(adminID int64) error {
	_, err := m.serverDB.Exec("DELETE FROM admin_sessions WHERE admin_id = ?", adminID)
	return err
}

// DeleteAllUserSessions deletes all sessions for a user
func (m *SessionManager) DeleteAllUserSessions(userID int64) error {
	_, err := m.usersDB.Exec("DELETE FROM user_sessions WHERE user_id = ?", userID)
	return err
}

// CleanupExpiredSessions removes expired sessions from both databases
func (m *SessionManager) CleanupExpiredSessions() (int64, error) {
	now := time.Now().Unix()

	result1, err := m.serverDB.Exec("DELETE FROM admin_sessions WHERE expires_at < ?", now)
	if err != nil {
		return 0, fmt.Errorf("cleaning admin sessions: %w", err)
	}

	result2, err := m.usersDB.Exec("DELETE FROM user_sessions WHERE expires_at < ?", now)
	if err != nil {
		return 0, fmt.Errorf("cleaning user sessions: %w", err)
	}

	count1, _ := result1.RowsAffected()
	count2, _ := result2.RowsAffected()

	return count1 + count2, nil
}

// SetSessionCookie sets a session cookie on the response
func SetSessionCookie(w http.ResponseWriter, name, value string, maxAge int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie clears a session cookie
func ClearSessionCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// GetSessionFromRequest extracts session token from request (cookie or header)
func GetSessionFromRequest(r *http.Request, cookieName string) string {
	// Try cookie first
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return ""
}
