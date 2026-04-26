package models

import (
	"time"
)

// Admin represents a server admin account
type Admin struct {
	ID             int64     `json:"id"`
	Username       string    `json:"username"`
	Password       string    `json:"-"`
	Email          string    `json:"email,omitempty"`
	Role           string    `json:"role"`
	Enabled        bool      `json:"enabled"`
	APITokenHash   string    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastLogin      time.Time `json:"last_login,omitempty"`
	FailedAttempts int       `json:"-"`
	LockedUntil    time.Time `json:"-"`
	Source         string    `json:"source"`
	ExternalID     string    `json:"-"`
	Groups         []string  `json:"-"`
	LastSync       time.Time `json:"-"`
}

// User represents an application user
type User struct {
	ID             int64     `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email,omitempty"`
	Password       string    `json:"-"`
	DisplayName    string    `json:"display_name,omitempty"`
	AvatarURL      string    `json:"avatar_url,omitempty"`
	Role           string    `json:"role"`
	Enabled        bool      `json:"enabled"`
	Verified       bool      `json:"verified"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastLogin      time.Time `json:"last_login,omitempty"`
	FailedAttempts int       `json:"-"`
	LockedUntil    time.Time `json:"-"`
	Metadata       string    `json:"-"`
}

// Team represents a team/organization
type Team struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	OwnerID     int64     `json:"owner_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Settings    string    `json:"-"`
}

// TeamMember represents a user's membership in a team
type TeamMember struct {
	ID        int64     `json:"id"`
	TeamID    int64     `json:"team_id"`
	UserID    int64     `json:"user_id"`
	Role      string    `json:"role"`
	InvitedBy int64     `json:"invited_by,omitempty"`
	JoinedAt  time.Time `json:"joined_at"`
}

// Secret represents a stored secret
type Secret struct {
	ID             int64     `json:"id"`
	TeamID         int64     `json:"team_id"`
	Path           string    `json:"path"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	EncryptedValue string    `json:"-"`
	Value          string    `json:"value,omitempty"`
	Metadata       string    `json:"metadata,omitempty"`
	Version        int       `json:"version"`
	CreatedBy      int64     `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedBy      int64     `json:"updated_by,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
	DeletedAt      time.Time `json:"deleted_at,omitempty"`
}

// SecretVersion represents a historical version of a secret
type SecretVersion struct {
	ID             int64     `json:"id"`
	SecretID       int64     `json:"secret_id"`
	Version        int       `json:"version"`
	EncryptedValue string    `json:"-"`
	Value          string    `json:"value,omitempty"`
	Metadata       string    `json:"metadata,omitempty"`
	CreatedBy      int64     `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// ACLPolicy represents an access control policy
type ACLPolicy struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	TeamID      int64     `json:"team_id"`
	Description string    `json:"description,omitempty"`
	Rules       string    `json:"rules"`
	CreatedBy   int64     `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PolicyAssignment represents a policy assigned to a user or group
type PolicyAssignment struct {
	ID          int64     `json:"id"`
	PolicyID    int64     `json:"policy_id"`
	SubjectType string    `json:"subject_type"`
	SubjectID   int64     `json:"subject_id"`
	AssignedBy  int64     `json:"assigned_by"`
	AssignedAt  time.Time `json:"assigned_at"`
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID        int64     `json:"id"`
	KeyHash   string    `json:"-"`
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

// Session represents a login session
type Session struct {
	ID         string    `json:"id"`
	UserType   string    `json:"user_type"`
	UserID     int64     `json:"user_id"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastActive time.Time `json:"last_active"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	Category   string    `json:"category"`
	Action     string    `json:"action"`
	ActorType  string    `json:"actor_type,omitempty"`
	ActorID    string    `json:"actor_id,omitempty"`
	ActorIP    string    `json:"actor_ip,omitempty"`
	TargetType string    `json:"target_type,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
	Details    string    `json:"details,omitempty"`
	Success    bool      `json:"success"`
}

// SecretAuditEntry represents a secret access audit entry
type SecretAuditEntry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	SecretID   int64     `json:"secret_id,omitempty"`
	SecretPath string    `json:"secret_path,omitempty"`
	TeamID     int64     `json:"team_id"`
	UserID     int64     `json:"user_id"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Version    int       `json:"version,omitempty"`
	Success    bool      `json:"success"`
	Details    string    `json:"details,omitempty"`
}

// TeamInvitation represents an invitation to join a team
type TeamInvitation struct {
	ID         int64     `json:"id"`
	TeamID     int64     `json:"team_id"`
	Email      string    `json:"email"`
	TokenHash  string    `json:"-"`
	Role       string    `json:"role"`
	InvitedBy  int64     `json:"invited_by"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	AcceptedAt time.Time `json:"accepted_at,omitempty"`
}

// SecretType constants
const (
	SecretTypeString = "string"
	SecretTypeFile   = "file"
	SecretTypeJSON   = "json"
	SecretTypeEnv    = "env"
)

// TeamRole constants
const (
	TeamRoleOwner  = "owner"
	TeamRoleAdmin  = "admin"
	TeamRoleMember = "member"
)

// AdminRole constants
const (
	AdminRoleSuperAdmin = "superadmin"
	AdminRoleAdmin      = "admin"
	AdminRoleReadOnly   = "readonly"
)

// AuditCategory constants
const (
	AuditCategoryAuth     = "auth"
	AuditCategoryConfig   = "config"
	AuditCategoryAdmin    = "admin"
	AuditCategoryAPI      = "api"
	AuditCategorySystem   = "system"
	AuditCategorySecrets  = "secrets"
	AuditCategoryTeams    = "teams"
)

// AuditAction constants
const (
	AuditActionLogin          = "login"
	AuditActionLogout         = "logout"
	AuditActionCreate         = "create"
	AuditActionRead           = "read"
	AuditActionUpdate         = "update"
	AuditActionDelete         = "delete"
	AuditActionRollback       = "rollback"
	AuditActionInvite         = "invite"
	AuditActionJoin           = "join"
	AuditActionLeave          = "leave"
	AuditActionTransfer       = "transfer"
)
