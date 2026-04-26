package database

// initSecretsSchema creates the cassecrets-specific tables in server.db
func (db *Database) initSecretsSchema() error {
	schema := `
-- ============================================================================
-- CASSECRETS-SPECIFIC TABLES - Secrets Management
-- ============================================================================

-- Teams/Organizations
CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT,
    owner_id    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    settings    TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_name ON teams(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_slug ON teams(slug);
CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams(owner_id);

-- Team Members
CREATE TABLE IF NOT EXISTS team_members (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id     INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',
    invited_by  INTEGER,
    joined_at   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(team_id, user_id),
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

-- Secrets (current version stored here, history in secret_versions)
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id         INTEGER NOT NULL,
    path            TEXT NOT NULL,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'string',
    encrypted_value TEXT NOT NULL,
    metadata        TEXT,
    version         INTEGER NOT NULL DEFAULT 1,
    created_by      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by      INTEGER,
    updated_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    deleted_at      INTEGER,
    UNIQUE(team_id, path),
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_secrets_team ON secrets(team_id);
CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(team_id, path);
CREATE INDEX IF NOT EXISTS idx_secrets_created_by ON secrets(created_by);

-- Secret Versions (history for rollback)
CREATE TABLE IF NOT EXISTS secret_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id       INTEGER NOT NULL,
    version         INTEGER NOT NULL,
    encrypted_value TEXT NOT NULL,
    metadata        TEXT,
    created_by      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(secret_id, version),
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_versions_version ON secret_versions(secret_id, version);

-- Access Control Policies
CREATE TABLE IF NOT EXISTS acl_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    team_id     INTEGER NOT NULL,
    description TEXT,
    rules       TEXT NOT NULL,
    created_by  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(team_id, name),
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_acl_policies_team ON acl_policies(team_id);

-- Policy Assignments (link policies to users/groups)
CREATE TABLE IF NOT EXISTS policy_assignments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id   INTEGER NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id  INTEGER NOT NULL,
    assigned_by INTEGER NOT NULL,
    assigned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(policy_id, subject_type, subject_id),
    FOREIGN KEY (policy_id) REFERENCES acl_policies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy ON policy_assignments(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_subject ON policy_assignments(subject_type, subject_id);

-- Secret Access Audit Log (detailed access tracking)
CREATE TABLE IF NOT EXISTS secret_audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    action      TEXT NOT NULL,
    secret_id   INTEGER,
    secret_path TEXT,
    team_id     INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    version     INTEGER,
    success     INTEGER NOT NULL DEFAULT 1,
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_secret_audit_timestamp ON secret_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_secret_audit_secret ON secret_audit_log(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_audit_team ON secret_audit_log(team_id);
CREATE INDEX IF NOT EXISTS idx_secret_audit_user ON secret_audit_log(user_id);

-- Team Invitations
CREATE TABLE IF NOT EXISTS team_invitations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id     INTEGER NOT NULL,
    email       TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL DEFAULT 'member',
    invited_by  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER NOT NULL,
    accepted_at INTEGER,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_team_invitations_team ON team_invitations(team_id);
CREATE INDEX IF NOT EXISTS idx_team_invitations_email ON team_invitations(email);
CREATE INDEX IF NOT EXISTS idx_team_invitations_token ON team_invitations(token_hash);
`

	_, err := db.ServerDB.Exec(schema)
	return err
}
