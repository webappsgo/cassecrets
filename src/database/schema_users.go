package database

// initUsersSchema creates the users.db tables
func (db *Database) initUsersSchema() error {
	schema := `
-- ============================================================================
-- USERS.DB - User accounts and authentication
-- ============================================================================

-- Server Admins (admin WebUI access)
CREATE TABLE IF NOT EXISTS admins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    email       TEXT,
    role        TEXT NOT NULL DEFAULT 'admin',
    enabled     INTEGER NOT NULL DEFAULT 1,
    api_token_hash TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_login  INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    source      TEXT NOT NULL DEFAULT 'local',
    external_id TEXT,
    groups      TEXT,
    last_sync   INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_username ON admins(username);

-- Regular Users (app users with secrets access)
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    email       TEXT UNIQUE,
    password    TEXT NOT NULL,
    display_name TEXT,
    avatar_url  TEXT,
    role        TEXT NOT NULL DEFAULT 'user',
    enabled     INTEGER NOT NULL DEFAULT 1,
    verified    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_login  INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    metadata    TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- API Keys (for API authentication)
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT NOT NULL UNIQUE,
    key_prefix  TEXT NOT NULL,
    name        TEXT NOT NULL,
    owner_type  TEXT NOT NULL,
    owner_id    INTEGER NOT NULL,
    scopes      TEXT,
    rate_limit  INTEGER,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER,
    last_used   INTEGER,
    use_count   INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_type, owner_id);

-- Password Reset Tokens
CREATE TABLE IF NOT EXISTS password_resets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT NOT NULL UNIQUE,
    user_type   TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);

-- Email Verification Tokens
CREATE TABLE IF NOT EXISTS email_verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT NOT NULL UNIQUE,
    user_type   TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    email       TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER NOT NULL,
    verified_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_email_verifications_expires ON email_verifications(expires_at);

-- TOTP Secrets (for 2FA)
CREATE TABLE IF NOT EXISTS totp_secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_type   TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    secret      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 0,
    backup_codes TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_used   INTEGER,
    UNIQUE(user_type, user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_user ON totp_secrets(user_type, user_id);

-- User Sessions (app user login sessions)
CREATE TABLE IF NOT EXISTS user_sessions (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    ip_address  TEXT NOT NULL,
    user_agent  TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER NOT NULL,
    last_active INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);

-- Passkeys (WebAuthn/FIDO2 credentials)
CREATE TABLE IF NOT EXISTS passkeys (
    id              TEXT PRIMARY KEY,
    user_type       TEXT NOT NULL,
    user_id         INTEGER NOT NULL,
    name            TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      TEXT,
    aaguid          TEXT,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_used       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_type, user_id);

-- Trusted Devices (skip 2FA for remembered devices)
CREATE TABLE IF NOT EXISTS trusted_devices (
    id          TEXT PRIMARY KEY,
    user_type   TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    device_hash TEXT NOT NULL,
    name        TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER NOT NULL,
    last_used   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_type, user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_expires ON trusted_devices(expires_at);
`

	_, err := db.UsersDB.Exec(schema)
	return err
}
