package database

// initServerSchema creates the server.db tables
func (db *Database) initServerSchema() error {
	schema := `
-- ============================================================================
-- SERVER.DB - Server state and operations
-- ============================================================================

-- Config key-value storage (mirrors YAML structure as flat keys)
CREATE TABLE IF NOT EXISTS config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    type        TEXT NOT NULL DEFAULT 'string',
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Config metadata for change detection
CREATE TABLE IF NOT EXISTS config_meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL DEFAULT 1,
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Initialize metadata row
INSERT OR IGNORE INTO config_meta (id, version) VALUES (1, 1);

-- Index for fast lookups by prefix
CREATE INDEX IF NOT EXISTS idx_config_key_prefix ON config(key);

-- Admin Sessions (admin WebUI login sessions)
CREATE TABLE IF NOT EXISTS admin_sessions (
    id          TEXT PRIMARY KEY,
    admin_id    INTEGER NOT NULL,
    ip_address  TEXT NOT NULL,
    user_agent  TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at  INTEGER NOT NULL,
    last_active INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

-- Rate Limiting (sliding window counters)
CREATE TABLE IF NOT EXISTS rate_limits (
    key         TEXT PRIMARY KEY,
    count       INTEGER NOT NULL DEFAULT 1,
    window_start INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);

-- Audit Log (admin actions, config changes, security events)
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    level       TEXT NOT NULL DEFAULT 'info',
    category    TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor_type  TEXT,
    actor_id    TEXT,
    actor_ip    TEXT,
    target_type TEXT,
    target_id   TEXT,
    details     TEXT,
    success     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_type, actor_id);

-- Scheduler (background task tracking)
CREATE TABLE IF NOT EXISTS scheduler_tasks (
    id          TEXT PRIMARY KEY,
    enabled     INTEGER NOT NULL DEFAULT 1,
    schedule    TEXT NOT NULL,
    last_run    INTEGER,
    next_run    INTEGER,
    last_status TEXT,
    last_error  TEXT,
    run_count   INTEGER NOT NULL DEFAULT 0,
    fail_count  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scheduler_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER,
    status      TEXT NOT NULL,
    error       TEXT,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scheduler_history_task ON scheduler_history(task_id);
CREATE INDEX IF NOT EXISTS idx_scheduler_history_started ON scheduler_history(started_at);

-- Backups (backup history and metadata)
CREATE TABLE IF NOT EXISTS backups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT NOT NULL UNIQUE,
    filepath    TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    type        TEXT NOT NULL DEFAULT 'auto',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    checksum    TEXT,
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at);
`

	_, err := db.ServerDB.Exec(schema)
	return err
}
