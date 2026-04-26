package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/casapps/cassecrets/src/models"
)

// AuditRepository handles audit log operations
type AuditRepository struct {
	serverDB *sql.DB
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(serverDB *sql.DB) *AuditRepository {
	return &AuditRepository{serverDB: serverDB}
}

// LogEntry logs an audit entry to server.db audit_log table
func (r *AuditRepository) LogEntry(entry *models.AuditLogEntry) error {
	query := `
		INSERT INTO audit_log (timestamp, level, category, action, actor_type, actor_id, actor_ip, target_type, target_id, details, success)
		VALUES (strftime('%s', 'now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := r.serverDB.Exec(query,
		entry.Level, entry.Category, entry.Action,
		entry.ActorType, entry.ActorID, entry.ActorIP,
		entry.TargetType, entry.TargetID, entry.Details,
		entry.Success,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}

	id, _ := result.LastInsertId()
	entry.ID = id
	entry.Timestamp = time.Now()

	return nil
}

// LogSecretAccess logs a secret access event
func (r *AuditRepository) LogSecretAccess(entry *models.SecretAuditEntry) error {
	query := `
		INSERT INTO secret_audit_log (timestamp, action, secret_id, secret_path, team_id, user_id, ip_address, user_agent, version, success, details)
		VALUES (strftime('%s', 'now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := r.serverDB.Exec(query,
		entry.Action, entry.SecretID, entry.SecretPath,
		entry.TeamID, entry.UserID, entry.IPAddress, entry.UserAgent,
		entry.Version, entry.Success, entry.Details,
	)
	if err != nil {
		return fmt.Errorf("inserting secret audit log: %w", err)
	}

	id, _ := result.LastInsertId()
	entry.ID = id
	entry.Timestamp = time.Now()

	return nil
}

// QueryParams defines parameters for querying audit logs
type QueryParams struct {
	Category   string
	Action     string
	ActorType  string
	ActorID    string
	TargetType string
	TargetID   string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
	Offset     int
}

// Query queries audit log entries
func (r *AuditRepository) Query(params QueryParams) ([]*models.AuditLogEntry, error) {
	query := `
		SELECT id, timestamp, level, category, action, actor_type, actor_id, actor_ip, target_type, target_id, details, success
		FROM audit_log
		WHERE 1=1
	`
	args := []interface{}{}

	if params.Category != "" {
		query += " AND category = ?"
		args = append(args, params.Category)
	}
	if params.Action != "" {
		query += " AND action = ?"
		args = append(args, params.Action)
	}
	if params.ActorType != "" {
		query += " AND actor_type = ?"
		args = append(args, params.ActorType)
	}
	if params.ActorID != "" {
		query += " AND actor_id = ?"
		args = append(args, params.ActorID)
	}
	if params.TargetType != "" {
		query += " AND target_type = ?"
		args = append(args, params.TargetType)
	}
	if params.TargetID != "" {
		query += " AND target_id = ?"
		args = append(args, params.TargetID)
	}
	if !params.StartTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, params.StartTime.Unix())
	}
	if !params.EndTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, params.EndTime.Unix())
	}

	query += " ORDER BY timestamp DESC"

	if params.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, params.Limit)
	} else {
		query += " LIMIT 100"
	}

	if params.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, params.Offset)
	}

	rows, err := r.serverDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []*models.AuditLogEntry
	for rows.Next() {
		entry := &models.AuditLogEntry{}
		var timestamp int64
		var actorType, actorID, actorIP, targetType, targetID, details sql.NullString

		err := rows.Scan(
			&entry.ID, &timestamp, &entry.Level, &entry.Category, &entry.Action,
			&actorType, &actorID, &actorIP, &targetType, &targetID, &details,
			&entry.Success,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}

		entry.Timestamp = time.Unix(timestamp, 0)
		if actorType.Valid {
			entry.ActorType = actorType.String
		}
		if actorID.Valid {
			entry.ActorID = actorID.String
		}
		if actorIP.Valid {
			entry.ActorIP = actorIP.String
		}
		if targetType.Valid {
			entry.TargetType = targetType.String
		}
		if targetID.Valid {
			entry.TargetID = targetID.String
		}
		if details.Valid {
			entry.Details = details.String
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// SecretQueryParams defines parameters for querying secret audit logs
type SecretQueryParams struct {
	SecretID   int64
	SecretPath string
	TeamID     int64
	UserID     int64
	Action     string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
	Offset     int
}

// QuerySecretAccess queries secret access audit logs
func (r *AuditRepository) QuerySecretAccess(params SecretQueryParams) ([]*models.SecretAuditEntry, error) {
	query := `
		SELECT id, timestamp, action, secret_id, secret_path, team_id, user_id, ip_address, user_agent, version, success, details
		FROM secret_audit_log
		WHERE 1=1
	`
	args := []interface{}{}

	if params.SecretID > 0 {
		query += " AND secret_id = ?"
		args = append(args, params.SecretID)
	}
	if params.SecretPath != "" {
		query += " AND secret_path = ?"
		args = append(args, params.SecretPath)
	}
	if params.TeamID > 0 {
		query += " AND team_id = ?"
		args = append(args, params.TeamID)
	}
	if params.UserID > 0 {
		query += " AND user_id = ?"
		args = append(args, params.UserID)
	}
	if params.Action != "" {
		query += " AND action = ?"
		args = append(args, params.Action)
	}
	if !params.StartTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, params.StartTime.Unix())
	}
	if !params.EndTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, params.EndTime.Unix())
	}

	query += " ORDER BY timestamp DESC"

	if params.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, params.Limit)
	} else {
		query += " LIMIT 100"
	}

	if params.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, params.Offset)
	}

	rows, err := r.serverDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying secret audit log: %w", err)
	}
	defer rows.Close()

	var entries []*models.SecretAuditEntry
	for rows.Next() {
		entry := &models.SecretAuditEntry{}
		var timestamp int64
		var secretID sql.NullInt64
		var secretPath, ipAddress, userAgent, details sql.NullString
		var version sql.NullInt64

		err := rows.Scan(
			&entry.ID, &timestamp, &entry.Action, &secretID, &secretPath,
			&entry.TeamID, &entry.UserID, &ipAddress, &userAgent, &version,
			&entry.Success, &details,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning secret audit log: %w", err)
		}

		entry.Timestamp = time.Unix(timestamp, 0)
		if secretID.Valid {
			entry.SecretID = secretID.Int64
		}
		if secretPath.Valid {
			entry.SecretPath = secretPath.String
		}
		if ipAddress.Valid {
			entry.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			entry.UserAgent = userAgent.String
		}
		if version.Valid {
			entry.Version = int(version.Int64)
		}
		if details.Valid {
			entry.Details = details.String
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// ExportAuditLogs exports audit logs as JSON
func (r *AuditRepository) ExportAuditLogs(params QueryParams) ([]byte, error) {
	entries, err := r.Query(params)
	if err != nil {
		return nil, err
	}

	return json.Marshal(entries)
}

// ExportSecretAuditLogs exports secret audit logs as JSON
func (r *AuditRepository) ExportSecretAuditLogs(params SecretQueryParams) ([]byte, error) {
	entries, err := r.QuerySecretAccess(params)
	if err != nil {
		return nil, err
	}

	return json.Marshal(entries)
}

// CleanupOldEntries removes audit log entries older than the specified duration
func (r *AuditRepository) CleanupOldEntries(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()

	// Clean up main audit log
	result1, err := r.serverDB.Exec("DELETE FROM audit_log WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleaning audit_log: %w", err)
	}

	// Clean up secret audit log
	result2, err := r.serverDB.Exec("DELETE FROM secret_audit_log WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleaning secret_audit_log: %w", err)
	}

	count1, _ := result1.RowsAffected()
	count2, _ := result2.RowsAffected()

	return count1 + count2, nil
}

// LogAuth logs an authentication event
func (r *AuditRepository) LogAuth(action string, userType string, userID string, ip string, success bool, details string) error {
	return r.LogEntry(&models.AuditLogEntry{
		Level:      "info",
		Category:   models.AuditCategoryAuth,
		Action:     action,
		ActorType:  userType,
		ActorID:    userID,
		ActorIP:    ip,
		Success:    success,
		Details:    details,
	})
}

// LogConfigChange logs a configuration change
func (r *AuditRepository) LogConfigChange(actorType, actorID, ip, key, oldValue, newValue string) error {
	details := fmt.Sprintf(`{"key":"%s","old":%q,"new":%q}`, key, oldValue, newValue)
	return r.LogEntry(&models.AuditLogEntry{
		Level:      "info",
		Category:   models.AuditCategoryConfig,
		Action:     "config_change",
		ActorType:  actorType,
		ActorID:    actorID,
		ActorIP:    ip,
		TargetType: "config",
		TargetID:   key,
		Success:    true,
		Details:    details,
	})
}

// LogSecretCreate logs a secret creation
func (r *AuditRepository) LogSecretCreate(teamID, userID, secretID int64, secretPath, ip, userAgent string) error {
	return r.LogSecretAccess(&models.SecretAuditEntry{
		Action:     models.AuditActionCreate,
		SecretID:   secretID,
		SecretPath: secretPath,
		TeamID:     teamID,
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		Version:    1,
		Success:    true,
	})
}

// LogSecretRead logs a secret read
func (r *AuditRepository) LogSecretRead(teamID, userID, secretID int64, secretPath, ip, userAgent string, version int) error {
	return r.LogSecretAccess(&models.SecretAuditEntry{
		Action:     models.AuditActionRead,
		SecretID:   secretID,
		SecretPath: secretPath,
		TeamID:     teamID,
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		Version:    version,
		Success:    true,
	})
}

// LogSecretUpdate logs a secret update
func (r *AuditRepository) LogSecretUpdate(teamID, userID, secretID int64, secretPath, ip, userAgent string, version int) error {
	return r.LogSecretAccess(&models.SecretAuditEntry{
		Action:     models.AuditActionUpdate,
		SecretID:   secretID,
		SecretPath: secretPath,
		TeamID:     teamID,
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		Version:    version,
		Success:    true,
	})
}

// LogSecretDelete logs a secret deletion
func (r *AuditRepository) LogSecretDelete(teamID, userID, secretID int64, secretPath, ip, userAgent string) error {
	return r.LogSecretAccess(&models.SecretAuditEntry{
		Action:     models.AuditActionDelete,
		SecretID:   secretID,
		SecretPath: secretPath,
		TeamID:     teamID,
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		Success:    true,
	})
}

// LogSecretRollback logs a secret rollback
func (r *AuditRepository) LogSecretRollback(teamID, userID, secretID int64, secretPath, ip, userAgent string, fromVersion, toVersion int) error {
	details := fmt.Sprintf(`{"from_version":%d,"to_version":%d}`, fromVersion, toVersion)
	return r.LogSecretAccess(&models.SecretAuditEntry{
		Action:     models.AuditActionRollback,
		SecretID:   secretID,
		SecretPath: secretPath,
		TeamID:     teamID,
		UserID:     userID,
		IPAddress:  ip,
		UserAgent:  userAgent,
		Version:    toVersion,
		Success:    true,
		Details:    details,
	})
}
