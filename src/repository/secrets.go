package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/casapps/cassecrets/src/crypto"
	"github.com/casapps/cassecrets/src/models"
)

// SecretsRepository handles secret storage operations
type SecretsRepository struct {
	db         *sql.DB
	keyManager *crypto.KeyManager
}

// NewSecretsRepository creates a new secrets repository
func NewSecretsRepository(db *sql.DB, km *crypto.KeyManager) *SecretsRepository {
	return &SecretsRepository{
		db:         db,
		keyManager: km,
	}
}

// Create creates a new secret
func (r *SecretsRepository) Create(secret *models.Secret) error {
	// Encrypt the value
	encrypted, err := r.keyManager.Encrypt([]byte(secret.Value))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	query := `
		INSERT INTO secrets (team_id, path, name, type, encrypted_value, metadata, version, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, strftime('%s', 'now'), strftime('%s', 'now'))
	`

	result, err := r.db.Exec(query, secret.TeamID, secret.Path, secret.Name, secret.Type, encrypted, secret.Metadata, secret.CreatedBy)
	if err != nil {
		return fmt.Errorf("inserting secret: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert id: %w", err)
	}

	secret.ID = id
	secret.Version = 1
	secret.EncryptedValue = encrypted
	secret.Value = ""

	// Create initial version in history
	if err := r.createVersion(secret); err != nil {
		return fmt.Errorf("creating version: %w", err)
	}

	return nil
}

// GetByPath retrieves a secret by team ID and path
func (r *SecretsRepository) GetByPath(teamID int64, path string) (*models.Secret, error) {
	query := `
		SELECT id, team_id, path, name, type, encrypted_value, metadata, version, created_by, created_at, updated_by, updated_at, deleted_at
		FROM secrets
		WHERE team_id = ? AND path = ? AND deleted_at IS NULL
	`

	secret := &models.Secret{}
	var createdAt, updatedAt int64
	var updatedBy, deletedAt sql.NullInt64
	var metadata sql.NullString

	err := r.db.QueryRow(query, teamID, path).Scan(
		&secret.ID, &secret.TeamID, &secret.Path, &secret.Name, &secret.Type,
		&secret.EncryptedValue, &metadata, &secret.Version, &secret.CreatedBy,
		&createdAt, &updatedBy, &updatedAt, &deletedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying secret: %w", err)
	}

	// Decrypt the value
	decrypted, err := r.keyManager.Decrypt(secret.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}
	secret.Value = string(decrypted)

	// Convert timestamps
	secret.CreatedAt = time.Unix(createdAt, 0)
	secret.UpdatedAt = time.Unix(updatedAt, 0)
	if updatedBy.Valid {
		secret.UpdatedBy = updatedBy.Int64
	}
	if metadata.Valid {
		secret.Metadata = metadata.String
	}

	return secret, nil
}

// GetByID retrieves a secret by ID
func (r *SecretsRepository) GetByID(id int64) (*models.Secret, error) {
	query := `
		SELECT id, team_id, path, name, type, encrypted_value, metadata, version, created_by, created_at, updated_by, updated_at, deleted_at
		FROM secrets
		WHERE id = ? AND deleted_at IS NULL
	`

	secret := &models.Secret{}
	var createdAt, updatedAt int64
	var updatedBy, deletedAt sql.NullInt64
	var metadata sql.NullString

	err := r.db.QueryRow(query, id).Scan(
		&secret.ID, &secret.TeamID, &secret.Path, &secret.Name, &secret.Type,
		&secret.EncryptedValue, &metadata, &secret.Version, &secret.CreatedBy,
		&createdAt, &updatedBy, &updatedAt, &deletedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying secret: %w", err)
	}

	// Decrypt the value
	decrypted, err := r.keyManager.Decrypt(secret.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}
	secret.Value = string(decrypted)

	// Convert timestamps
	secret.CreatedAt = time.Unix(createdAt, 0)
	secret.UpdatedAt = time.Unix(updatedAt, 0)
	if updatedBy.Valid {
		secret.UpdatedBy = updatedBy.Int64
	}
	if metadata.Valid {
		secret.Metadata = metadata.String
	}

	return secret, nil
}

// ListByTeam lists all secrets for a team
func (r *SecretsRepository) ListByTeam(teamID int64, includeValues bool) ([]*models.Secret, error) {
	query := `
		SELECT id, team_id, path, name, type, encrypted_value, metadata, version, created_by, created_at, updated_by, updated_at
		FROM secrets
		WHERE team_id = ? AND deleted_at IS NULL
		ORDER BY path ASC
	`

	rows, err := r.db.Query(query, teamID)
	if err != nil {
		return nil, fmt.Errorf("querying secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*models.Secret
	for rows.Next() {
		secret := &models.Secret{}
		var createdAt, updatedAt int64
		var updatedBy sql.NullInt64
		var metadata sql.NullString

		err := rows.Scan(
			&secret.ID, &secret.TeamID, &secret.Path, &secret.Name, &secret.Type,
			&secret.EncryptedValue, &metadata, &secret.Version, &secret.CreatedBy,
			&createdAt, &updatedBy, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning secret: %w", err)
		}

		// Only decrypt if requested
		if includeValues {
			decrypted, err := r.keyManager.Decrypt(secret.EncryptedValue)
			if err != nil {
				return nil, fmt.Errorf("decrypting secret: %w", err)
			}
			secret.Value = string(decrypted)
		}
		secret.EncryptedValue = ""

		secret.CreatedAt = time.Unix(createdAt, 0)
		secret.UpdatedAt = time.Unix(updatedAt, 0)
		if updatedBy.Valid {
			secret.UpdatedBy = updatedBy.Int64
		}
		if metadata.Valid {
			secret.Metadata = metadata.String
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// Update updates a secret and creates a new version
func (r *SecretsRepository) Update(secret *models.Secret) error {
	// Encrypt the new value
	encrypted, err := r.keyManager.Encrypt([]byte(secret.Value))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	// Get current version
	var currentVersion int
	err = r.db.QueryRow("SELECT version FROM secrets WHERE id = ?", secret.ID).Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("getting current version: %w", err)
	}

	newVersion := currentVersion + 1

	// Update the secret
	query := `
		UPDATE secrets
		SET encrypted_value = ?, metadata = ?, version = ?, updated_by = ?, updated_at = strftime('%s', 'now')
		WHERE id = ?
	`

	_, err = r.db.Exec(query, encrypted, secret.Metadata, newVersion, secret.UpdatedBy, secret.ID)
	if err != nil {
		return fmt.Errorf("updating secret: %w", err)
	}

	secret.Version = newVersion
	secret.EncryptedValue = encrypted

	// Create version record
	if err := r.createVersion(secret); err != nil {
		return fmt.Errorf("creating version: %w", err)
	}

	secret.Value = ""
	return nil
}

// Delete soft-deletes a secret
func (r *SecretsRepository) Delete(id int64) error {
	query := `UPDATE secrets SET deleted_at = strftime('%s', 'now') WHERE id = ?`
	_, err := r.db.Exec(query, id)
	return err
}

// HardDelete permanently deletes a secret and all versions
func (r *SecretsRepository) HardDelete(id int64) error {
	// Delete versions first
	_, err := r.db.Exec("DELETE FROM secret_versions WHERE secret_id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting versions: %w", err)
	}

	// Delete secret
	_, err = r.db.Exec("DELETE FROM secrets WHERE id = ?", id)
	return err
}

// createVersion creates a version record
func (r *SecretsRepository) createVersion(secret *models.Secret) error {
	query := `
		INSERT INTO secret_versions (secret_id, version, encrypted_value, metadata, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, strftime('%s', 'now'))
	`

	_, err := r.db.Exec(query, secret.ID, secret.Version, secret.EncryptedValue, secret.Metadata, secret.CreatedBy)
	return err
}

// GetVersions lists all versions of a secret
func (r *SecretsRepository) GetVersions(secretID int64) ([]*models.SecretVersion, error) {
	query := `
		SELECT id, secret_id, version, encrypted_value, metadata, created_by, created_at
		FROM secret_versions
		WHERE secret_id = ?
		ORDER BY version DESC
	`

	rows, err := r.db.Query(query, secretID)
	if err != nil {
		return nil, fmt.Errorf("querying versions: %w", err)
	}
	defer rows.Close()

	var versions []*models.SecretVersion
	for rows.Next() {
		version := &models.SecretVersion{}
		var createdAt int64
		var metadata sql.NullString

		err := rows.Scan(
			&version.ID, &version.SecretID, &version.Version,
			&version.EncryptedValue, &metadata, &version.CreatedBy, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning version: %w", err)
		}

		version.CreatedAt = time.Unix(createdAt, 0)
		if metadata.Valid {
			version.Metadata = metadata.String
		}
		version.EncryptedValue = ""

		versions = append(versions, version)
	}

	return versions, nil
}

// GetVersion retrieves a specific version of a secret
func (r *SecretsRepository) GetVersion(secretID int64, version int) (*models.SecretVersion, error) {
	query := `
		SELECT id, secret_id, version, encrypted_value, metadata, created_by, created_at
		FROM secret_versions
		WHERE secret_id = ? AND version = ?
	`

	v := &models.SecretVersion{}
	var createdAt int64
	var metadata sql.NullString

	err := r.db.QueryRow(query, secretID, version).Scan(
		&v.ID, &v.SecretID, &v.Version,
		&v.EncryptedValue, &metadata, &v.CreatedBy, &createdAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying version: %w", err)
	}

	// Decrypt the value
	decrypted, err := r.keyManager.Decrypt(v.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypting version: %w", err)
	}
	v.Value = string(decrypted)

	v.CreatedAt = time.Unix(createdAt, 0)
	if metadata.Valid {
		v.Metadata = metadata.String
	}

	return v, nil
}

// Rollback rolls back a secret to a specific version
func (r *SecretsRepository) Rollback(secretID int64, targetVersion int, userID int64) error {
	// Get the target version
	version, err := r.GetVersion(secretID, targetVersion)
	if err != nil {
		return fmt.Errorf("getting target version: %w", err)
	}
	if version == nil {
		return fmt.Errorf("version %d not found", targetVersion)
	}

	// Get current secret
	secret, err := r.GetByID(secretID)
	if err != nil {
		return fmt.Errorf("getting secret: %w", err)
	}
	if secret == nil {
		return fmt.Errorf("secret not found")
	}

	// Update secret with rolled-back value
	secret.Value = version.Value
	secret.Metadata = version.Metadata
	secret.UpdatedBy = userID

	return r.Update(secret)
}
