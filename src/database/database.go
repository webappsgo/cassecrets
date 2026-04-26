package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// Database wraps the SQLite database connections
type Database struct {
	ServerDB *sql.DB
	UsersDB  *sql.DB
	dataDir  string
	mu       sync.RWMutex
}

// Open opens both server.db and users.db SQLite databases
func Open(dataDir string) (*Database, error) {
	dbDir := filepath.Join(dataDir, "db")

	// Create database directory if it doesn't exist
	if err := os.MkdirAll(dbDir, 0750); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	// Open server.db
	serverDBPath := filepath.Join(dbDir, "server.db")
	serverDB, err := sql.Open("sqlite", serverDBPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("opening server.db: %w", err)
	}

	// Test server.db connection
	if err := serverDB.Ping(); err != nil {
		serverDB.Close()
		return nil, fmt.Errorf("pinging server.db: %w", err)
	}

	// Open users.db
	usersDBPath := filepath.Join(dbDir, "users.db")
	usersDB, err := sql.Open("sqlite", usersDBPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		serverDB.Close()
		return nil, fmt.Errorf("opening users.db: %w", err)
	}

	// Test users.db connection
	if err := usersDB.Ping(); err != nil {
		serverDB.Close()
		usersDB.Close()
		return nil, fmt.Errorf("pinging users.db: %w", err)
	}

	db := &Database{
		ServerDB: serverDB,
		UsersDB:  usersDB,
		dataDir:  dataDir,
	}

	// Initialize schema
	if err := db.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing schema: %w", err)
	}

	return db, nil
}

// Close closes both database connections
func (db *Database) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	var errs []error

	if db.ServerDB != nil {
		if err := db.ServerDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing server.db: %w", err))
		}
	}

	if db.UsersDB != nil {
		if err := db.UsersDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing users.db: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("closing databases: %v", errs)
	}

	return nil
}

// initSchema initializes both database schemas
func (db *Database) initSchema() error {
	// Initialize server.db schema
	if err := db.initServerSchema(); err != nil {
		return fmt.Errorf("initializing server schema: %w", err)
	}

	// Initialize users.db schema
	if err := db.initUsersSchema(); err != nil {
		return fmt.Errorf("initializing users schema: %w", err)
	}

	// Initialize cassecrets-specific schema
	if err := db.initSecretsSchema(); err != nil {
		return fmt.Errorf("initializing secrets schema: %w", err)
	}

	return nil
}

// DataDir returns the data directory path
func (db *Database) DataDir() string {
	return db.dataDir
}
