package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds all path configurations
type Config struct {
	ConfigDir string
	DataDir   string
	LogDir    string
	PIDFile   string
	IsRoot    bool
}

// Initialize sets up and validates all paths
func Initialize(configDir, dataDir, logDir, pidFile string) *Config {
	isRoot := os.Geteuid() == 0

	cfg := &Config{
		ConfigDir: getConfigDir(configDir, isRoot),
		DataDir:   getDataDir(dataDir, isRoot),
		LogDir:    getLogDir(logDir, isRoot),
		PIDFile:   getPIDFile(pidFile, isRoot),
		IsRoot:    isRoot,
	}

	// Ensure directories exist
	ensureDir(cfg.ConfigDir, isRoot)
	ensureDir(cfg.DataDir, isRoot)
	ensureDir(cfg.LogDir, isRoot)
	ensurePIDDir(cfg.PIDFile, isRoot)

	return cfg
}

// getConfigDir returns the config directory path
func getConfigDir(custom string, isRoot bool) string {
	if custom != "" {
		return custom
	}

	if isRoot {
		return "/etc/casapps/cassecrets"
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "casapps", "cassecrets")
}

// getDataDir returns the data directory path
func getDataDir(custom string, isRoot bool) string {
	if custom != "" {
		return custom
	}

	if isRoot {
		return "/var/lib/casapps/cassecrets"
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "casapps", "cassecrets")
}

// getLogDir returns the log directory path
func getLogDir(custom string, isRoot bool) string {
	if custom != "" {
		return custom
	}

	if isRoot {
		return "/var/log/casapps/cassecrets"
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "casapps", "cassecrets", "logs")
}

// getPIDFile returns the PID file path
func getPIDFile(custom string, isRoot bool) string {
	if custom != "" {
		return custom
	}

	if isRoot {
		return "/var/run/casapps/cassecrets.pid"
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "casapps", "cassecrets", "cassecrets.pid")
}

// ensureDir creates a directory if it doesn't exist
func ensureDir(path string, isRoot bool) error {
	perm := os.FileMode(0700)
	if isRoot {
		perm = 0755
	}

	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	// Verify writable
	testFile := filepath.Join(path, ".write-test")
	if err := os.WriteFile(testFile, []byte{}, 0600); err != nil {
		return fmt.Errorf("directory %s is not writable: %w", path, err)
	}
	os.Remove(testFile)

	return nil
}

// ensurePIDDir creates the PID file directory
func ensurePIDDir(pidFile string, isRoot bool) error {
	dir := filepath.Dir(pidFile)
	return ensureDir(dir, isRoot)
}
