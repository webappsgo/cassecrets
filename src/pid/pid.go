package pid

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CheckPIDFile checks if PID file exists and if the process is still running
// Returns: (isRunning bool, pid int, err error)
func CheckPIDFile(pidPath string) (bool, int, error) {
	data, err := os.ReadFile(pidPath)
	if os.IsNotExist(err) {
		return false, 0, nil // No PID file, not running
	}
	if err != nil {
		return false, 0, fmt.Errorf("reading pid file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		// Corrupt PID file - remove it
		os.Remove(pidPath)
		return false, 0, nil
	}

	// Check if process is running (platform-specific)
	if !isProcessRunning(pid) {
		// Stale PID file - remove it
		os.Remove(pidPath)
		return false, 0, nil
	}

	// Process exists - verify it's actually our process (not PID reuse)
	if !isOurProcess(pid) {
		// PID was reused by another process - remove stale file
		os.Remove(pidPath)
		return false, 0, nil
	}

	return true, pid, nil
}

// WritePIDFile writes current process PID to file
func WritePIDFile(pidPath string) error {
	// Check for existing running instance first
	running, existingPID, err := CheckPIDFile(pidPath)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("already running (pid %d)", existingPID)
	}

	// Ensure directory exists
	dir := filepath.Dir(pidPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating pid directory: %w", err)
	}

	// Write our PID
	pid := os.Getpid()
	return os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0644)
}

// RemovePIDFile removes PID file on shutdown
func RemovePIDFile(pidPath string) error {
	err := os.Remove(pidPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// GetRunningPID returns the PID of a running instance, or 0 if not running
func GetRunningPID(pidPath string) int {
	running, pid, _ := CheckPIDFile(pidPath)
	if running {
		return pid
	}
	return 0
}
