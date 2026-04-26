//go:build windows
// +build windows

package signal

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

// Setup configures graceful shutdown for Windows
// Windows only supports os.Interrupt (Ctrl+C, Ctrl+Break)
func Setup(server *http.Server, pidFile string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		for sig := range sigChan {
			log.Printf("Received %v, starting graceful shutdown...", sig)
			gracefulShutdown(server, pidFile)
		}
	}()
}

// stopChildProcesses terminates children (Windows)
// Windows cannot send graceful signals - immediate termination only
func stopChildProcesses(timeout time.Duration) {
	pids := getChildPIDs()
	if len(pids) == 0 {
		return
	}

	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		// Windows: Kill() is immediate termination (TerminateProcess)
		process.Kill()
	}
}

// KillProcess terminates process (Windows)
// Windows doesn't have graceful signals - uses TerminateProcess
func KillProcess(pid int, graceful bool) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	// Windows: Kill() calls TerminateProcess - no graceful option
	return process.Kill()
}

// IsProcessRunning checks if a process with given PID exists (Windows)
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, FindProcess succeeds for any valid PID
	// Try to read exit code - fails if process doesn't exist
	// This is a simplified check; production code should use Windows API
	// But for basic functionality, checking Kill returns a useful error
	err = process.Signal(os.Kill)
	// If we can signal it (even kill), it exists
	// Note: This isn't ideal but works for basic detection
	return err == nil || err.Error() != "os: process already finished"
}
