//go:build !windows
// +build !windows

package signal

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Setup configures graceful shutdown for Unix systems
func Setup(server *http.Server, pidFile string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM,  // kill (default)
		syscall.SIGINT,   // Ctrl+C
		syscall.SIGQUIT,  // Ctrl+\
		syscall.SIGUSR1,  // Reopen logs
		syscall.SIGUSR2,  // Status dump
	)

	// Handle SIGRTMIN+3 (Docker STOPSIGNAL) - signal 37
	signal.Notify(sigChan, syscall.Signal(37))

	// Ignore SIGHUP - config reloads automatically via file watcher
	signal.Ignore(syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGUSR1:
				log.Println("Received SIGUSR1, reopening logs...")
				reopenLogs()

			case syscall.SIGUSR2:
				log.Println("Received SIGUSR2, dumping status...")
				dumpStatus()

			default:
				// Graceful shutdown (SIGTERM, SIGINT, SIGQUIT, SIGRTMIN+3)
				log.Printf("Received %v, starting graceful shutdown...", sig)
				gracefulShutdown(server, pidFile)
			}
		}
	}()
}

// stopChildProcesses sends SIGTERM to children, SIGKILL after timeout (Unix)
func stopChildProcesses(timeout time.Duration) {
	pids := getChildPIDs()
	if len(pids) == 0 {
		return
	}

	// Send SIGTERM (graceful) to all children
	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		process.Signal(syscall.SIGTERM)
	}

	// Wait with timeout, then SIGKILL
	deadline := time.Now().Add(timeout)
	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}

		for time.Now().Before(deadline) {
			// Check if process is still running by sending signal 0
			err := process.Signal(syscall.Signal(0))
			if err != nil {
				break // Process exited
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Force kill if still running
		process.Signal(syscall.SIGKILL)
	}
}

// KillProcess sends signal to process (Unix)
func KillProcess(pid int, graceful bool) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if graceful {
		return process.Signal(syscall.SIGTERM)
	}
	return process.Signal(syscall.SIGKILL)
}

// IsProcessRunning checks if a process with given PID exists (Unix)
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds - need to send signal 0
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
