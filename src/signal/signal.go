package signal

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	isShuttingDown bool
	shutdownMu     sync.RWMutex
	childPIDs      []int
	childPIDsMu    sync.Mutex
)

// IsShuttingDown returns true if the server is shutting down
func IsShuttingDown() bool {
	shutdownMu.RLock()
	defer shutdownMu.RUnlock()
	return isShuttingDown
}

// setShuttingDown sets the shutdown state
func setShuttingDown(val bool) {
	shutdownMu.Lock()
	defer shutdownMu.Unlock()
	isShuttingDown = val
}

// RegisterChildPID registers a child process PID for cleanup during shutdown
func RegisterChildPID(pid int) {
	childPIDsMu.Lock()
	defer childPIDsMu.Unlock()
	childPIDs = append(childPIDs, pid)
}

// UnregisterChildPID removes a child process PID from the list
func UnregisterChildPID(pid int) {
	childPIDsMu.Lock()
	defer childPIDsMu.Unlock()
	for i, p := range childPIDs {
		if p == pid {
			childPIDs = append(childPIDs[:i], childPIDs[i+1:]...)
			return
		}
	}
}

// getChildPIDs returns a copy of the child PIDs list
func getChildPIDs() []int {
	childPIDsMu.Lock()
	defer childPIDsMu.Unlock()
	result := make([]int, len(childPIDs))
	copy(result, childPIDs)
	return result
}

// ShutdownFunc is a callback for graceful shutdown
type ShutdownFunc func()

var shutdownCallbacks []ShutdownFunc
var shutdownCallbacksMu sync.Mutex

// OnShutdown registers a callback to be called during shutdown
func OnShutdown(fn ShutdownFunc) {
	shutdownCallbacksMu.Lock()
	defer shutdownCallbacksMu.Unlock()
	shutdownCallbacks = append(shutdownCallbacks, fn)
}

// runShutdownCallbacks runs all registered shutdown callbacks
func runShutdownCallbacks() {
	shutdownCallbacksMu.Lock()
	callbacks := make([]ShutdownFunc, len(shutdownCallbacks))
	copy(callbacks, shutdownCallbacks)
	shutdownCallbacksMu.Unlock()

	for _, fn := range callbacks {
		fn()
	}
}

// gracefulShutdown performs orderly shutdown (cross-platform)
func gracefulShutdown(server *http.Server, pidFile string) {
	// Set shutdown flag for health checks
	setShuttingDown(true)

	// Run registered callbacks
	runShutdownCallbacks()

	// Create context with timeout for HTTP server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop accepting new connections, wait for in-flight requests
	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}

	// Stop child processes (platform-specific)
	stopChildProcesses(10 * time.Second)

	// Flush logs (give them a moment)
	time.Sleep(100 * time.Millisecond)

	// Remove PID file
	if pidFile != "" {
		if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
			log.Printf("Failed to remove PID file: %v", err)
		}
	}

	log.Println("Graceful shutdown complete")
	os.Exit(0)
}

// reopenLogs handles SIGUSR1 for log rotation
func reopenLogs() {
	// TODO: Implement log file reopening for log rotation
	log.Println("Log rotation requested (not yet implemented)")
}

// dumpStatus handles SIGUSR2 for status dump
func dumpStatus() {
	// TODO: Dump status information to log
	log.Println("Status dump requested (not yet implemented)")
}
