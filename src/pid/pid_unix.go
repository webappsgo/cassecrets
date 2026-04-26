//go:build !windows
// +build !windows

package pid

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const projectName = "cassecrets"

// isProcessRunning checks if a process with given PID exists (Unix)
func isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds - need to send signal 0
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// isOurProcess verifies the process is actually our binary (Unix)
func isOurProcess(pid int) bool {
	// Read /proc/{pid}/exe symlink (Linux)
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		return strings.Contains(filepath.Base(exePath), projectName)
	}

	// On macOS/BSD, use ps command
	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" {
		return isOurProcessDarwinBSD(pid)
	}

	// If we can't verify, assume it's ours to avoid accidental file deletion
	return true
}

// isOurProcessDarwinBSD checks process on macOS/BSD
func isOurProcessDarwinBSD(pid int) bool {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), projectName)
}
