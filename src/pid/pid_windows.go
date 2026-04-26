//go:build windows
// +build windows

package pid

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const projectName = "cassecrets"

var (
	modKernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                 = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW  = modKernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle                 = modKernel32.NewProc("CloseHandle")
)

const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

// isProcessRunning checks if a process with given PID exists (Windows)
func isProcessRunning(pid int) bool {
	// Try to open the process with minimal permissions
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return false
	}
	defer procCloseHandle.Call(handle)

	// If we got a handle, process exists
	// Check if we got ERROR_ACCESS_DENIED (process exists but no access)
	if err != nil && err != syscall.Errno(0) {
		// ERROR_INVALID_PARAMETER (87) means process doesn't exist
		if err == syscall.Errno(87) {
			return false
		}
	}

	return true
}

// isOurProcess verifies the process is actually our binary (Windows)
func isOurProcess(pid int) bool {
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 || err == syscall.Errno(0) {
		return false
	}
	defer procCloseHandle.Call(handle)

	// Get the process image name
	var buf [512]uint16
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		// If we can't get the name, assume it's ours to be safe
		return true
	}

	exePath := syscall.UTF16ToString(buf[:size])
	baseName := strings.ToLower(filepath.Base(exePath))
	return strings.Contains(baseName, projectName)
}
