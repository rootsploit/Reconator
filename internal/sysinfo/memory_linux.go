//go:build linux
// +build linux

package sysinfo

import (
	"syscall"
)

// getMemoryMB returns total system memory in MB
func getMemoryMB() int64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		// Fallback: assume 4GB if detection fails
		return 4096
	}
	// Sysinfo returns memory in bytes, account for unit multiplier
	return int64(info.Totalram) * int64(info.Unit) / (1024 * 1024)
}
