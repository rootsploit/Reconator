//go:build !linux && !darwin
// +build !linux,!darwin

package sysinfo

// getMemoryMB returns total system memory in MB
// Fallback for unsupported platforms - assumes 4GB (medium profile)
func getMemoryMB() int64 {
	// Cannot detect memory on this platform, assume 4GB
	return 4096
}
