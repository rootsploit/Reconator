//go:build darwin
// +build darwin

package sysinfo

import (
	"syscall"
	"unsafe"
)

// getMemoryMB returns total system memory in MB
func getMemoryMB() int64 {
	// Use sysctl to get hw.memsize on macOS
	mib := []int32{6, 24} // CTL_HW, HW_MEMSIZE

	var memsize int64
	size := unsafe.Sizeof(memsize)

	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&memsize)),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)

	if errno != 0 {
		// Fallback: assume 4GB if detection fails
		return 4096
	}

	return memsize / (1024 * 1024)
}
