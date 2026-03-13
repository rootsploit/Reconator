package sysinfo

import (
	"runtime"
)

// Profile represents a performance profile
type Profile string

const (
	ProfileLow      Profile = "low"      // ≤2GB RAM or ≤2 cores (EC2 t2.micro/small)
	ProfileMedium   Profile = "medium"   // 2-6GB RAM, 2-4 cores (typical laptop)
	ProfileHigh     Profile = "high"     // 6-12GB RAM, 4-6 cores (good laptop)
	ProfileVeryHigh Profile = "veryhigh" // 12-24GB RAM, 6-12 cores (workstation)
	ProfileExtreme  Profile = "extreme"  // >24GB RAM, >12 cores (high-end server)
)

// SystemInfo contains detected system information
type SystemInfo struct {
	TotalMemoryMB int64   // Total RAM in MB
	NumCPU        int     // Number of CPU cores
	Profile       Profile // Detected profile
}

// PerformanceSettings contains recommended settings based on system profile
type PerformanceSettings struct {
	Threads        int
	DNSThreads     int
	MaxConcTargets int
	RateLimit      int // 0 = unlimited
}

// Detect returns system information and detected profile
func Detect() *SystemInfo {
	info := &SystemInfo{
		NumCPU:        runtime.NumCPU(),
		TotalMemoryMB: getMemoryMB(),
	}

	// Determine profile based on RAM and CPU
	info.Profile = determineProfile(info.TotalMemoryMB, info.NumCPU)

	return info
}

// determineProfile selects profile based on available resources
// Uses the more restrictive of memory or CPU constraints
func determineProfile(memoryMB int64, cpuCores int) Profile {
	memProfile := getMemoryProfile(memoryMB)
	cpuProfile := getCPUProfile(cpuCores)

	// Return the more restrictive (lower) profile
	profiles := []Profile{ProfileLow, ProfileMedium, ProfileHigh, ProfileVeryHigh, ProfileExtreme}
	memIdx := profileIndex(memProfile, profiles)
	cpuIdx := profileIndex(cpuProfile, profiles)

	if memIdx < cpuIdx {
		return memProfile
	}
	return cpuProfile
}

// getMemoryProfile returns profile based on RAM
func getMemoryProfile(memoryMB int64) Profile {
	switch {
	case memoryMB <= 2048: // ≤2GB
		return ProfileLow
	case memoryMB <= 6144: // ≤6GB
		return ProfileMedium
	case memoryMB <= 12288: // ≤12GB
		return ProfileHigh
	case memoryMB <= 24576: // ≤24GB
		return ProfileVeryHigh
	default: // >24GB
		return ProfileExtreme
	}
}

// getCPUProfile returns profile based on CPU cores
func getCPUProfile(cpuCores int) Profile {
	switch {
	case cpuCores <= 2:
		return ProfileLow
	case cpuCores <= 4:
		return ProfileMedium
	case cpuCores <= 6:
		return ProfileHigh
	case cpuCores <= 12:
		return ProfileVeryHigh
	default: // >12 cores
		return ProfileExtreme
	}
}

// profileIndex returns the index of a profile in the hierarchy
func profileIndex(p Profile, profiles []Profile) int {
	for i, profile := range profiles {
		if p == profile {
			return i
		}
	}
	return 1 // Default to medium
}

// GetSettings returns recommended performance settings for a profile
func GetSettings(profile Profile) *PerformanceSettings {
	switch profile {
	case ProfileLow:
		// For 2GB RAM / 2 cores (EC2 t2.small, cheap VPS)
		return &PerformanceSettings{
			Threads:        25,
			DNSThreads:     40,
			MaxConcTargets: 1,
			RateLimit:      100,
		}
	case ProfileMedium:
		// For 4GB RAM / 4 cores (typical laptop, t2.medium)
		return &PerformanceSettings{
			Threads:        50,
			DNSThreads:     80,
			MaxConcTargets: 1,
			RateLimit:      200,
		}
	case ProfileHigh:
		// For 8GB RAM / 6 cores (good laptop, t2.large)
		return &PerformanceSettings{
			Threads:        100,
			DNSThreads:     150,
			MaxConcTargets: 2,
			RateLimit:      0, // Unlimited
		}
	case ProfileVeryHigh:
		// For 16GB RAM / 8 cores (workstation, m5.xlarge)
		return &PerformanceSettings{
			Threads:        150,
			DNSThreads:     250,
			MaxConcTargets: 3,
			RateLimit:      0,
		}
	case ProfileExtreme:
		// For 32GB+ RAM / 16+ cores (high-end server)
		return &PerformanceSettings{
			Threads:        250,
			DNSThreads:     400,
			MaxConcTargets: 5,
			RateLimit:      0,
		}
	default:
		return GetSettings(ProfileMedium)
	}
}

// GetSettingsForSystem returns settings based on detected system info
func GetSettingsForSystem() (*PerformanceSettings, *SystemInfo) {
	info := Detect()
	settings := GetSettings(info.Profile)
	return settings, info
}
