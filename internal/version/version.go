package version

import (
	"fmt"
	"runtime"
)

// Version information - set at build time via ldflags
var (
	Version   = "0.1.0"
	Commit    = "none"
	Date      = "unknown"
	BuildDate = "dev" // Deprecated: use Date instead
	GitCommit = "none" // Deprecated: use Commit instead
)

// Info returns formatted version information
func Info() string {
	return fmt.Sprintf("reconator version %s\n  commit: %s\n  built: %s\n  go: %s\n  os/arch: %s/%s",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// Short returns just the version string
func Short() string {
	return Version
}

// Full returns version with commit hash
func Full() string {
	if Commit != "none" && len(Commit) > 7 {
		return fmt.Sprintf("%s (%s)", Version, Commit[:7])
	}
	return Version
}
