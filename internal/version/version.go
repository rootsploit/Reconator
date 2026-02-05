package version

import (
	"fmt"
	"runtime"
)

// Version information - set at build time with ldflags
var (
	Version   = "1.1.0"
	Commit    = "dev"
	BuildDate = "unknown"
)

// Info returns formatted version information
func Info() string {
	return fmt.Sprintf("reconator version %s\n  go: %s\n  os/arch: %s/%s",
		Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// Short returns just the version string
func Short() string {
	return Version
}

// Full returns version string
func Full() string {
	return Version
}
