package tools

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Platform holds information about the current system
type Platform struct {
	OS       string // linux, darwin, windows
	Arch     string // amd64, arm64
	PkgMgr   string // apt, brew, yum, dnf, pacman, choco, ""
	HasSudo  bool
	HomeDir  string
	GoBinDir string
}

// DetectPlatform returns information about the current system
func DetectPlatform() *Platform {
	p := &Platform{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// Normalize architecture names
	switch p.Arch {
	case "amd64", "x86_64":
		p.Arch = "amd64"
	case "arm64", "aarch64":
		p.Arch = "arm64"
	}

	// Detect package manager
	p.PkgMgr = detectPackageManager()

	// Check for sudo
	_, err := exec.LookPath("sudo")
	p.HasSudo = err == nil

	// Get home directory
	p.HomeDir, _ = os.UserHomeDir()

	// Get Go bin directory
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = p.HomeDir + "/go"
	}
	p.GoBinDir = gopath + "/bin"

	return p
}

func detectPackageManager() string {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			return "brew"
		}
	case "linux":
		// Check in order of preference
		pkgMgrs := []string{"apt", "apt-get", "dnf", "yum", "pacman", "apk", "zypper"}
		for _, pm := range pkgMgrs {
			if _, err := exec.LookPath(pm); err == nil {
				return pm
			}
		}
	case "windows":
		if _, err := exec.LookPath("choco"); err == nil {
			return "choco"
		}
		if _, err := exec.LookPath("winget"); err == nil {
			return "winget"
		}
		if _, err := exec.LookPath("scoop"); err == nil {
			return "scoop"
		}
	}
	return ""
}

// InstallSystemPackage installs a package using the system package manager
func (p *Platform) InstallSystemPackage(pkg string) error {
	if p.PkgMgr == "" {
		return fmt.Errorf("no package manager found")
	}

	var cmd *exec.Cmd
	switch p.PkgMgr {
	case "apt", "apt-get":
		if p.HasSudo {
			cmd = exec.Command("sudo", p.PkgMgr, "install", "-y", pkg)
		} else {
			cmd = exec.Command(p.PkgMgr, "install", "-y", pkg)
		}
	case "brew":
		cmd = exec.Command("brew", "install", pkg)
	case "dnf", "yum":
		if p.HasSudo {
			cmd = exec.Command("sudo", p.PkgMgr, "install", "-y", pkg)
		} else {
			cmd = exec.Command(p.PkgMgr, "install", "-y", pkg)
		}
	case "pacman":
		if p.HasSudo {
			cmd = exec.Command("sudo", "pacman", "-S", "--noconfirm", pkg)
		} else {
			cmd = exec.Command("pacman", "-S", "--noconfirm", pkg)
		}
	case "apk":
		if p.HasSudo {
			cmd = exec.Command("sudo", "apk", "add", pkg)
		} else {
			cmd = exec.Command("apk", "add", pkg)
		}
	case "choco":
		cmd = exec.Command("choco", "install", "-y", pkg)
	case "winget":
		cmd = exec.Command("winget", "install", "-e", "--id", pkg)
	case "scoop":
		cmd = exec.Command("scoop", "install", pkg)
	default:
		return fmt.Errorf("unsupported package manager: %s", p.PkgMgr)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// GetLibpcapPackage returns the libpcap package name for this platform
func (p *Platform) GetLibpcapPackage() string {
	switch p.PkgMgr {
	case "apt", "apt-get":
		return "libpcap-dev"
	case "dnf", "yum":
		return "libpcap-devel"
	case "pacman":
		return "libpcap"
	case "apk":
		return "libpcap-dev"
	case "brew":
		return "libpcap"
	default:
		return "libpcap-dev"
	}
}

// GetMassdnsPackage returns the massdns package name for this platform
func (p *Platform) GetMassdnsPackage() string {
	switch p.PkgMgr {
	case "brew":
		return "massdns"
	case "apt", "apt-get":
		return "massdns" // Available on newer Ubuntu
	default:
		return "" // Build from source
	}
}

// String returns a human-readable description of the platform
func (p *Platform) String() string {
	return fmt.Sprintf("%s/%s (pkg: %s)", p.OS, p.Arch, p.PkgMgr)
}

// HasLibpcap checks if libpcap is installed on this platform
func (p *Platform) HasLibpcap() bool {
	switch p.OS {
	case "darwin":
		// macOS has libpcap built-in, but headers might be missing
		locations := []string{
			"/usr/include/pcap.h",
			"/opt/homebrew/include/pcap.h",
			"/usr/local/include/pcap.h",
			"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/pcap.h",
		}
		for _, loc := range locations {
			if _, err := os.Stat(loc); err == nil {
				return true
			}
		}
		return false
	case "linux":
		locations := []string{
			"/usr/include/pcap.h",
			"/usr/include/pcap/pcap.h",
		}
		for _, loc := range locations {
			if _, err := os.Stat(loc); err == nil {
				return true
			}
		}
		return false
	case "windows":
		// Windows uses npcap/winpcap
		if _, err := os.Stat("C:\\Windows\\System32\\wpcap.dll"); err == nil {
			return true
		}
		if _, err := os.Stat("C:\\Windows\\System32\\Npcap\\wpcap.dll"); err == nil {
			return true
		}
		return false
	}
	return false
}

// GetPrebuiltURL returns the URL for a pre-built binary if available
func (p *Platform) GetPrebuiltURL(tool, version string) string {
	// Map of tools to their GitHub release URL patterns
	switch tool {
	case "massdns":
		// massdns doesn't have official releases, need to build
		return ""
	case "naabu":
		// projectdiscovery releases
		osName := p.OS
		if osName == "darwin" {
			osName = "macOS"
		}
		return fmt.Sprintf("https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_%s_%s.zip", osName, p.Arch)
	}
	return ""
}
