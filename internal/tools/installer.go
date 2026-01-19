package tools

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Installer struct {
	c        *Checker
	platform *Platform
}

func NewInstaller() *Installer {
	return &Installer{
		c:        NewChecker(),
		platform: DetectPlatform(),
	}
}

func (i *Installer) GetPlatform() *Platform    { return i.platform }
func (i *Installer) GetGoTools() []Tool        { return GoTools() }
func (i *Installer) GetPythonTools() []Tool    { return PythonTools() }
func (i *Installer) GetRustTools() []Tool      { return RustTools() }
func (i *Installer) GetWordlists() []Wordlist  { return GetWordlists() }
func (i *Installer) IsInstalled(name string) bool { return i.c.IsInstalled(name) }

func (i *Installer) InstallWordlist(wl Wordlist) error {
	return DownloadWordlist(wl)
}

// ProjectDiscovery tools that can be installed via pdtm
var pdtmTools = map[string]bool{
	"subfinder": true,
	"httpx":     true,
	"dnsx":      true,
	"naabu":     true,
	"nuclei":    true,
	"katana":    true,
	"tlsx":      true,
	"cdncheck":  true,
	"alterx":    true,
	"urlfinder": true,
}

// System tools that need package manager installation
var systemTools = map[string]map[string]string{
	"nmap": {
		"apt":     "nmap",
		"dnf":     "nmap",
		"yum":     "nmap",
		"pacman":  "nmap",
		"brew":    "nmap",
		"apk":     "nmap",
		"choco":   "nmap",
		"winget":  "nmap",
		"default": "nmap",
	},
	"python3": {
		"apt":     "python3",
		"dnf":     "python3",
		"yum":     "python3",
		"pacman":  "python",
		"brew":    "python3",
		"apk":     "python3",
		"choco":   "python3",
		"default": "python3",
	},
	"pipx": {
		"apt":     "pipx",
		"dnf":     "pipx",
		"brew":    "pipx",
		"pacman":  "python-pipx",
		"default": "",
	},
	"git": {
		"apt":     "git",
		"dnf":     "git",
		"yum":     "git",
		"pacman":  "git",
		"brew":    "git",
		"apk":     "git",
		"choco":   "git",
		"default": "git",
	},
}

// InstallGoTool installs a Go-based tool with platform-aware fallbacks
func (i *Installer) InstallGoTool(t Tool) error {
	if i.c.IsInstalled(t.Binary) {
		return nil
	}

	// Handle special cases
	switch t.Name {
	case "massdns":
		return i.installMassdns()
	case "naabu":
		// Try pdtm first, then check libpcap
		if i.tryPdtm("naabu") {
			return nil
		}
		if !i.platform.HasLibpcap() {
			return fmt.Errorf("needs %s: %s", i.platform.GetLibpcapPackage(), i.getLibpcapInstallCmd())
		}
	}

	// For ProjectDiscovery tools, try pdtm first (handles dependencies automatically)
	if pdtmTools[t.Name] {
		if i.tryPdtm(t.Name) {
			return nil
		}
	}

	// Standard go install
	if t.InstallCmd == "" {
		return fmt.Errorf("no install command")
	}
	out, err := exec.Command("go", "install", t.InstallCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// tryPdtm attempts to install a tool using pdtm
func (i *Installer) tryPdtm(tool string) bool {
	// First ensure pdtm is installed
	if !i.c.IsInstalled("pdtm") {
		// Try to install pdtm
		out, err := exec.Command("go", "install", "github.com/projectdiscovery/pdtm/cmd/pdtm@latest").CombinedOutput()
		if err != nil {
			_ = out
			return false
		}
	}

	// Use pdtm to install the tool
	out, err := exec.Command("pdtm", "-i", tool).CombinedOutput()
	if err != nil {
		_ = out
		return false
	}

	// Verify installation
	return i.c.IsInstalled(tool)
}

func (i *Installer) getLibpcapInstallCmd() string {
	switch i.platform.PkgMgr {
	case "apt", "apt-get":
		return "sudo apt install libpcap-dev"
	case "dnf", "yum":
		return "sudo dnf install libpcap-devel"
	case "pacman":
		return "sudo pacman -S libpcap"
	case "brew":
		return "brew install libpcap"
	case "apk":
		return "sudo apk add libpcap-dev"
	default:
		return "install libpcap development package"
	}
}

func (i *Installer) installMassdns() error {
	if i.c.IsInstalled("massdns") {
		return nil
	}

	// Try package manager first
	pkg := i.platform.GetMassdnsPackage()
	if pkg != "" {
		if err := i.platform.InstallSystemPackage(pkg); err == nil {
			if i.c.IsInstalled("massdns") {
				return nil
			}
		}
	}

	// Build from source as fallback
	return i.buildMassdnsFromSource()
}

func (i *Installer) buildMassdnsFromSource() error {
	tmpDir, err := os.MkdirTemp("", "massdns-build")
	if err != nil {
		return fmt.Errorf("install manually: git clone https://github.com/blechschmidt/massdns && cd massdns && make && sudo make install")
	}
	defer os.RemoveAll(tmpDir)

	// Clone
	out, err := exec.Command("git", "clone", "--depth=1", "https://github.com/blechschmidt/massdns.git", tmpDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s", strings.TrimSpace(string(out)))
	}

	// Build
	cmd := exec.Command("make")
	cmd.Dir = tmpDir
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("make failed: %s", strings.TrimSpace(string(out)))
	}

	// Install to Go bin directory
	srcBin := filepath.Join(tmpDir, "bin", "massdns")
	dstBin := filepath.Join(i.platform.GoBinDir, "massdns")

	// Ensure bin directory exists
	os.MkdirAll(i.platform.GoBinDir, 0755)

	// Copy binary
	if _, err := exec.Command("cp", srcBin, dstBin).CombinedOutput(); err != nil {
		// Try sudo install to /usr/local/bin
		if i.platform.HasSudo {
			if out, err := exec.Command("sudo", "cp", srcBin, "/usr/local/bin/massdns").CombinedOutput(); err != nil {
				return fmt.Errorf("install failed: %s", strings.TrimSpace(string(out)))
			}
			exec.Command("sudo", "chmod", "+x", "/usr/local/bin/massdns").Run()
			return nil
		}
		return fmt.Errorf("failed to copy binary")
	}
	exec.Command("chmod", "+x", dstBin).Run()

	return nil
}

func (i *Installer) InstallPythonTool(t Tool) error {
	if i.c.IsInstalled(t.Binary) {
		return nil
	}

	// Try pipx first (recommended)
	if i.c.IsInstalled("pipx") {
		out, err := exec.Command("pipx", "install", t.InstallCmd).CombinedOutput()
		if err != nil {
			// Check if already installed
			if strings.Contains(string(out), "already") {
				return nil
			}
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Try pip3
	if i.c.IsInstalled("pip3") {
		out, err := exec.Command("pip3", "install", "--user", t.InstallCmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		// Check if ~/.local/bin is in PATH
		localBin := filepath.Join(i.platform.HomeDir, ".local", "bin")
		if !strings.Contains(os.Getenv("PATH"), localBin) {
			return fmt.Errorf("installed, add %s to PATH", localBin)
		}
		return nil
	}

	// Suggest installing pipx
	return fmt.Errorf("pipx/pip3 not found - install with: %s", i.getPipxInstallCmd())
}

func (i *Installer) getPipxInstallCmd() string {
	switch i.platform.PkgMgr {
	case "apt", "apt-get":
		return "sudo apt install pipx"
	case "dnf":
		return "sudo dnf install pipx"
	case "brew":
		return "brew install pipx"
	case "pacman":
		return "sudo pacman -S python-pipx"
	default:
		return "pip3 install --user pipx"
	}
}

func (i *Installer) InstallRustTool(t Tool) error {
	if i.c.IsInstalled(t.Binary) {
		return nil
	}

	// Try package manager first (much faster than cargo)
	pkgName := i.getRustToolPkgName(t.Name)
	if pkgName != "" {
		if err := i.platform.InstallSystemPackage(pkgName); err == nil {
			if i.c.IsInstalled(t.Binary) {
				return nil
			}
		}
	}

	// Try downloading pre-built binary from GitHub releases
	if err := i.downloadRustToolRelease(t.Name); err == nil {
		if i.c.IsInstalled(t.Binary) {
			return nil
		}
	}

	// Fall back to cargo (only for tools that are actually on crates.io)
	if t.Name == "vita" || t.Name == "findomain" {
		// These tools are not on crates.io as binaries
		return fmt.Errorf("download from GitHub releases failed")
	}

	if !i.c.IsInstalled("cargo") {
		return fmt.Errorf("cargo not found - install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
	}

	out, err := exec.Command("cargo", "install", t.InstallCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// downloadRustToolRelease downloads a pre-built binary from GitHub releases
func (i *Installer) downloadRustToolRelease(tool string) error {
	var url, assetName string

	switch tool {
	case "findomain":
		// Findomain uses simple naming: findomain-linux.zip, findomain-osx.zip
		osName := "linux"
		if i.platform.OS == "darwin" {
			osName = "osx"
		}
		assetName = fmt.Sprintf("findomain-%s.zip", osName)
		url = fmt.Sprintf("https://github.com/findomain/findomain/releases/latest/download/%s", assetName)

	case "feroxbuster":
		// Feroxbuster uses: x86_64-linux-feroxbuster.zip, x86_64-macos-feroxbuster.zip
		archName := "x86_64"
		if i.platform.Arch == "arm64" {
			archName = "aarch64"
		}
		osName := "linux"
		if i.platform.OS == "darwin" {
			osName = "macos"
		}
		assetName = fmt.Sprintf("%s-%s-feroxbuster.zip", archName, osName)
		url = fmt.Sprintf("https://github.com/epi052/feroxbuster/releases/latest/download/%s", assetName)

	default:
		return fmt.Errorf("no release info for %s", tool)
	}

	// Download to temp location
	tmpDir, err := os.MkdirTemp("", tool+"-download")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	downloadPath := filepath.Join(tmpDir, assetName)
	if err := DownloadFile(url, downloadPath); err != nil {
		return fmt.Errorf("download failed: %v", err)
	}

	// Handle zip files
	var binaryPath string
	if strings.HasSuffix(assetName, ".zip") {
		if err := Unzip(downloadPath, tmpDir); err != nil {
			return fmt.Errorf("unzip failed: %v", err)
		}
		binaryPath = filepath.Join(tmpDir, tool)
	} else {
		binaryPath = downloadPath
	}

	// Make executable
	os.Chmod(binaryPath, 0755)

	// Move to Go bin directory
	dstPath := filepath.Join(i.platform.GoBinDir, tool)
	os.MkdirAll(i.platform.GoBinDir, 0755)

	if _, err := exec.Command("mv", binaryPath, dstPath).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to move binary: %v", err)
	}

	return nil
}

// InstallRust installs Rust via rustup
func (i *Installer) InstallRust() error {
	if i.c.IsInstalled("cargo") {
		return nil
	}

	// Download and run rustup
	cmd := exec.Command("sh", "-c", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rustup failed: %s", strings.TrimSpace(string(out)))
	}

	// Source the cargo env
	cargoEnv := filepath.Join(i.platform.HomeDir, ".cargo", "env")
	if _, err := os.Stat(cargoEnv); err == nil {
		os.Setenv("PATH", filepath.Join(i.platform.HomeDir, ".cargo", "bin")+":"+os.Getenv("PATH"))
	}

	return nil
}

func (i *Installer) getRustToolPkgName(tool string) string {
	// Package names vary by package manager
	switch tool {
	case "feroxbuster":
		switch i.platform.PkgMgr {
		case "apt", "apt-get":
			return "feroxbuster" // Ubuntu 22.04+
		case "brew":
			return "feroxbuster"
		}
	case "findomain":
		switch i.platform.PkgMgr {
		case "brew":
			return "findomain"
		}
	}
	return ""
}

func (i *Installer) tryPrebuiltBinary(tool string) bool {
	// Map of tools to their GitHub release patterns
	releases := map[string]struct {
		repo    string
		pattern string // {os}, {arch} will be replaced
	}{
		"feroxbuster": {
			repo:    "epi052/feroxbuster",
			pattern: "feroxbuster-{version}-{target}.zip",
		},
	}

	release, ok := releases[tool]
	if !ok {
		return false
	}

	// Determine target triple
	target := i.getTargetTriple()
	if target == "" {
		return false
	}

	// Try to download (this is a simplified version)
	_ = release
	return false // Disable for now, use package manager or cargo
}

func (i *Installer) getTargetTriple() string {
	switch i.platform.OS {
	case "linux":
		switch i.platform.Arch {
		case "amd64":
			return "x86_64-unknown-linux-gnu"
		case "arm64":
			return "aarch64-unknown-linux-gnu"
		}
	case "darwin":
		switch i.platform.Arch {
		case "amd64":
			return "x86_64-apple-darwin"
		case "arm64":
			return "aarch64-apple-darwin"
		}
	case "windows":
		switch i.platform.Arch {
		case "amd64":
			return "x86_64-pc-windows-msvc"
		}
	}
	return ""
}

// InstallLibpcap installs the libpcap development package
func (i *Installer) InstallLibpcap() error {
	if i.platform.HasLibpcap() {
		return nil
	}

	pkg := i.platform.GetLibpcapPackage()
	return i.platform.InstallSystemPackage(pkg)
}

// InstallSystemTool installs a system tool using the package manager
func (i *Installer) InstallSystemTool(name string) error {
	if i.c.IsInstalled(name) {
		return nil
	}

	pkgMap, ok := systemTools[name]
	if !ok {
		return fmt.Errorf("unknown system tool: %s", name)
	}

	// Get package name for this package manager
	pkg := pkgMap[i.platform.PkgMgr]
	if pkg == "" {
		pkg = pkgMap["default"]
	}
	if pkg == "" {
		return fmt.Errorf("no package available for %s on %s", name, i.platform.PkgMgr)
	}

	return i.platform.InstallSystemPackage(pkg)
}

// InstallNucleiTemplates clones or updates nuclei templates
func (i *Installer) InstallNucleiTemplates() error {
	templatesDir := filepath.Join(i.platform.HomeDir, "nuclei-templates")
	gitDir := filepath.Join(templatesDir, ".git")

	// Check if templates directory exists
	if _, err := os.Stat(templatesDir); err == nil {
		// Check if it's actually a git repository
		if _, err := os.Stat(gitDir); err == nil {
			// It's a git repo, update it
			cmd := exec.Command("git", "-C", templatesDir, "pull", "--quiet")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("update failed: %s", strings.TrimSpace(string(out)))
			}
			return nil
		}
		// Directory exists but not a git repo - remove and re-clone
		if err := os.RemoveAll(templatesDir); err != nil {
			return fmt.Errorf("failed to remove existing directory: %v", err)
		}
	}

	// Clone templates
	out, err := exec.Command("git", "clone", "--depth=1", "https://github.com/projectdiscovery/nuclei-templates.git", templatesDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("clone failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// GetSystemTools returns the list of system tools to install
func (i *Installer) GetSystemTools() []string {
	tools := make([]string, 0, len(systemTools))
	for name := range systemTools {
		tools = append(tools, name)
	}
	return tools
}

// ChromeInfo holds Chrome installation details
type ChromeInfo struct {
	Installed bool
	Path      string
	Version   string
}

// Common Chrome paths by OS (exported for use by other packages)
var ChromePaths = map[string][]string{
	"darwin": {
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	},
	"linux": {
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
	},
	"windows": {
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	},
}

// CheckChrome checks if Chrome/Chromium is installed and returns its info
func (i *Installer) CheckChrome() *ChromeInfo {
	info := &ChromeInfo{}

	// Check common paths for this OS
	paths, ok := ChromePaths[i.platform.OS]
	if !ok {
		return info
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			info.Installed = true
			info.Path = p

			// Try to get version
			out, err := exec.Command(p, "--version").Output()
			if err == nil {
				info.Version = strings.TrimSpace(string(out))
			}
			return info
		}
	}

	// Also check if it's in PATH (common on Linux)
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			info.Installed = true
			info.Path = path
			out, _ := exec.Command(path, "--version").Output()
			info.Version = strings.TrimSpace(string(out))
			return info
		}
	}

	return info
}

// GetChromeInstallInstructions returns OS-specific Chrome install instructions
func (i *Installer) GetChromeInstallInstructions() string {
	switch i.platform.OS {
	case "darwin":
		return "Install Google Chrome from https://www.google.com/chrome/ or run: brew install --cask google-chrome"
	case "linux":
		switch i.platform.PkgMgr {
		case "apt", "apt-get":
			return "Install Chromium: sudo apt install chromium-browser"
		case "dnf":
			return "Install Chromium: sudo dnf install chromium"
		case "pacman":
			return "Install Chromium: sudo pacman -S chromium"
		default:
			return "Install Google Chrome or Chromium browser"
		}
	case "windows":
		return "Install Google Chrome from https://www.google.com/chrome/"
	default:
		return "Install Google Chrome or Chromium browser"
	}
}

// DownloadFile downloads a file from a URL to the specified path
func DownloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// Unzip extracts a zip file to the specified directory
func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}
