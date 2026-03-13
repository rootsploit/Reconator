package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const (
	goModulePath = "github.com/rootsploit/reconator"
	goProxyURL   = "https://proxy.golang.org/" + goModulePath + "/@latest"
	userAgent    = "Reconator-Updater/1.0"
)

// UpdateInfo contains information about an available update
type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
}

// Updater handles binary updates
type Updater struct {
	currentVersion string
	httpClient     *http.Client
}

// New creates a new updater instance
func New(currentVersion string) *Updater {
	return &Updater{
		currentVersion: currentVersion,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CheckForUpdate checks if a newer version is available using the Go module proxy
func (u *Updater) CheckForUpdate() (*UpdateInfo, error) {
	latestVersion, err := u.fetchLatestModuleVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to check latest version: %w", err)
	}

	// Parse versions
	current, err := semver.NewVersion(u.currentVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid current version: %w", err)
	}

	latest, err := semver.NewVersion(strings.TrimPrefix(latestVersion, "v"))
	if err != nil {
		return nil, fmt.Errorf("invalid latest version %q: %w", latestVersion, err)
	}

	// Compare versions
	if !latest.GreaterThan(current) {
		return nil, nil // Already up to date
	}

	return &UpdateInfo{
		CurrentVersion: u.currentVersion,
		LatestVersion:  latestVersion,
	}, nil
}

// ForceUpdate runs go install @latest without version checking
func (u *Updater) ForceUpdate(progressCallback func(int64, int64)) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Create backup
	backupPath := execPath + ".old"
	fmt.Printf("Creating backup: %s\n", backupPath)
	if err := copyFile(execPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	fmt.Println("Installing latest version using go install...")
	installPath := goModulePath + "@latest"
	cmd := exec.Command("go", "install", installPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.Remove(backupPath)
		return fmt.Errorf("go install failed: %w (make sure Go is installed and in PATH)", err)
	}

	fmt.Println("Successfully updated to latest version")
	fmt.Printf("  Backup saved: %s\n", backupPath)
	fmt.Println("\nRun 'reconator --version' to verify the update.")
	return nil
}

// Update installs the latest version using go install
func (u *Updater) Update(updateInfo *UpdateInfo, progressCallback func(int64, int64)) error {
	// Get current binary path for reference
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Create backup
	backupPath := execPath + ".old"
	fmt.Printf("Creating backup: %s\n", backupPath)
	if err := copyFile(execPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Install using go install with specific version
	fmt.Printf("Installing %s using go install...\n", updateInfo.LatestVersion)
	installPath := fmt.Sprintf("github.com/rootsploit/reconator@%s", updateInfo.LatestVersion)

	cmd := exec.Command("go", "install", installPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.Remove(backupPath)
		return fmt.Errorf("go install failed: %w (make sure Go is installed and in PATH)", err)
	}

	fmt.Printf("✓ Successfully updated to %s\n", updateInfo.LatestVersion)
	fmt.Printf("  Backup saved: %s\n", backupPath)
	fmt.Println("\nRun 'reconator --version' to verify the update.")
	fmt.Println("Note: The binary is installed to $GOPATH/bin (usually ~/go/bin)")

	return nil
}

// Rollback restores the previous version from backup
func (u *Updater) Rollback() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	backupPath := execPath + ".old"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("no backup found at %s", backupPath)
	}

	fmt.Printf("Rolling back from backup: %s\n", backupPath)
	if err := os.Rename(backupPath, execPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	fmt.Println("✓ Successfully rolled back to previous version")
	return nil
}

// fetchLatestModuleVersion queries the Go module proxy for the latest version
func (u *Updater) fetchLatestModuleVersion() (string, error) {
	req, err := http.NewRequest("GET", goProxyURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		// Fallback: try go list if proxy is unreachable
		return u.fetchVersionViaGoList()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Fallback: try go list
		return u.fetchVersionViaGoList()
	}

	var proxyResp struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&proxyResp); err != nil {
		return "", fmt.Errorf("failed to parse proxy response: %w", err)
	}

	if proxyResp.Version == "" {
		return "", fmt.Errorf("empty version from Go module proxy")
	}

	return proxyResp.Version, nil
}

// fetchVersionViaGoList uses `go list` as fallback when the proxy is unavailable
func (u *Updater) fetchVersionViaGoList() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-json", goModulePath+"@latest")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list failed: %w (make sure Go is installed and in PATH)", err)
	}

	var modInfo struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(output, &modInfo); err != nil {
		return "", fmt.Errorf("failed to parse go list output: %w", err)
	}

	if modInfo.Version == "" {
		return "", fmt.Errorf("empty version from go list")
	}

	return modInfo.Version, nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Copy permissions
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, sourceInfo.Mode())
}

// FormatBytes formats bytes into human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
