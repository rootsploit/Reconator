package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const (
	githubAPIURL  = "https://api.github.com/repos/rootsploit/Reconator/releases/latest"
	githubRepoURL = "https://github.com/rootsploit/Reconator"
	userAgent     = "Reconator-Updater/1.0"
)

// Release represents a GitHub release
type Release struct {
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	PublishedAt string  `json:"published_at"`
	Assets      []Asset `json:"assets"`
}

// Asset represents a release asset (binary file)
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateInfo contains information about an available update
type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
	ReleaseNotes   string
	DownloadURL    string
	Checksum       string
	Size           int64
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

// CheckForUpdate checks if a newer version is available
func (u *Updater) CheckForUpdate() (*UpdateInfo, error) {
	// Fetch latest release from GitHub
	release, err := u.fetchLatestRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %w", err)
	}

	// Parse versions
	current, err := semver.NewVersion(u.currentVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid current version: %w", err)
	}

	latest, err := semver.NewVersion(strings.TrimPrefix(release.TagName, "v"))
	if err != nil {
		return nil, fmt.Errorf("invalid latest version: %w", err)
	}

	// Compare versions
	if !latest.GreaterThan(current) {
		return nil, nil // Already up to date
	}

	// Using go install - no need to download binary assets
	return &UpdateInfo{
		CurrentVersion: u.currentVersion,
		LatestVersion:  release.TagName,
		ReleaseNotes:   release.Body,
		DownloadURL:    "",  // Not used with go install
		Checksum:       "",  // Not used with go install
		Size:           0,   // Not used with go install
	}, nil
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

// fetchLatestRelease fetches the latest release from GitHub API
func (u *Updater) fetchLatestRelease() (*Release, error) {
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

// downloadBinary downloads a binary file with progress reporting
func (u *Updater) downloadBinary(url string, size int64, progressCallback func(int64, int64)) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "reconator-update-*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Download with progress
	downloaded := int64(0)
	buffer := make([]byte, 32*1024) // 32KB buffer

	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := tmpFile.Write(buffer[:n]); writeErr != nil {
				return "", writeErr
			}
			downloaded += int64(n)
			if progressCallback != nil {
				progressCallback(downloaded, size)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	return tmpFile.Name(), nil
}

// fetchChecksum fetches and parses the checksum file
func (u *Updater) fetchChecksum(checksumURL, binaryName string) (string, error) {
	req, err := http.NewRequest("GET", checksumURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse checksum file (format: "hash filename")
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, binaryName) {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				return parts[0], nil
			}
		}
	}

	return "", fmt.Errorf("checksum not found for %s", binaryName)
}

// verifyChecksum verifies the SHA256 checksum of a file
func verifyChecksum(filePath, expectedChecksum string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
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

// getBinaryName returns the expected binary name for the current OS/architecture
func getBinaryName() string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	// Normalize architecture names
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	}

	// Format: reconator-{os}-{arch}
	// Examples: reconator-linux-x86_64, reconator-darwin-aarch64, reconator-windows-x86_64.exe
	name := fmt.Sprintf("reconator-%s-%s", os, arch)

	if os == "windows" {
		name += ".exe"
	}

	return name
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
