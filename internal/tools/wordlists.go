package tools

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Wordlist represents a downloadable wordlist
type Wordlist struct {
	Name        string
	Filename    string
	URL         string
	Description string
	Required    bool
}

// WordlistDir returns the path to the reconator wordlists directory
func WordlistDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wordlists"
	}
	return filepath.Join(home, ".reconator", "wordlists")
}

// ResolversFile returns the path to the resolvers file
func ResolversFile() string {
	return filepath.Join(WordlistDir(), "resolvers.txt")
}

// SubdomainWordlist returns paths to check for subdomain wordlists (in priority order)
func SubdomainWordlistPaths() []string {
	wlDir := WordlistDir()
	home, _ := os.UserHomeDir()
	return []string{
		// Reconator installed wordlists (highest priority)
		filepath.Join(wlDir, "subdomain-bruteforce-medium.txt"),
		filepath.Join(wlDir, "subdomain-bruteforce.txt"),
		// Local directory fallback
		"wordlists/subdomain-bruteforce-medium.txt",
		"wordlists/subdomain-bruteforce.txt",
		// Common SecLists locations
		"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		// Homebrew on macOS
		"/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		// Home directory
		filepath.Join(home, "wordlists/subdomains.txt"),
		filepath.Join(home, "SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
	}
}

// GetWordlists returns the list of wordlists to download
func GetWordlists() []Wordlist {
	return []Wordlist{
		{
			Name:        "DNS Resolvers",
			Filename:    "resolvers.txt",
			URL:         "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
			Description: "Trickest quality DNS resolvers",
			Required:    true,
		},
		{
			Name:        "Subdomain Bruteforce (20k)",
			Filename:    "subdomain-bruteforce-medium.txt",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
			Description: "SecLists top 20k subdomains",
			Required:    true,
		},
		{
			Name:        "Subdomain Bruteforce (5k)",
			Filename:    "subdomain-bruteforce.txt",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
			Description: "SecLists top 5k subdomains (quick)",
			Required:    false,
		},
	}
}

// DownloadWordlist downloads a wordlist to the wordlists directory
func DownloadWordlist(wl Wordlist) error {
	dir := WordlistDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		// Fallback to local wordlists directory if home is not writable
		dir = "wordlists"
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create dir: %w", err)
		}
	}

	destPath := filepath.Join(dir, wl.Filename)

	// Check if already exists and has content
	if info, err := os.Stat(destPath); err == nil && info.Size() > 100 {
		return nil // Already exists
	}

	// Download
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(wl.URL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Create file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// CheckWordlists checks if wordlists are installed
func CheckWordlists() map[string]bool {
	result := make(map[string]bool)
	homeDir := WordlistDir()
	localDir := "wordlists"

	for _, wl := range GetWordlists() {
		// Check both home and local directories
		homePath := filepath.Join(homeDir, wl.Filename)
		localPath := filepath.Join(localDir, wl.Filename)

		found := false
		if info, err := os.Stat(homePath); err == nil && info.Size() > 100 {
			found = true
		} else if info, err := os.Stat(localPath); err == nil && info.Size() > 100 {
			found = true
		}
		result[wl.Name] = found
	}
	return result
}

// FindWordlist finds the first available subdomain wordlist
func FindWordlist() string {
	for _, p := range SubdomainWordlistPaths() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// FindResolvers finds the resolvers file
func FindResolvers() string {
	paths := []string{
		ResolversFile(),
		"wordlists/resolvers.txt",
		"/usr/share/wordlists/resolvers.txt",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
