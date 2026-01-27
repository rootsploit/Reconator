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
	Name         string
	Filename     string
	URL          string
	FallbackURLs []string // Additional URLs to try if primary fails
	Description  string
	Required     bool
}

// WordlistDir returns the path to the reconator wordlists directory
func WordlistDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wordlists"
	}
	return filepath.Join(home, ".reconator", "wordlists")
}

// ResolversFile returns the path to the resolvers file (large list for bruteforce)
func ResolversFile() string {
	return filepath.Join(WordlistDir(), "resolvers.txt")
}

// TrustedResolversFile returns the path to trusted resolvers (small list for validation)
func TrustedResolversFile() string {
	return filepath.Join(WordlistDir(), "trusted-resolvers.txt")
}

// CreateTrustedResolvers creates a file with reliable public DNS resolvers
// These are well-known, fast, and reliable for DNS validation
func CreateTrustedResolvers() error {
	dir := WordlistDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	path := TrustedResolversFile()

	// Skip if already exists
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	// Curated list of reliable public DNS resolvers
	// These are fast, reliable, and don't rate-limit aggressively
	resolvers := `# Trusted DNS Resolvers for validation
# Cloudflare (fastest, most reliable)
1.1.1.1
1.0.0.1
# Google Public DNS
8.8.8.8
8.8.4.4
# Quad9 (security-focused)
9.9.9.9
149.112.112.112
# OpenDNS
208.67.222.222
208.67.220.220
# Cloudflare for Families
1.1.1.2
1.0.0.2
# Level3/Lumen
4.2.2.1
4.2.2.2
# Verisign
64.6.64.6
64.6.65.6
# AdGuard DNS
94.140.14.14
94.140.15.15
# CleanBrowsing
185.228.168.9
185.228.169.9
# Comodo Secure DNS
8.26.56.26
8.20.247.20
# Neustar UltraDNS
64.6.64.6
156.154.70.1
# Hurricane Electric
74.82.42.42
`
	return os.WriteFile(path, []byte(resolvers), 0644)
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
			Name:     "DNS Resolvers",
			Filename: "resolvers.txt",
			URL:      "https://cdn.jsdelivr.net/gh/trickest/resolvers@main/resolvers.txt",
			FallbackURLs: []string{
				"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
			},
			Description: "Trickest quality DNS resolvers",
			Required:    true,
		},
		{
			Name:     "Subdomain Bruteforce (20k)",
			Filename: "subdomain-bruteforce-medium.txt",
			URL:      "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Discovery/DNS/subdomains-top1million-20000.txt",
			FallbackURLs: []string{
				"https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/DNS/subdomains-top1million-20000.txt",
			},
			Description: "SecLists top 20k subdomains",
			Required:    true,
		},
		{
			Name:     "Subdomain Bruteforce (5k)",
			Filename: "subdomain-bruteforce.txt",
			URL:      "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Discovery/DNS/subdomains-top1million-5000.txt",
			FallbackURLs: []string{
				"https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/DNS/subdomains-top1million-5000.txt",
			},
			Description: "SecLists top 5k subdomains (quick)",
			Required:    false,
		},
		{
			Name:     "Directory Bruteforce",
			Filename: "directory-list-2.3-small.txt",
			URL:      "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Discovery/Web-Content/directory-list-2.3-small.txt",
			FallbackURLs: []string{
				"https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
				"https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/Web-Content/directory-list-2.3-small.txt",
				"https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
			},
			Description: "SecLists directory bruteforce wordlist",
			Required:    true,
		},
		{
			Name:     "VHost Bruteforce",
			Filename: "vhosts.txt",
			URL:      "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Discovery/DNS/subdomains-top1million-5000.txt",
			FallbackURLs: []string{
				"https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/DNS/subdomains-top1million-5000.txt",
			},
			Description: "VHost/subdomain wordlist for host header fuzzing",
			Required:    false,
		},
	}
}

// FindDirBruteWordlist finds the first available directory bruteforce wordlist
func FindDirBruteWordlist() string {
	home, _ := os.UserHomeDir()
	paths := []string{
		// Reconator installed wordlists (highest priority)
		filepath.Join(WordlistDir(), "directory-list-2.3-small.txt"),
		// SecLists locations (new naming with DirBuster prefix)
		"/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
		"/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
		filepath.Join(home, "SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"),
		// Legacy SecLists locations (old naming)
		"/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
		filepath.Join(home, "SecLists/Discovery/Web-Content/directory-list-2.3-small.txt"),
		// Kali default
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
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

	// Build list of URLs to try (primary + fallbacks)
	urls := append([]string{wl.URL}, wl.FallbackURLs...)

	client := &http.Client{Timeout: 60 * time.Second}
	var lastErr error

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = fmt.Errorf("download: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
			continue
		}

		// Create file
		out, err := os.Create(destPath)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("create file: %w", err)
		}

		_, err = io.Copy(out, resp.Body)
		out.Close()
		resp.Body.Close()

		if err != nil {
			os.Remove(destPath)
			lastErr = fmt.Errorf("write file: %w", err)
			continue
		}

		return nil // Success
	}

	return fmt.Errorf("all download URLs failed: %v", lastErr)
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

// FindResolvers finds the resolvers file (large list for bruteforce)
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

// FindTrustedResolvers finds or creates the trusted resolvers file (for validation)
func FindTrustedResolvers() string {
	path := TrustedResolversFile()

	// Create if doesn't exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := CreateTrustedResolvers(); err != nil {
			// Fall back to regular resolvers if creation fails
			return FindResolvers()
		}
	}

	if _, err := os.Stat(path); err == nil {
		return path
	}

	// Fall back to regular resolvers
	return FindResolvers()
}
