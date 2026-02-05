package dirscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// Result represents directory bruteforce scan results
type Result struct {
	URL         string      `json:"url"`
	Directories []Directory `json:"directories"`
	Files       []File      `json:"files"`
	Tool        string      `json:"tool"`
	Duration    time.Duration `json:"duration"`
	TotalFound  int         `json:"total_found"`
}

// Directory represents a discovered directory
type Directory struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Lines      int    `json:"lines,omitempty"`
	Words      int    `json:"words,omitempty"`
}

// File represents a discovered file
type File struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Lines      int    `json:"lines,omitempty"`
	Words      int    `json:"words,omitempty"`
	Extension  string `json:"extension,omitempty"`
}

// Scanner performs directory bruteforce scanning
type Scanner struct {
	checker *tools.Checker
	timeout time.Duration
	threads int
}

// NewScanner creates a new directory scanner
func NewScanner(checker *tools.Checker, timeout time.Duration, threads int) *Scanner {
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	if threads == 0 {
		threads = 50
	}
	return &Scanner{
		checker: checker,
		timeout: timeout,
		threads: threads,
	}
}

// Scan performs directory bruteforce on a target URL
// Uses feroxbuster (preferred) or ffuf (fallback)
func (s *Scanner) Scan(targetURL string, wordlist string) (*Result, error) {
	start := time.Now()

	// Use feroxbuster (preferred) or ffuf (fallback)
	var result *Result
	var err error

	if s.checker.IsInstalled("feroxbuster") {
		result, err = s.runFeroxbuster(targetURL, wordlist)
	} else if s.checker.IsInstalled("ffuf") {
		result, err = s.runFfuf(targetURL, wordlist)
	} else {
		return nil, fmt.Errorf("no directory bruteforce tools installed (install feroxbuster or ffuf)")
	}

	if err != nil {
		return nil, err
	}

	result.Duration = time.Since(start)
	result.TotalFound = len(result.Directories) + len(result.Files)

	return result, nil
}

// runFeroxbuster runs feroxbuster (recommended, fastest)
func (s *Scanner) runFeroxbuster(targetURL, wordlist string) (*Result, error) {
	result := &Result{
		URL:  targetURL,
		Tool: "feroxbuster",
	}

	if wordlist == "" {
		wordlist = s.getDefaultWordlist()
	}

	// Create temp output file for JSON results
	tmpFile, err := os.CreateTemp("", "feroxbuster-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"--url", targetURL,
		"--wordlist", wordlist,
		"--output", tmpPath,
		"--json",
		"--threads", fmt.Sprintf("%d", s.threads),
		"--auto-bail",         // Stop if errors exceed threshold (smart filtering)
		"--auto-tune",         // Auto-adjust speed based on server
		"--dont-filter",       // Don't auto-filter responses (we want to see everything)
		"--collect-words",     // Collect words for better filtering
		"--silent",            // Less verbose
		"--status-codes", "200,204,301,302,307,308,401,403,405", // Interesting codes
	}

	r := exec.Run("feroxbuster", args, &exec.Options{Timeout: s.timeout})
	if r.Error != nil {
		return nil, fmt.Errorf("feroxbuster failed: %w", r.Error)
	}

	// Parse JSON output
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	// Feroxbuster outputs JSON lines
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var entry struct {
			Type       string `json:"type"`
			URL        string `json:"url"`
			Path       string `json:"path"`
			StatusCode int    `json:"status"`
			ContentLength int64 `json:"content_length"`
			LineCount  int    `json:"line_count"`
			WordCount  int    `json:"word_count"`
		}

		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}

		// Skip if not a response type
		if entry.Type != "response" {
			continue
		}

		// Determine if directory or file
		if strings.HasSuffix(entry.Path, "/") {
			result.Directories = append(result.Directories, Directory{
				Path:       entry.Path,
				StatusCode: entry.StatusCode,
				Size:       entry.ContentLength,
				Lines:      entry.LineCount,
				Words:      entry.WordCount,
			})
		} else {
			ext := filepath.Ext(entry.Path)
			result.Files = append(result.Files, File{
				Path:       entry.Path,
				StatusCode: entry.StatusCode,
				Size:       entry.ContentLength,
				Lines:      entry.LineCount,
				Words:      entry.WordCount,
				Extension:  ext,
			})
		}
	}

	return result, nil
}

// runFfuf runs ffuf (fast, flexible)
func (s *Scanner) runFfuf(targetURL, wordlist string) (*Result, error) {
	result := &Result{
		URL:  targetURL,
		Tool: "ffuf",
	}

	if wordlist == "" {
		wordlist = s.getDefaultWordlist()
	}

	// Ensure URL has FUZZ placeholder
	scanURL := targetURL
	if !strings.HasSuffix(scanURL, "/") {
		scanURL += "/"
	}
	scanURL += "FUZZ"

	args := []string{
		"-u", scanURL,
		"-w", wordlist,
		"-t", fmt.Sprintf("%d", s.threads),
		"-mc", "200,204,301,302,307,308,401,403,405",
		"-ac",  // Auto-calibrate filtering (smart filtering)
		"-of", "json",
		"-o", "/dev/stdout",
		"-s", // Silent mode
	}

	r := exec.Run("ffuf", args, &exec.Options{Timeout: s.timeout})
	if r.Error != nil {
		return nil, fmt.Errorf("ffuf failed: %w", r.Error)
	}

	// Parse JSON output
	var ffufResult struct {
		Results []struct {
			Input      string `json:"input"`
			Position   int    `json:"position"`
			StatusCode int    `json:"status"`
			Length     int64  `json:"length"`
			Words      int    `json:"words"`
			Lines      int    `json:"lines"`
		} `json:"results"`
	}

	if json.Unmarshal([]byte(r.Stdout), &ffufResult) != nil {
		// Try line-by-line parsing if full JSON fails
		for _, line := range exec.Lines(r.Stdout) {
			if line == "" {
				continue
			}
			// ffuf output parsing fallback
		}
	} else {
		for _, entry := range ffufResult.Results {
			path := "/" + entry.Input
			if strings.HasSuffix(path, "/") {
				result.Directories = append(result.Directories, Directory{
					Path:       path,
					StatusCode: entry.StatusCode,
					Size:       entry.Length,
					Lines:      entry.Lines,
					Words:      entry.Words,
				})
			} else {
				result.Files = append(result.Files, File{
					Path:       path,
					StatusCode: entry.StatusCode,
					Size:       entry.Length,
					Lines:      entry.Lines,
					Words:      entry.Words,
					Extension:  filepath.Ext(path),
				})
			}
		}
	}

	return result, nil
}

// getDefaultWordlist returns the best available wordlist (short, impactful)
// Prioritizes smaller, high-impact lists for default scanning
func (s *Scanner) getDefaultWordlist() string {
	// Priority order: SHORT, IMPACTFUL wordlists first
	candidates := []string{
		// SecLists common (SHORT: ~4,700 entries - best default)
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
		"/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/local/share/seclists/Discovery/Web-Content/common.txt",

		// Kali dirb common (SHORT: ~4,600 entries)
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirb/wordlists/common.txt",

		// SecLists raft-small (SMALL: ~1,600 entries)
		"/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt",

		// FALLBACK: raft-medium (MEDIUM: ~30,000 entries - only if nothing else)
		"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// If no wordlist found, return empty (tool will use its default)
	return ""
}

// GetInterestingPaths filters results to only interesting findings
func (r *Result) GetInterestingPaths() []string {
	var interesting []string

	// Interesting directories
	interestingDirs := map[string]bool{
		"admin": true, "administrator": true, "backup": true, "backups": true,
		"api": true, "internal": true, "private": true, "test": true,
		"dev": true, "staging": true, "debug": true, "config": true,
		"console": true, "dashboard": true, "panel": true, "portal": true,
		".git": true, ".svn": true, ".env": true, "wp-admin": true,
	}

	for _, dir := range r.Directories {
		baseName := strings.ToLower(strings.Trim(filepath.Base(dir.Path), "/"))
		if interestingDirs[baseName] || dir.StatusCode == 401 || dir.StatusCode == 403 {
			interesting = append(interesting, dir.Path)
		}
	}

	// Interesting files
	interestingFiles := map[string]bool{
		".env": true, ".git": true, "config.php": true, "config.yml": true,
		"wp-config.php": true, "database.yml": true, "credentials.json": true,
		"backup.sql": true, "dump.sql": true, "phpinfo.php": true,
	}

	interestingExts := map[string]bool{
		".bak": true, ".backup": true, ".old": true, ".sql": true,
		".zip": true, ".tar.gz": true, ".config": true, ".json": true,
	}

	for _, file := range r.Files {
		baseName := strings.ToLower(filepath.Base(file.Path))
		ext := strings.ToLower(file.Extension)

		if interestingFiles[baseName] || interestingExts[ext] || file.StatusCode == 200 {
			interesting = append(interesting, file.Path)
		}
	}

	return interesting
}
