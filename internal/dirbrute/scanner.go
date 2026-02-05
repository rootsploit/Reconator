package dirbrute

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	TotalHosts   int               `json:"total_hosts"`
	Discoveries  []Discovery       `json:"discoveries"`
	ByHost       map[string]int    `json:"by_host"`
	ByStatusCode map[int]int       `json:"by_status_code"`
	Duration     time.Duration     `json:"duration"`
}

type Discovery struct {
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code"`
	ContentLength int   `json:"content_length,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	Tool         string `json:"tool"`
}

type Scanner struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
}

// Scan performs directory bruteforce on alive hosts
func (s *Scanner) Scan(hosts []string) (*Result, error) {
	return s.ScanWithContext(context.Background(), hosts)
}

// ScanWithContext performs directory bruteforce with context support
func (s *Scanner) ScanWithContext(ctx context.Context, hosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TotalHosts:   len(hosts),
		Discoveries:  []Discovery{},
		ByHost:       make(map[string]int),
		ByStatusCode: make(map[int]int),
	}

	if len(hosts) == 0 {
		return result, nil
	}

	// CRITICAL: Limit hosts to prevent forever scans
	maxHosts := 20
	if len(hosts) > maxHosts {
		fmt.Printf("        [DirBrute] Limiting from %d to %d hosts\n", len(hosts), maxHosts)
		hosts = hosts[:maxHosts]
	}

	// Find wordlist
	wordlist := s.findWordlist()
	if wordlist == "" {
		fmt.Println("        [!] No wordlist found, skipping directory bruteforce")
		return result, nil
	}
	fmt.Printf("    [*] Using wordlist: %s\n", filepath.Base(wordlist))

	// Create temp file with hosts
	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-hosts.txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run feroxbuster (primary tool)
	if s.c.IsInstalled("feroxbuster") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			fmt.Println("        Running feroxbuster...")
			discoveries := s.feroxbusterWithContext(ctx, tmp, wordlist)
			mu.Lock()
			result.Discoveries = append(result.Discoveries, discoveries...)
			mu.Unlock()
			fmt.Printf("        feroxbuster: %d discoveries\n", len(discoveries))
		}()
	}

	// Run ffuf as fallback/supplement
	if s.c.IsInstalled("ffuf") && !s.c.IsInstalled("feroxbuster") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			fmt.Println("        Running ffuf...")
			discoveries := s.ffufWithContext(ctx, hosts, wordlist)
			mu.Lock()
			result.Discoveries = append(result.Discoveries, discoveries...)
			mu.Unlock()
			fmt.Printf("        ffuf: %d discoveries\n", len(discoveries))
		}()
	}

	wg.Wait()

	// Dedupe discoveries
	seen := make(map[string]bool)
	var unique []Discovery
	for _, d := range result.Discoveries {
		key := fmt.Sprintf("%s|%d", d.URL, d.StatusCode)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, d)
			// Count by host
			host := extractHost(d.URL)
			result.ByHost[host]++
			// Count by status
			result.ByStatusCode[d.StatusCode]++
		}
	}
	result.Discoveries = unique
	result.Duration = time.Since(start)

	return result, nil
}

// feroxbuster runs feroxbuster for directory bruteforce
func (s *Scanner) feroxbuster(hostsFile, wordlist string) []Discovery {
	return s.feroxbusterWithContext(context.Background(), hostsFile, wordlist)
}

// feroxbusterWithContext runs feroxbuster with context support
func (s *Scanner) feroxbusterWithContext(ctx context.Context, hostsFile, wordlist string) []Discovery {
	var discoveries []Discovery

	// Check context
	select {
	case <-ctx.Done():
		return discoveries
	default:
	}

	// Create output file
	outFile, err := os.CreateTemp("", "ferox-*.json")
	if err != nil {
		return discoveries
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	// feroxbuster --stdin -w wordlist --depth 2 -t threads -s 200,301,302,403,401 -x php,html,js,txt -o output.json --json
	args := []string{
		"--stdin",
		"-w", wordlist,
		"--depth", "2",
		"-s", "200,301,302,403,401,500",
		"-x", "php,html,js,txt,bak,old,zip",
		"--silent",
		"--no-state",
		"-o", outPath,
		"--json",
		"--time-limit", "10m", // Add time limit to feroxbuster itself
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", s.cfg.Threads))
	} else {
		args = append(args, "-t", "50") // Restored to 50 for throughput
	}

	if s.cfg.RateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", s.cfg.RateLimit))
	}

	// Read hosts and pipe to feroxbuster
	hostsContent, err := os.ReadFile(hostsFile)
	if err != nil {
		return discoveries
	}

	// Reduced timeout from 15 to 12 minutes
	r := exec.RunWithInputAndContext(ctx, "feroxbuster", args, string(hostsContent), &exec.Options{Timeout: 12 * time.Minute})
	if r.Error != nil {
		// Still try to parse output file
	}

	// Parse JSON output
	content, err := os.ReadFile(outPath)
	if err != nil {
		return discoveries
	}

	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			URL           string `json:"url"`
			Status        int    `json:"status"`
			ContentLength int    `json:"content_length"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.URL != "" {
			discoveries = append(discoveries, Discovery{
				URL:           entry.URL,
				StatusCode:    entry.Status,
				ContentLength: entry.ContentLength,
				Tool:          "feroxbuster",
			})
		}
	}

	return discoveries
}

// ffuf runs ffuf for directory bruteforce
func (s *Scanner) ffuf(hosts []string, wordlist string) []Discovery {
	return s.ffufWithContext(context.Background(), hosts, wordlist)
}

// ffufWithContext runs ffuf with context support and parallel execution
func (s *Scanner) ffufWithContext(ctx context.Context, hosts []string, wordlist string) []Discovery {
	var discoveries []Discovery
	var mu sync.Mutex

	// CRITICAL: Limit hosts to prevent forever scans
	maxHosts := 10
	if len(hosts) > maxHosts {
		fmt.Printf("        [ffuf] Limiting from %d to %d hosts\n", len(hosts), maxHosts)
		hosts = hosts[:maxHosts]
	}

	// Run ffuf in parallel with limited concurrency
	maxConcurrent := 3
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, host := range hosts {
		// Check for cancellation
		select {
		case <-ctx.Done():
			fmt.Printf("        [ffuf] Cancelled, stopping\n")
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire

		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }() // Release

			// Check context inside goroutine
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Create output file
			outFile, err := os.CreateTemp("", "ffuf-*.json")
			if err != nil {
				return
			}
			outPath := outFile.Name()
			outFile.Close()
			defer os.Remove(outPath)

			// ffuf -w wordlist -u host/FUZZ -mc 200,301,302,403,401 -o output.json -of json
			args := []string{
				"-w", wordlist,
				"-u", strings.TrimSuffix(host, "/") + "/FUZZ",
				"-mc", "200,301,302,403,401,500",
				"-fc", "404",
				"-o", outPath,
				"-of", "json",
				"-s",            // silent
				"-t", "20",      // Limit threads per instance
				"-timeout", "3", // 3 second request timeout
			}

			if s.cfg.RateLimit > 0 {
				args = append(args, "-rate", fmt.Sprintf("%d", s.cfg.RateLimit))
			}

			// Reduced timeout from 5 to 3 minutes per host
			exec.RunWithContext(ctx, "ffuf", args, &exec.Options{Timeout: 3 * time.Minute})

			// Parse JSON output
			content, err := os.ReadFile(outPath)
			if err != nil {
				return
			}

			var ffufResult struct {
				Results []struct {
					URL    string `json:"url"`
					Status int    `json:"status"`
					Length int    `json:"length"`
				} `json:"results"`
			}
			if json.Unmarshal(content, &ffufResult) == nil {
				mu.Lock()
				for _, r := range ffufResult.Results {
					discoveries = append(discoveries, Discovery{
						URL:           r.URL,
						StatusCode:    r.Status,
						ContentLength: r.Length,
						Tool:          "ffuf",
					})
				}
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return discoveries
}

// findWordlist finds a suitable wordlist for directory bruteforce
func (s *Scanner) findWordlist() string {
	// Check custom wordlist from config
	if s.cfg.WordlistFile != "" {
		if _, err := os.Stat(s.cfg.WordlistFile); err == nil {
			return s.cfg.WordlistFile
		}
	}

	// Use the centralized wordlist finder from tools package
	return tools.FindDirBruteWordlist()
}

// extractHost extracts the host from a URL
func extractHost(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx > 0 {
		return url[:idx]
	}
	return url
}
