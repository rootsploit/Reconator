package dirbrute

import (
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
			fmt.Println("        Running feroxbuster...")
			discoveries := s.feroxbuster(tmp, wordlist)
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
			fmt.Println("        Running ffuf...")
			discoveries := s.ffuf(hosts, wordlist)
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
	var discoveries []Discovery

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
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", s.cfg.Threads))
	} else {
		args = append(args, "-t", "50")
	}

	if s.cfg.RateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", s.cfg.RateLimit))
	}

	// Read hosts and pipe to feroxbuster
	hostsContent, err := os.ReadFile(hostsFile)
	if err != nil {
		return discoveries
	}

	r := exec.RunWithInput("feroxbuster", args, string(hostsContent), &exec.Options{Timeout: 30 * time.Minute})
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
	var discoveries []Discovery

	for _, host := range hosts {
		// Limit to first 10 hosts to avoid long scan times
		if len(discoveries) > 1000 {
			break
		}

		// Create output file
		outFile, err := os.CreateTemp("", "ffuf-*.json")
		if err != nil {
			continue
		}
		outPath := outFile.Name()
		outFile.Close()

		// ffuf -w wordlist -u host/FUZZ -mc 200,301,302,403,401 -o output.json -of json
		args := []string{
			"-w", wordlist,
			"-u", strings.TrimSuffix(host, "/") + "/FUZZ",
			"-mc", "200,301,302,403,401,500",
			"-fc", "404",
			"-o", outPath,
			"-of", "json",
			"-s", // silent
		}

		if s.cfg.Threads > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", s.cfg.Threads))
		}

		if s.cfg.RateLimit > 0 {
			args = append(args, "-rate", fmt.Sprintf("%d", s.cfg.RateLimit))
		}

		exec.Run("ffuf", args, &exec.Options{Timeout: 10 * time.Minute})

		// Parse JSON output
		content, err := os.ReadFile(outPath)
		os.Remove(outPath)
		if err != nil {
			continue
		}

		var ffufResult struct {
			Results []struct {
				URL    string `json:"url"`
				Status int    `json:"status"`
				Length int    `json:"length"`
			} `json:"results"`
		}
		if json.Unmarshal(content, &ffufResult) == nil {
			for _, r := range ffufResult.Results {
				discoveries = append(discoveries, Discovery{
					URL:           r.URL,
					StatusCode:    r.Status,
					ContentLength: r.Length,
					Tool:          "ffuf",
				})
			}
		}
	}

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
