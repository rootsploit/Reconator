package vulnscan

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	TotalScanned   int             `json:"total_scanned"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	BySeverity     map[string]int  `json:"by_severity"`
	ByType         map[string]int  `json:"by_type"`
	Duration       time.Duration   `json:"duration"`
}

type Vulnerability struct {
	Host        string `json:"host"`
	URL         string `json:"url,omitempty"`
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Matcher     string `json:"matcher,omitempty"`
	Tool        string `json:"tool"`
}

type Scanner struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
}

// Scan performs vulnerability scanning using nuclei templates and dalfox
func (s *Scanner) Scan(hosts []string, categorizedURLs *historic.CategorizedURLs) (*Result, error) {
	start := time.Now()
	result := &Result{
		TotalScanned:    len(hosts),
		Vulnerabilities: []Vulnerability{},
		BySeverity:      make(map[string]int),
		ByType:          make(map[string]int),
	}

	if len(hosts) == 0 {
		return result, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Create temp file with hosts for nuclei
	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-hosts.txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// OPTIMIZATION: Run a single nuclei process for host-based scanning
	// This avoids template reload overhead and thread explosion from multiple processes
	// Nuclei's template clustering automatically optimizes requests to same endpoints
	if s.c.IsInstalled("nuclei") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running nuclei vulnerability scan...")
			vulns := s.nucleiScan(tmp)
			mu.Lock()
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			mu.Unlock()
			fmt.Printf("        nuclei: %d vulnerabilities found\n", len(vulns))
		}()
	}

	// Run dalfox for XSS scanning on categorized XSS URLs (parallel with nuclei)
	if s.c.IsInstalled("dalfox") && categorizedURLs != nil && len(categorizedURLs.XSS) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running dalfox XSS scan...")
			vulns := s.dalfoxScan(categorizedURLs.XSS)
			mu.Lock()
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			mu.Unlock()
			fmt.Printf("        dalfox: %d XSS vulnerabilities found\n", len(vulns))
		}()
	}

	// OPTIMIZATION: Single nuclei process for ALL categorized URLs with combined tags
	// Instead of 5 separate nuclei processes (sqli, ssrf, lfi, ssti, rce), run one
	// This reduces: 5 template loads → 1, thread explosion (5×50=250 → 50)
	if s.c.IsInstalled("nuclei") && categorizedURLs != nil {
		// Collect all categorized URLs into one list (deduplicated)
		var allCategorizedURLs []string
		urlSet := make(map[string]bool)

		for _, urls := range [][]string{
			categorizedURLs.SQLi,
			categorizedURLs.SSRF,
			categorizedURLs.LFI,
			categorizedURLs.SSTI,
			categorizedURLs.RCE,
		} {
			for _, u := range urls {
				if !urlSet[u] {
					urlSet[u] = true
					allCategorizedURLs = append(allCategorizedURLs, u)
				}
			}
		}

		if len(allCategorizedURLs) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Printf("        Running nuclei targeted scan on %d categorized URLs...\n", len(allCategorizedURLs))
				// Run single nuclei with combined tags
				vulns := s.nucleiTargeted(allCategorizedURLs, "sqli,ssrf,lfi,ssti,rce,injection")
				mu.Lock()
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
				mu.Unlock()
				fmt.Printf("        nuclei-targeted: %d vulnerabilities found\n", len(vulns))
			}()
		}
	}

	wg.Wait()

	// Dedupe vulnerabilities
	seen := make(map[string]bool)
	var unique []Vulnerability
	for _, v := range result.Vulnerabilities {
		key := fmt.Sprintf("%s|%s|%s", v.URL, v.TemplateID, v.Tool)
		if v.URL == "" {
			key = fmt.Sprintf("%s|%s|%s", v.Host, v.TemplateID, v.Tool)
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
			// Count by severity
			result.BySeverity[v.Severity]++
			// Count by type
			result.ByType[v.Type]++
		}
	}
	result.Vulnerabilities = unique
	result.Duration = time.Since(start)

	return result, nil
}

// nucleiScan runs nuclei with comprehensive template coverage
func (s *Scanner) nucleiScan(hostsFile string) []Vulnerability {
	var vulns []Vulnerability

	// Get home directory for nuclei-templates path
	home, err := os.UserHomeDir()
	if err != nil {
		return vulns
	}
	templateDir := home + "/nuclei-templates"

	// Build args - use tags-based approach which works with default nuclei config
	// This is more reliable than specifying directory paths
	args := []string{
		"-l", hostsFile,
		"-severity", "medium,high,critical",
		"-silent", "-json",
		"-exclude-tags", "dos,fuzz",
	}

	// Check if templates directory exists at ~/nuclei-templates
	if _, err := os.Stat(templateDir); err == nil {
		// Use full paths to template directories (nuclei v3 structure)
		args = append(args,
			"-t", templateDir+"/http/cves/",
			"-t", templateDir+"/http/vulnerabilities/",
			"-t", templateDir+"/http/exposures/",
			"-t", templateDir+"/http/default-logins/",
			"-t", templateDir+"/http/misconfiguration/",
			"-t", templateDir+"/http/technologies/",
		)
	} else {
		// Fallback: use tags-based filtering (works with nuclei's default template location)
		args = append(args, "-tags", "cve,exposure,misconfig,default-login,tech")
	}

	// Performance tuning based on ProjectDiscovery recommendations
	// -c: template concurrency (how many templates run in parallel)
	// -bs: bulk-size (hosts analyzed per template in parallel)
	// -rl: rate-limit (requests per second)
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
		// Set bulk-size to match concurrency for optimal throughput
		args = append(args, "-bs", fmt.Sprintf("%d", s.cfg.Threads))
	} else {
		// Defaults optimized for stability
		args = append(args, "-c", "25", "-bs", "25")
	}

	if s.cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.cfg.RateLimit))
	} else {
		// Default rate limit to avoid overwhelming targets
		args = append(args, "-rl", "300")
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: 60 * time.Minute})
	if r.Error != nil {
		return vulns
	}

	vulns = s.parseNucleiOutput(r.Stdout)
	return vulns
}

// nucleiTargeted runs nuclei with specific tags for targeted scanning
func (s *Scanner) nucleiTargeted(urls []string, tag string) []Vulnerability {
	var vulns []Vulnerability

	if len(urls) == 0 {
		return vulns
	}

	// Create temp file with URLs
	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-urls.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	args := []string{
		"-l", tmp,
		"-tags", tag,
		"-severity", "medium,high,critical",
		"-silent", "-json",
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: 30 * time.Minute})
	if r.Error != nil {
		return vulns
	}

	vulns = s.parseNucleiOutput(r.Stdout)
	return vulns
}

// parseNucleiOutput parses nuclei JSON output
func (s *Scanner) parseNucleiOutput(output string) []Vulnerability {
	var vulns []Vulnerability

	for _, line := range exec.Lines(output) {
		if line == "" {
			continue
		}
		var entry struct {
			Host       string `json:"host"`
			MatchedAt  string `json:"matched-at"`
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Tags        []string `json:"tags"`
			} `json:"info"`
			MatcherName string `json:"matcher-name"`
			Type        string `json:"type"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if entry.Host == "" && entry.MatchedAt == "" {
			continue
		}

		vulnType := entry.Type
		if vulnType == "" && len(entry.Info.Tags) > 0 {
			vulnType = entry.Info.Tags[0]
		}

		vulns = append(vulns, Vulnerability{
			Host:        entry.Host,
			URL:         entry.MatchedAt,
			TemplateID:  entry.TemplateID,
			Name:        entry.Info.Name,
			Severity:    entry.Info.Severity,
			Type:        vulnType,
			Description: entry.Info.Description,
			Matcher:     entry.MatcherName,
			Tool:        "nuclei",
		})
	}

	return vulns
}

// dalfoxScan runs dalfox for XSS scanning
func (s *Scanner) dalfoxScan(urls []string) []Vulnerability {
	var vulns []Vulnerability

	if len(urls) == 0 {
		return vulns
	}

	// Create temp file with URLs
	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-xss-urls.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	// Create output file
	outFile, err := os.CreateTemp("", "dalfox-*.json")
	if err != nil {
		return vulns
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	// dalfox file urls.txt --silence --format json -o output.json
	args := []string{
		"file", tmp,
		"--silence",
		"--format", "json",
		"-o", outPath,
		"--skip-bav", // Skip BAV (Blind XSS) for faster scanning
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-w", fmt.Sprintf("%d", s.cfg.Threads))
	}

	r := exec.Run("dalfox", args, &exec.Options{Timeout: 30 * time.Minute})
	if r.Error != nil {
		// Still try to parse output file
	}

	// Parse JSON output
	content, err := os.ReadFile(outPath)
	if err != nil {
		return vulns
	}

	// dalfox outputs JSON lines
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Data       string `json:"data"`
			URL        string `json:"url"`
			Param      string `json:"param"`
			Type       string `json:"type"`
			MessageStr string `json:"message_str"`
			Severity   string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.URL != "" {
			severity := entry.Severity
			if severity == "" {
				severity = "high" // XSS is typically high severity
			}
			vulns = append(vulns, Vulnerability{
				URL:        entry.URL,
				TemplateID: "dalfox-xss",
				Name:       fmt.Sprintf("XSS via %s parameter", entry.Param),
				Severity:   severity,
				Type:       "xss",
				Description: entry.MessageStr,
				Tool:       "dalfox",
			})
		}
	}

	return vulns
}
