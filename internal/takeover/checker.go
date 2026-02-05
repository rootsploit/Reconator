package takeover

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
	TotalChecked int           `json:"total_checked"`
	Vulnerable   []Vulnerable  `json:"vulnerable"`
	Duration     time.Duration `json:"duration"`
}

type Vulnerable struct {
	Subdomain string `json:"subdomain"`
	Service   string `json:"service,omitempty"`
	Severity  string `json:"severity"`
	Tool      string `json:"tool"`
	Details   string `json:"details,omitempty"`
}

type Checker struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewChecker(cfg *config.Config, checker *tools.Checker) *Checker {
	return &Checker{cfg: cfg, c: checker}
}

func (c *Checker) Check(subdomains []string) (*Result, error) {
	start := time.Now()
	result := &Result{TotalChecked: len(subdomains), Vulnerable: []Vulnerable{}}

	if len(subdomains) == 0 {
		return result, nil
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(subdomains, "\n"), ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Nuclei
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !c.c.IsInstalled("nuclei") {
			return
		}
		fmt.Println("        Running nuclei takeover templates...")
		vulns := c.nuclei(tmp)
		mu.Lock()
		result.Vulnerable = append(result.Vulnerable, vulns...)
		mu.Unlock()
		fmt.Printf("        nuclei: %d potential takeovers\n", len(vulns))
	}()

	// Subzy
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !c.c.IsInstalled("subzy") {
			return
		}
		fmt.Println("        Running subzy...")
		vulns := c.subzy(tmp)
		mu.Lock()
		result.Vulnerable = append(result.Vulnerable, vulns...)
		mu.Unlock()
		fmt.Printf("        subzy: %d potential takeovers\n", len(vulns))
	}()

	// Subjack
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !c.c.IsInstalled("subjack") {
			return
		}
		fmt.Println("        Running subjack...")
		vulns := c.subjack(tmp)
		mu.Lock()
		result.Vulnerable = append(result.Vulnerable, vulns...)
		mu.Unlock()
		fmt.Printf("        subjack: %d potential takeovers\n", len(vulns))
	}()

	wg.Wait()

	// Dedupe by subdomain+service+tool (not just subdomain)
	seen := make(map[string]bool)
	var unique []Vulnerable
	for _, v := range result.Vulnerable {
		key := v.Subdomain + "|" + v.Service + "|" + v.Tool
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
		}
	}
	result.Vulnerable = unique
	result.Duration = time.Since(start)
	return result, nil
}

func (c *Checker) nuclei(input string) []Vulnerable {
	var vulns []Vulnerable

	// Build args for takeover detection
	// Use tags-based filtering to run ONLY takeover-specific templates
	// This avoids running CVE/misconfiguration templates from /dns/ directory
	// CVE scanning happens in the separate vulnscan phase
	args := []string{
		"-l", input,
		"-tags", "takeover", // Only templates tagged with "takeover"
		"-severity", "critical,high,medium",
		"-silent", "-jsonl",
	}

	if c.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", c.cfg.Threads))
	}
	r := exec.Run("nuclei", args, &exec.Options{Timeout: 15 * time.Minute})
	if r.Error != nil {
		return vulns
	}
	for _, line := range exec.Lines(r.Stdout) {
		var e struct {
			Host       string `json:"host"`
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		vulns = append(vulns, Vulnerable{Subdomain: e.Host, Service: e.TemplateID, Severity: e.Info.Severity, Tool: "nuclei", Details: e.Info.Name})
	}
	return vulns
}

func (c *Checker) subzy(input string) []Vulnerable {
	var vulns []Vulnerable

	// BB-9: Enhanced subzy flags for better accuracy
	// --verify: Verifies findings (reduces false positives)
	// --https: Use HTTPS for checks
	// --hide_fails: Only show vulnerable ones
	args := []string{
		"run",
		"--targets", input,
		"--concurrency", "50",
		"--hide_fails",
		"--https",
		"--verify_ssl", // BB-9: Verify SSL for accurate results
	}
	r := exec.Run("subzy", args, &exec.Options{Timeout: 10 * time.Minute})

	if r.Error != nil {
		return vulns
	}

	// Parse text output - subzy with --hide_fails only shows vulnerable subdomains
	// Format: [subdomain] [service] VULNERABLE
	for _, line := range exec.Lines(r.Stdout) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		// Skip header/info lines
		if strings.Contains(upper, "TARGET") || strings.Contains(upper, "CHECKING") {
			continue
		}
		// With --hide_fails, any subdomain shown is vulnerable
		// Extract subdomain from line (usually first field)
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			sub := strings.Trim(parts[0], "[]")
			// Skip if it's not a valid subdomain
			if !strings.Contains(sub, ".") {
				continue
			}
			service := ""
			if len(parts) >= 2 {
				service = strings.Trim(parts[1], "[]")
			}
			vulns = append(vulns, Vulnerable{
				Subdomain: sub,
				Service:   service,
				Severity:  "high",
				Tool:      "subzy",
				Details:   line,
			})
		}
	}
	return vulns
}

// findSubjackFingerprints locates the subjack fingerprints.json file
func (c *Checker) findSubjackFingerprints() string {
	// Common locations for subjack fingerprints
	home, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(home, "go", "pkg", "mod", "github.com", "haccer", "subjack@v0.0.0-20201112041112-49c51e57deab", "fingerprints.json"),
		filepath.Join(home, ".reconator", "wordlists", "fingerprints.json"),
		"/usr/local/share/subjack/fingerprints.json",
		"/opt/subjack/fingerprints.json",
	}

	// Also try to find it in GOPATH
	gopath := os.Getenv("GOPATH")
	if gopath != "" {
		// Look for any version of subjack in go modules
		subjackDir := filepath.Join(gopath, "pkg", "mod", "github.com", "haccer")
		if entries, err := os.ReadDir(subjackDir); err == nil {
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "subjack@") {
					fp := filepath.Join(subjackDir, entry.Name(), "fingerprints.json")
					paths = append([]string{fp}, paths...)
				}
			}
		}
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (c *Checker) subjack(input string) []Vulnerable {
	var vulns []Vulnerable

	// subjack -w subdomains.txt -timeout 30 -ssl -v -c fingerprints.json
	// Find fingerprints.json in common locations
	fingerprintsPath := c.findSubjackFingerprints()
	if fingerprintsPath == "" {
		// No fingerprints file found, subjack won't work
		return vulns
	}

	args := []string{"-w", input, "-timeout", "30", "-ssl", "-v", "-c", fingerprintsPath}
	if c.cfg.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", c.cfg.Threads))
	}
	r := exec.Run("subjack", args, &exec.Options{Timeout: 10 * time.Minute})

	if r.Error != nil {
		return vulns
	}

	// Parse output - subjack outputs vulnerable subdomains
	// Format: [subdomain] is vulnerable to [service]
	for _, line := range exec.Lines(r.Stdout) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip non-vulnerable lines
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "vulnerable") && !strings.Contains(lower, "takeover") {
			continue
		}
		// Extract subdomain (usually in brackets or first field)
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			sub := strings.Trim(parts[0], "[]")
			if !strings.Contains(sub, ".") {
				continue
			}
			service := ""
			// Try to extract service name
			if idx := strings.Index(lower, "vulnerable to"); idx != -1 {
				service = strings.TrimSpace(line[idx+len("vulnerable to"):])
			}
			vulns = append(vulns, Vulnerable{
				Subdomain: sub,
				Service:   service,
				Severity:  "high",
				Tool:      "subjack",
				Details:   line,
			})
		}
	}
	return vulns
}
