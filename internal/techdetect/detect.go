package techdetect

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	Domain     string                 `json:"domain"`
	TechByHost map[string][]string    `json:"tech_by_host"`
	TechCount  map[string]int         `json:"tech_count"`
	Total      int                    `json:"total"`
	Duration   time.Duration          `json:"duration"`
}

type Detector struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewDetector(cfg *config.Config, checker *tools.Checker) *Detector {
	return &Detector{cfg: cfg, c: checker}
}

// Detect runs technology detection on a list of hosts
func (d *Detector) Detect(hosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TechByHost: make(map[string][]string),
		TechCount:  make(map[string]int),
	}

	if len(hosts) == 0 {
		return result, nil
	}

	// Use httpx with tech detection
	if d.c.IsInstalled("httpx") {
		techResults := d.httpxTechDetect(hosts)
		for host, techs := range techResults {
			result.TechByHost[host] = techs
			for _, tech := range techs {
				result.TechCount[tech]++
			}
		}
	}

	result.Total = len(result.TechByHost)
	result.Duration = time.Since(start)
	return result, nil
}

// httpxTechDetect uses httpx with tech detection
func (d *Detector) httpxTechDetect(hosts []string) map[string][]string {
	if !d.c.IsInstalled("httpx") {
		return nil
	}

	// Create temp file with hosts
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-hosts.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// httpx -l hosts.txt -tech-detect -json -silent
	args := []string{"-l", tmpFile, "-tech-detect", "-json", "-silent"}
	if d.cfg.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", d.cfg.Threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return nil
	}

	// Parse JSON output
	results := make(map[string][]string)
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			URL  string   `json:"url"`
			Tech []string `json:"tech"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if len(entry.Tech) > 0 {
			// Extract host from URL
			host := entry.URL
			host = strings.TrimPrefix(host, "http://")
			host = strings.TrimPrefix(host, "https://")
			if idx := strings.Index(host, "/"); idx > 0 {
				host = host[:idx]
			}
			results[host] = entry.Tech
		}
	}

	return results
}
