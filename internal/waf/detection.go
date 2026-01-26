package waf

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
	TotalChecked int               `json:"total_checked"`
	CDNHosts     []string          `json:"cdn_hosts"`
	DirectHosts  []string          `json:"direct_hosts"`
	CDNDetails   map[string]string `json:"cdn_details"`
	OriginIPs    map[string]string `json:"origin_ips,omitempty"` // Discovered origin IPs for CF hosts
	Duration     time.Duration     `json:"duration"`
}

type cdnEntry struct {
	Input     string `json:"input"`
	CDN       bool   `json:"cdn"`
	CDNName   string `json:"cdn_name,omitempty"`
	WAF       bool   `json:"waf"`
	WAFName   string `json:"waf_name,omitempty"`
	Cloud     bool   `json:"cloud"`
	CloudName string `json:"cloud_name,omitempty"`
}

type Detector struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewDetector(cfg *config.Config, checker *tools.Checker) *Detector {
	return &Detector{cfg: cfg, c: checker}
}

func (d *Detector) Detect(hosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TotalChecked: len(hosts),
		CDNHosts:     []string{},
		DirectHosts:  []string{},
		CDNDetails:   make(map[string]string),
		OriginIPs:    make(map[string]string),
	}

	if !d.c.IsInstalled("cdncheck") {
		return nil, fmt.Errorf("cdncheck not installed")
	}
	if len(hosts) == 0 {
		return result, nil
	}

	fmt.Println("    [*] Running CDN/WAF detection with cdncheck...")

	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	r := exec.Run("cdncheck", []string{"-i", tmp, "-j", "-silent", "-c", "100"}, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		// cdncheck failed - return partial result with all hosts as "unknown/direct"
		// This ensures the phase completes and 2-waf folder is created
		fmt.Printf("    [!] cdncheck failed: %v, marking all hosts as direct (unknown CDN status)\n", r.Error)
		result.DirectHosts = hosts
		result.Duration = time.Since(start)
		return result, nil // Return result instead of error for graceful degradation
	}

	checked := make(map[string]bool)
	for _, line := range exec.Lines(r.Stdout) {
		var e cdnEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		checked[e.Input] = true

		if e.CDN || e.WAF || e.Cloud {
			result.CDNHosts = append(result.CDNHosts, e.Input)
			if p := e.CDNName; p == "" {
				if p = e.WAFName; p == "" {
					p = e.CloudName
				}
			}
			if p := coalesce(e.CDNName, e.WAFName, e.CloudName); p != "" {
				result.CDNDetails[e.Input] = p
			}
		} else {
			result.DirectHosts = append(result.DirectHosts, e.Input)
		}
	}

	for _, h := range hosts {
		if !checked[h] {
			result.DirectHosts = append(result.DirectHosts, h)
		}
	}

	// Print provider summary
	counts := make(map[string]int)
	for _, p := range result.CDNDetails {
		counts[p]++
	}
	for p, c := range counts {
		fmt.Printf("        %s: %d hosts\n", p, c)
	}

	// Attempt origin IP discovery for Cloudflare hosts
	cfHosts := d.filterCloudflareHosts(result.CDNHosts, result.CDNDetails)
	if len(cfHosts) > 0 {
		fmt.Printf("    [*] Attempting origin IP discovery for %d Cloudflare hosts...\n", len(cfHosts))
		origins := d.discoverOriginIPs(cfHosts)
		for host, ip := range origins {
			result.OriginIPs[host] = ip
		}
		if len(origins) > 0 {
			fmt.Printf("        Discovered %d origin IPs\n", len(origins))
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// filterCloudflareHosts returns only Cloudflare-protected hosts
func (d *Detector) filterCloudflareHosts(cdnHosts []string, cdnDetails map[string]string) []string {
	var cfHosts []string
	for _, host := range cdnHosts {
		provider := strings.ToLower(cdnDetails[host])
		if strings.Contains(provider, "cloudflare") {
			cfHosts = append(cfHosts, host)
		}
	}
	return cfHosts
}

// discoverOriginIPs attempts to find origin IPs behind Cloudflare using multiple methods
func (d *Detector) discoverOriginIPs(hosts []string) map[string]string {
	origins := make(map[string]string)

	if len(hosts) == 0 {
		return origins
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-cf-hosts.txt")
	if err != nil {
		return origins
	}
	defer cleanup()

	// Try CF-Hero first (comprehensive - uses SecurityTrails, Censys, Shodan, etc.)
	if d.c.IsInstalled("cf-hero") {
		fmt.Println("        Running cf-hero...")
		r := exec.Run("cf-hero", []string{"-f", tmp}, &exec.Options{Timeout: 5 * time.Minute})
		if r.Error == nil {
			for _, line := range exec.Lines(r.Stdout) {
				// Parse cf-hero output: host -> origin_ip
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					host := strings.TrimSpace(parts[0])
					ip := strings.TrimSpace(parts[len(parts)-1])
					if isValidIP(ip) && host != "" {
						origins[host] = ip
					}
				}
			}
		}
	}

	// Fallback to hakoriginfinder (doesn't need API keys)
	// Usage: hakoriginfinder -h hosts.txt
	if len(origins) < len(hosts) && d.c.IsInstalled("hakoriginfinder") {
		fmt.Println("        Running hakoriginfinder...")
		r := exec.Run("hakoriginfinder", []string{"-h", tmp}, &exec.Options{Timeout: 3 * time.Minute})
		if r.Error == nil {
			for _, line := range exec.Lines(r.Stdout) {
				// Parse hakoriginfinder output
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					host := strings.TrimSpace(parts[0])
					ip := strings.TrimSpace(parts[len(parts)-1])
					if isValidIP(ip) && host != "" && origins[host] == "" {
						origins[host] = ip
					}
				}
			}
		}
	}

	return origins
}

// isValidIP checks if string is a valid IPv4 address
func isValidIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
