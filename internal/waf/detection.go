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

	r := exec.Run("cdncheck", []string{"-i", tmp, "-j", "-silent"}, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil, r.Error
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

	result.Duration = time.Since(start)

	// Print provider summary
	counts := make(map[string]int)
	for _, p := range result.CDNDetails {
		counts[p]++
	}
	for p, c := range counts {
		fmt.Printf("        %s: %d hosts\n", p, c)
	}

	return result, nil
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
