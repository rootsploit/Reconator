package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/waf"
)

// Manager handles output file management
type Manager struct {
	outputDir string
	results   map[string]interface{}
}

// NewManager creates a new output manager
func NewManager(outputDir string) *Manager {
	return &Manager{
		outputDir: outputDir,
		results:   make(map[string]interface{}),
	}
}

// phaseDir creates and returns the path to a phase subdirectory
func (m *Manager) phaseDir(phase string) string {
	dir := filepath.Join(m.outputDir, phase)
	os.MkdirAll(dir, 0755)
	return dir
}

// SaveSubdomains saves subdomain enumeration results
func (m *Manager) SaveSubdomains(result *subdomain.Result) error {
	m.results["subdomains"] = result
	dir := m.phaseDir("1-subdomains")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "subdomains.json"), result); err != nil {
		return err
	}

	// Save validated subdomains
	m.saveLines(filepath.Join(dir, "subdomains.txt"), result.Subdomains)

	// Save all subdomains (before validation)
	if len(result.AllSubdomains) > 0 {
		m.saveLines(filepath.Join(dir, "all_subdomains.txt"), result.AllSubdomains)
	}

	return nil
}

// SaveWAFResults saves WAF/CDN detection results
func (m *Manager) SaveWAFResults(result *waf.Result) error {
	m.results["waf"] = result
	dir := m.phaseDir("2-waf")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "waf_detection.json"), result); err != nil {
		return err
	}

	// Save CDN hosts
	if len(result.CDNHosts) > 0 {
		m.saveLines(filepath.Join(dir, "cdn_hosts.txt"), result.CDNHosts)
	}

	// Save direct hosts (not behind CDN)
	if len(result.DirectHosts) > 0 {
		m.saveLines(filepath.Join(dir, "direct_hosts.txt"), result.DirectHosts)
	}

	return nil
}

// SavePortResults saves port scanning results
func (m *Manager) SavePortResults(result *portscan.Result) error {
	m.results["ports"] = result
	dir := m.phaseDir("3-ports")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "port_scan.json"), result); err != nil {
		return err
	}

	// Save alive hosts
	if len(result.AliveHosts) > 0 {
		m.saveLines(filepath.Join(dir, "alive_hosts.txt"), result.AliveHosts)
	}

	// Save open ports in host:port format
	var hostPorts []string
	for host, ports := range result.OpenPorts {
		for _, port := range ports {
			hostPorts = append(hostPorts, fmt.Sprintf("%s:%d", host, port))
		}
	}
	if len(hostPorts) > 0 {
		sort.Strings(hostPorts)
		m.saveLines(filepath.Join(dir, "open_ports.txt"), hostPorts)
	}

	// Save TLS info
	if len(result.TLSInfo) > 0 {
		m.saveJSON(filepath.Join(dir, "tls_info.json"), result.TLSInfo)
	}

	return nil
}

// SaveTakeoverResults saves subdomain takeover results
func (m *Manager) SaveTakeoverResults(result *takeover.Result) error {
	m.results["takeover"] = result
	dir := m.phaseDir("4-takeover")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "takeover.json"), result); err != nil {
		return err
	}

	// Save vulnerable subdomains
	if len(result.Vulnerable) > 0 {
		var vulnList []string
		for _, v := range result.Vulnerable {
			svc := v.Service
			if svc == "" {
				svc = "unknown"
			}
			vulnList = append(vulnList, fmt.Sprintf("%s | %s | %s | %s", v.Subdomain, svc, v.Severity, v.Tool))
		}
		m.saveLines(filepath.Join(dir, "vulnerable.txt"), vulnList)
	}

	return nil
}

// SaveHistoricResults saves historic URL collection results
func (m *Manager) SaveHistoricResults(result *historic.Result) error {
	m.results["historic"] = result
	dir := m.phaseDir("5-historic")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "historic_urls.json"), result); err != nil {
		return err
	}

	// Save all URLs
	if len(result.URLs) > 0 {
		m.saveLines(filepath.Join(dir, "urls.txt"), result.URLs)
	}

	// Save interesting URLs (filtered)
	interesting := historic.FilterInteresting(result.URLs)
	if len(interesting) > 0 {
		m.saveLines(filepath.Join(dir, "interesting_urls.txt"), interesting)
	}

	// Save unique endpoints
	endpoints := historic.ExtractEndpoints(result.URLs)
	if len(endpoints) > 0 {
		m.saveLines(filepath.Join(dir, "endpoints.txt"), endpoints)
	}

	return nil
}

// SaveSummary saves a summary of all results
func (m *Manager) SaveSummary(target string) error {
	summary := Summary{
		Target:    target,
		Timestamp: time.Now(),
		Results:   make(map[string]interface{}),
	}

	// Build summary stats
	if subResult, ok := m.results["subdomains"].(*subdomain.Result); ok {
		summary.Results["subdomains"] = map[string]interface{}{
			"total":     subResult.Total,
			"total_all": subResult.TotalAll,
			"sources":   subResult.Sources,
			"duration":  subResult.Duration.String(),
		}
	}

	if wafResult, ok := m.results["waf"].(*waf.Result); ok {
		summary.Results["waf"] = map[string]interface{}{
			"cdn_hosts":    len(wafResult.CDNHosts),
			"direct_hosts": len(wafResult.DirectHosts),
			"duration":     wafResult.Duration.String(),
		}
	}

	if portResult, ok := m.results["ports"].(*portscan.Result); ok {
		summary.Results["ports"] = map[string]interface{}{
			"total_ports": portResult.TotalPorts,
			"alive_hosts": len(portResult.AliveHosts),
			"tls_hosts":   len(portResult.TLSInfo),
			"duration":    portResult.Duration.String(),
		}
	}

	if takeoverResult, ok := m.results["takeover"].(*takeover.Result); ok {
		summary.Results["takeover"] = map[string]interface{}{
			"checked":    takeoverResult.TotalChecked,
			"vulnerable": len(takeoverResult.Vulnerable),
			"duration":   takeoverResult.Duration.String(),
		}
	}

	if historicResult, ok := m.results["historic"].(*historic.Result); ok {
		summary.Results["historic"] = map[string]interface{}{
			"total_urls": historicResult.Total,
			"sources":    historicResult.Sources,
			"duration":   historicResult.Duration.String(),
		}
	}

	return m.saveJSON(filepath.Join(m.outputDir, "summary.json"), summary)
}

// Summary represents a scan summary
type Summary struct {
	Target    string                 `json:"target"`
	Timestamp time.Time              `json:"timestamp"`
	Results   map[string]interface{} `json:"results"`
}

// saveJSON saves data as formatted JSON
func (m *Manager) saveJSON(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// saveLines saves a list of strings to a file
func (m *Manager) saveLines(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}

	_, err = file.WriteString(content)
	return err
}
