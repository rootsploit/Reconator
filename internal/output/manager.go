package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/storage"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// Manager handles output file management
type Manager struct {
	outputDir string
	results   map[string]interface{}

	// Scan metadata (set once per scan, zero overhead)
	scanID    string
	target    string
	version   string
	startTime time.Time
}

// NewManager creates a new output manager
func NewManager(outputDir string) *Manager {
	return &Manager{
		outputDir: outputDir,
		results:   make(map[string]interface{}),
		scanID:    storage.GenerateScanID(),
		startTime: time.Now(),
	}
}

// SetScanMeta sets scan-level metadata (call once at scan start)
// Zero overhead: just stores values, no I/O
func (m *Manager) SetScanMeta(target, version string) {
	m.target = target
	m.version = version
}

// ScanID returns the unique scan identifier
func (m *Manager) ScanID() string {
	return m.scanID
}

// BaseDir returns the base output directory
func (m *Manager) BaseDir() string {
	return m.outputDir
}

// phaseDir creates and returns the path to a phase subdirectory
func (m *Manager) phaseDir(phase string) string {
	dir := filepath.Join(m.outputDir, phase)
	os.MkdirAll(dir, 0755)
	return dir
}

// SaveIPRangeResults saves IP range discovery results
func (m *Manager) SaveIPRangeResults(result *iprange.Result) error {
	m.results["iprange"] = result
	dir := m.phaseDir("0-iprange")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "ip_discovery.json"), result); err != nil {
		return err
	}

	// Save discovered IPs
	if len(result.IPs) > 0 {
		m.saveLines(filepath.Join(dir, "ips.txt"), result.IPs)
	}

	// Save discovered domains
	if len(result.Domains) > 0 {
		m.saveLines(filepath.Join(dir, "domains.txt"), result.Domains)
	}

	// Save base domains (TLDs)
	tlds := iprange.ExtractTLDs(result.Domains)
	if len(tlds) > 0 {
		m.saveLines(filepath.Join(dir, "base_domains.txt"), tlds)
	}

	return nil
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

// SaveTechResults saves technology detection results
func (m *Manager) SaveTechResults(result *techdetect.Result) error {
	m.results["tech"] = result
	dir := m.phaseDir("6-tech")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "tech_detection.json"), result); err != nil {
		return err
	}

	// Save tech by host
	if len(result.TechByHost) > 0 {
		var lines []string
		for host, techs := range result.TechByHost {
			lines = append(lines, fmt.Sprintf("%s: %s", host, strings.Join(techs, ", ")))
		}
		sort.Strings(lines)
		m.saveLines(filepath.Join(dir, "tech_by_host.txt"), lines)
	}

	// Save tech summary (most common technologies)
	if len(result.TechCount) > 0 {
		var lines []string
		for tech, count := range result.TechCount {
			lines = append(lines, fmt.Sprintf("%s: %d", tech, count))
		}
		sort.Strings(lines)
		m.saveLines(filepath.Join(dir, "tech_summary.txt"), lines)
	}

	return nil
}

// SaveDirBruteResults saves directory bruteforce results
func (m *Manager) SaveDirBruteResults(result *dirbrute.Result) error {
	m.results["dirbrute"] = result
	dir := m.phaseDir("7-dirbrute")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "dirbrute.json"), result); err != nil {
		return err
	}

	// Save discoveries
	if len(result.Discoveries) > 0 {
		var lines []string
		for _, d := range result.Discoveries {
			lines = append(lines, fmt.Sprintf("%s [%d] %s", d.URL, d.StatusCode, d.Tool))
		}
		m.saveLines(filepath.Join(dir, "discoveries.txt"), lines)

		// Save just URLs
		var urls []string
		for _, d := range result.Discoveries {
			urls = append(urls, d.URL)
		}
		m.saveLines(filepath.Join(dir, "discovered_urls.txt"), urls)
	}

	return nil
}

// SaveVulnResults saves vulnerability scanning results
func (m *Manager) SaveVulnResults(result *vulnscan.Result) error {
	m.results["vulnscan"] = result
	dir := m.phaseDir("8-vulnscan")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "vulnerabilities.json"), result); err != nil {
		return err
	}

	// Save vulnerabilities by severity
	if len(result.Vulnerabilities) > 0 {
		var critical, high, medium []string
		for _, v := range result.Vulnerabilities {
			line := fmt.Sprintf("%s | %s | %s | %s", v.Host, v.TemplateID, v.Name, v.Tool)
			if v.URL != "" {
				line = fmt.Sprintf("%s | %s | %s | %s", v.URL, v.TemplateID, v.Name, v.Tool)
			}
			switch v.Severity {
			case "critical":
				critical = append(critical, line)
			case "high":
				high = append(high, line)
			case "medium":
				medium = append(medium, line)
			}
		}
		if len(critical) > 0 {
			m.saveLines(filepath.Join(dir, "critical.txt"), critical)
		}
		if len(high) > 0 {
			m.saveLines(filepath.Join(dir, "high.txt"), high)
		}
		if len(medium) > 0 {
			m.saveLines(filepath.Join(dir, "medium.txt"), medium)
		}

		// Save all vulnerabilities
		var all []string
		for _, v := range result.Vulnerabilities {
			line := fmt.Sprintf("[%s] %s | %s | %s", v.Severity, v.Host, v.TemplateID, v.Name)
			all = append(all, line)
		}
		m.saveLines(filepath.Join(dir, "all_vulnerabilities.txt"), all)
	}

	return nil
}

// SaveAIGuidedResults saves AI-guided scanning results
func (m *Manager) SaveAIGuidedResults(result *aiguided.Result) error {
	m.results["aiguided"] = result
	dir := m.phaseDir("9-aiguided")

	// Save JSON
	if err := m.saveJSON(filepath.Join(dir, "ai_guided.json"), result); err != nil {
		return err
	}

	// Save AI recommendations
	recLines := []string{
		fmt.Sprintf("AI Provider: %s", result.AIProvider),
		fmt.Sprintf("Summary: %s", result.TargetSummary),
		fmt.Sprintf("Recommended Tags: %v", result.RecommendedTags),
	}
	if len(result.RecommendedTemplates) > 0 {
		recLines = append(recLines, fmt.Sprintf("Recommended Templates: %v", result.RecommendedTemplates))
	}
	m.saveLines(filepath.Join(dir, "ai_recommendations.txt"), recLines)

	// Save vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		var lines []string
		for _, v := range result.Vulnerabilities {
			line := fmt.Sprintf("[%s] %s | %s | %s", v.Severity, v.Host, v.TemplateID, v.Name)
			lines = append(lines, line)
		}
		m.saveLines(filepath.Join(dir, "ai_vulnerabilities.txt"), lines)
	}

	return nil
}

// SaveSummary saves a summary of all results
func (m *Manager) SaveSummary(target string) error {
	endTime := time.Now()
	summary := Summary{
		ScanID:    m.scanID,
		Target:    target,
		Version:   m.version,
		StartTime: m.startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(m.startTime).String(),
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

	if techResult, ok := m.results["tech"].(*techdetect.Result); ok {
		summary.Results["tech"] = map[string]interface{}{
			"hosts_scanned": techResult.Total,
			"unique_techs":  len(techResult.TechCount),
			"duration":      techResult.Duration.String(),
		}
	}

	return m.saveJSON(filepath.Join(m.outputDir, "summary.json"), summary)
}

// Summary represents a scan summary
type Summary struct {
	// Scan metadata
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	Version   string    `json:"version,omitempty"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`

	// Phase results
	Results map[string]interface{} `json:"results"`
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
