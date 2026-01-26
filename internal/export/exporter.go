package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/report"
)

// Format represents an export format type
type Format string

const (
	FormatCSV      Format = "csv"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// Exporter handles exporting scan results to various formats
type Exporter struct {
	data   *report.Data
	outDir string
}

// NewExporter creates a new exporter
func NewExporter(data *report.Data, outDir string) *Exporter {
	return &Exporter{data: data, outDir: outDir}
}

// Export exports data to the specified format
func (e *Exporter) Export(format Format) (string, error) {
	switch format {
	case FormatCSV:
		return e.ExportCSV()
	case FormatJSON:
		return e.ExportJSON()
	case FormatMarkdown:
		return e.ExportMarkdown()
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// ExportAll exports to all supported formats
func (e *Exporter) ExportAll() ([]string, error) {
	var files []string

	for _, format := range []Format{FormatCSV, FormatJSON, FormatMarkdown} {
		path, err := e.Export(format)
		if err != nil {
			return files, err
		}
		files = append(files, path)
	}

	return files, nil
}

// ExportCSV exports scan results to CSV files
func (e *Exporter) ExportCSV() (string, error) {
	exportDir := filepath.Join(e.outDir, "exports")
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", err
	}

	// Export subdomains
	if e.data.Subdomain != nil && len(e.data.Subdomain.Subdomains) > 0 {
		if err := e.exportSubdomainsCSV(filepath.Join(exportDir, "subdomains.csv")); err != nil {
			return "", err
		}
	}

	// Export vulnerabilities
	if e.data.VulnScan != nil && len(e.data.VulnScan.Vulnerabilities) > 0 {
		if err := e.exportVulnsCSV(filepath.Join(exportDir, "vulnerabilities.csv")); err != nil {
			return "", err
		}
	}

	// Export ports
	if e.data.Ports != nil && len(e.data.Ports.AliveHosts) > 0 {
		if err := e.exportPortsCSV(filepath.Join(exportDir, "ports.csv")); err != nil {
			return "", err
		}
	}

	// Export endpoints from JS analysis
	if e.data.JSAnalysis != nil && len(e.data.JSAnalysis.Endpoints) > 0 {
		if err := e.exportEndpointsCSV(filepath.Join(exportDir, "endpoints.csv")); err != nil {
			return "", err
		}
	}

	return exportDir, nil
}

func (e *Exporter) exportSubdomainsCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"subdomain", "is_alive", "technologies", "waf_protected", "cdn_provider"})

	// Build lookup maps for enrichment
	alive := make(map[string]bool)
	techs := make(map[string][]string)
	cdnProtected := make(map[string]bool)
	cdnProvider := make(map[string]string)

	if e.data.Ports != nil {
		for _, h := range e.data.Ports.AliveHosts {
			alive[h] = true
		}
	}
	if e.data.Tech != nil {
		for host, t := range e.data.Tech.TechByHost {
			techs[host] = t
		}
	}
	if e.data.WAF != nil {
		for _, h := range e.data.WAF.CDNHosts {
			cdnProtected[h] = true
		}
		for host, provider := range e.data.WAF.CDNDetails {
			cdnProvider[host] = provider
		}
	}

	// Write data
	for _, sub := range e.data.Subdomain.Subdomains {
		isAlive := "false"
		if alive[sub] {
			isAlive = "true"
		}
		wafStatus := "false"
		if cdnProtected[sub] {
			wafStatus = "true"
		}
		techList := strings.Join(techs[sub], "; ")
		w.Write([]string{
			sub,
			isAlive,
			techList,
			wafStatus,
			cdnProvider[sub],
		})
	}

	return nil
}

func (e *Exporter) exportVulnsCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"severity", "name", "template_id", "host", "url", "type", "tool", "description"})

	// Sort by severity
	vulns := e.data.VulnScan.Vulnerabilities
	sort.Slice(vulns, func(i, j int) bool {
		return severityRank(vulns[i].Severity) > severityRank(vulns[j].Severity)
	})

	for _, v := range vulns {
		w.Write([]string{
			v.Severity,
			v.Name,
			v.TemplateID,
			v.Host,
			v.URL,
			v.Type,
			v.Tool,
			v.Description,
		})
	}

	return nil
}

func (e *Exporter) exportPortsCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"host", "port", "service"})

	// Use OpenPorts and Services maps
	for host, ports := range e.data.Ports.OpenPorts {
		services := e.data.Ports.Services[host]
		serviceMap := make(map[int]string)
		for _, svc := range services {
			// Use WebServer or Title as service identifier
			name := svc.WebServer
			if name == "" {
				name = svc.Title
			}
			serviceMap[svc.Port] = name
		}

		for _, port := range ports {
			serviceName := serviceMap[port]
			if serviceName == "" {
				serviceName = "unknown"
			}
			w.Write([]string{
				host,
				fmt.Sprintf("%d", port),
				serviceName,
			})
		}
	}

	return nil
}

func (e *Exporter) exportEndpointsCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"path", "url", "source", "method", "sensitive"})

	for _, ep := range e.data.JSAnalysis.Endpoints {
		sensitive := "false"
		if ep.Sensitive {
			sensitive = "true"
		}
		w.Write([]string{
			ep.Path,
			ep.URL,
			ep.Source,
			ep.Method,
			sensitive,
		})
	}

	return nil
}

// ExportJSON exports complete scan data as structured JSON
func (e *Exporter) ExportJSON() (string, error) {
	exportDir := filepath.Join(e.outDir, "exports")
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", err
	}

	// Create structured export data
	exportData := struct {
		Metadata    MetadataExport    `json:"metadata"`
		Subdomains  []SubdomainExport `json:"subdomains,omitempty"`
		Vulns       []VulnExport      `json:"vulnerabilities,omitempty"`
		Ports       []PortExport      `json:"ports,omitempty"`
		Endpoints   []EndpointExport  `json:"endpoints,omitempty"`
		Technologies map[string][]string `json:"technologies,omitempty"`
	}{
		Metadata: MetadataExport{
			Target:    e.data.Target,
			Version:   e.data.Version,
			Date:      e.data.Date,
			Duration:  e.data.Duration,
			Generated: time.Now().Format(time.RFC3339),
		},
	}

	// Add subdomains
	if e.data.Subdomain != nil {
		for _, sub := range e.data.Subdomain.Subdomains {
			exportData.Subdomains = append(exportData.Subdomains, SubdomainExport{
				Name: sub,
			})
		}
	}

	// Add vulnerabilities
	if e.data.VulnScan != nil {
		for _, v := range e.data.VulnScan.Vulnerabilities {
			exportData.Vulns = append(exportData.Vulns, VulnExport{
				Severity:    v.Severity,
				Name:        v.Name,
				TemplateID:  v.TemplateID,
				Host:        v.Host,
				URL:         v.URL,
				Type:        v.Type,
				Tool:        v.Tool,
				Description: v.Description,
			})
		}
	}

	// Add ports
	if e.data.Ports != nil {
		for host, ports := range e.data.Ports.OpenPorts {
			services := e.data.Ports.Services[host]
			serviceMap := make(map[int]string)
			for _, svc := range services {
				name := svc.WebServer
				if name == "" {
					name = svc.Title
				}
				serviceMap[svc.Port] = name
			}
			for _, port := range ports {
				exportData.Ports = append(exportData.Ports, PortExport{
					Host:    host,
					Port:    port,
					Service: serviceMap[port],
				})
			}
		}
	}

	// Add endpoints
	if e.data.JSAnalysis != nil {
		for _, ep := range e.data.JSAnalysis.Endpoints {
			exportData.Endpoints = append(exportData.Endpoints, EndpointExport{
				Path:      ep.Path,
				URL:       ep.URL,
				Source:    ep.Source,
				Sensitive: ep.Sensitive,
			})
		}
	}

	// Add technologies
	if e.data.Tech != nil {
		exportData.Technologies = e.data.Tech.TechByHost
	}

	// Write JSON
	path := filepath.Join(exportDir, "scan_export.json")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exportData); err != nil {
		return "", err
	}

	return path, nil
}

// ExportMarkdown exports a markdown summary
func (e *Exporter) ExportMarkdown() (string, error) {
	exportDir := filepath.Join(e.outDir, "exports")
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", err
	}

	path := filepath.Join(exportDir, "report_summary.md")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var sb strings.Builder

	// Title
	sb.WriteString(fmt.Sprintf("# Reconator Scan Report: %s\n\n", e.data.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", e.data.Date))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", e.data.Duration))
	sb.WriteString(fmt.Sprintf("**Version:** %s\n\n", e.data.Version))
	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")

	if e.data.Subdomain != nil {
		sb.WriteString(fmt.Sprintf("| Subdomains | %d |\n", len(e.data.Subdomain.Subdomains)))
	}
	if e.data.Ports != nil {
		sb.WriteString(fmt.Sprintf("| Alive Hosts | %d |\n", e.data.Ports.AliveCount))
		sb.WriteString(fmt.Sprintf("| Open Ports | %d |\n", e.data.Ports.TotalPorts))
	}
	if e.data.VulnScan != nil {
		sb.WriteString(fmt.Sprintf("| Vulnerabilities | %d |\n", len(e.data.VulnScan.Vulnerabilities)))
		if e.data.VulnScan.BySeverity != nil {
			sb.WriteString(fmt.Sprintf("| Critical | %d |\n", e.data.VulnScan.BySeverity["critical"]))
			sb.WriteString(fmt.Sprintf("| High | %d |\n", e.data.VulnScan.BySeverity["high"]))
		}
	}
	if e.data.Takeover != nil {
		sb.WriteString(fmt.Sprintf("| Takeover Vulns | %d |\n", len(e.data.Takeover.Vulnerable)))
	}
	sb.WriteString("\n")

	// Vulnerabilities Section
	if e.data.VulnScan != nil && len(e.data.VulnScan.Vulnerabilities) > 0 {
		sb.WriteString("## Vulnerabilities\n\n")

		// Sort by severity
		vulns := e.data.VulnScan.Vulnerabilities
		sort.Slice(vulns, func(i, j int) bool {
			return severityRank(vulns[i].Severity) > severityRank(vulns[j].Severity)
		})

		// Group by severity
		bySeverity := make(map[string]int)
		for _, v := range vulns {
			bySeverity[v.Severity]++
		}

		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := bySeverity[sev]; ok && count > 0 {
				sb.WriteString(fmt.Sprintf("### %s (%d)\n\n", strings.Title(sev), count))
				for _, v := range vulns {
					if v.Severity == sev {
						sb.WriteString(fmt.Sprintf("- **%s** (`%s`)\n", v.Name, v.TemplateID))
						if v.URL != "" {
							sb.WriteString(fmt.Sprintf("  - URL: `%s`\n", v.URL))
						} else if v.Host != "" {
							sb.WriteString(fmt.Sprintf("  - Host: `%s`\n", v.Host))
						}
						sb.WriteString(fmt.Sprintf("  - Tool: %s\n", v.Tool))
					}
				}
				sb.WriteString("\n")
			}
		}
	}

	// Subdomain Takeovers
	if e.data.Takeover != nil && len(e.data.Takeover.Vulnerable) > 0 {
		sb.WriteString("## Subdomain Takeover Vulnerabilities\n\n")
		for _, t := range e.data.Takeover.Vulnerable {
			sb.WriteString(fmt.Sprintf("- **%s** - %s\n", t.Subdomain, t.Service))
		}
		sb.WriteString("\n")
	}

	// Technologies Detected
	if e.data.Tech != nil && len(e.data.Tech.TechByHost) > 0 {
		sb.WriteString("## Technologies Detected\n\n")

		// Aggregate tech counts
		techCounts := make(map[string]int)
		for _, techs := range e.data.Tech.TechByHost {
			for _, t := range techs {
				techCounts[t]++
			}
		}

		// Sort by count
		type techCount struct {
			name  string
			count int
		}
		var sorted []techCount
		for name, count := range techCounts {
			sorted = append(sorted, techCount{name, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})

		sb.WriteString("| Technology | Hosts |\n")
		sb.WriteString("|------------|-------|\n")
		for _, tc := range sorted[:min(20, len(sorted))] {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", tc.name, tc.count))
		}
		sb.WriteString("\n")
	}

	// JS Analysis Findings
	if e.data.JSAnalysis != nil {
		if len(e.data.JSAnalysis.DOMXSSSinks) > 0 {
			sb.WriteString("## DOM XSS Sinks\n\n")
			for _, sink := range e.data.JSAnalysis.DOMXSSSinks {
				icon := ""
				if sink.HasInput {
					icon = " [USER INPUT]"
				}
				sb.WriteString(fmt.Sprintf("- **[%s]** %s%s\n", sink.Severity, sink.Type, icon))
				sb.WriteString(fmt.Sprintf("  - Source: `%s:%d`\n", sink.Source, sink.Line))
			}
			sb.WriteString("\n")
		}

		if len(e.data.JSAnalysis.Secrets) > 0 {
			sb.WriteString("## Exposed Secrets\n\n")
			for _, secret := range e.data.JSAnalysis.Secrets {
				sb.WriteString(fmt.Sprintf("- **%s**: `%s`\n", secret.Type, secret.Value))
				sb.WriteString(fmt.Sprintf("  - Source: `%s`\n", secret.Source))
			}
			sb.WriteString("\n")
		}
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Generated by Reconator %s*\n", e.data.Version))

	f.WriteString(sb.String())
	return path, nil
}

// Export types for JSON
type MetadataExport struct {
	Target    string `json:"target"`
	Version   string `json:"version"`
	Date      string `json:"date"`
	Duration  string `json:"duration"`
	Generated string `json:"generated"`
}

type SubdomainExport struct {
	Name string `json:"name"`
}

type VulnExport struct {
	Severity    string `json:"severity"`
	Name        string `json:"name"`
	TemplateID  string `json:"template_id"`
	Host        string `json:"host,omitempty"`
	URL         string `json:"url,omitempty"`
	Type        string `json:"type"`
	Tool        string `json:"tool"`
	Description string `json:"description,omitempty"`
}

type PortExport struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

type EndpointExport struct {
	Path      string `json:"path"`
	URL       string `json:"url,omitempty"`
	Source    string `json:"source"`
	Sensitive bool   `json:"sensitive"`
}

// Helper functions
func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
