package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/storage"
)

// Builder constructs PhaseInput by reading outputs from previous phases
type Builder struct {
	storage storage.Storage
	scanID  string
	target  string
	cfg     *config.Config
}

// NewBuilder creates a new phase input builder
func NewBuilder(s storage.Storage, scanID, target string, cfg *config.Config) *Builder {
	return &Builder{
		storage: s,
		scanID:  scanID,
		target:  target,
		cfg:     cfg,
	}
}

// Build constructs a PhaseInput for the given phase by loading its dependencies
func (b *Builder) Build(ctx context.Context, phase Phase) (*PhaseInput, error) {
	input := NewPhaseInput(b.target, b.scanID, b.cfg)

	deps := GetDependencies(phase)
	loadedDeps := 0
	for _, dep := range deps {
		if err := b.loadPhaseData(ctx, dep, input); err != nil {
			// Dependencies are soft - phase can run with partial data
			// Log warning but continue - expected for phases that didn't run (e.g., IPRange for domain targets)
			// Check if it's a "not exist" error (expected) vs other errors (unexpected)
			if !os.IsNotExist(err) && !isStorageNotFound(err) {
				fmt.Printf("        [Builder] Warning: Failed to load %s dependency for %s: %v\n", dep, phase, err)
			}
			continue
		}
		loadedDeps++
	}

	if len(deps) > 0 {
		fmt.Printf("        [Builder] Loaded %d/%d dependencies for %s\n", loadedDeps, len(deps), phase)
	}

	// CRITICAL FIX: Merge historic extracted subdomains into Subdomains for Ports/Takeover phases
	// This ensures subdomains discovered in wayback/gau URLs are scanned for live hosts
	if phase == PhasePorts || phase == PhaseTakeover {
		if len(input.ExtractedSubdomains) > 0 {
			beforeCount := len(input.Subdomains)
			input.Subdomains = b.mergeSubdomains(input.Subdomains, input.ExtractedSubdomains)
			input.AllSubdomains = b.mergeSubdomains(input.AllSubdomains, input.ExtractedSubdomains)
			newCount := len(input.Subdomains) - beforeCount
			if newCount > 0 {
				fmt.Printf("        [Builder] Merged %d historic subdomains into scan list (total: %d)\n",
					newCount, len(input.Subdomains))
			}
		}
	}

	return input, nil
}

// mergeSubdomains merges two subdomain lists, removing duplicates
func (b *Builder) mergeSubdomains(existing, additional []string) []string {
	if len(additional) == 0 {
		return existing
	}

	seen := make(map[string]bool, len(existing)+len(additional))
	result := make([]string, 0, len(existing)+len(additional))

	// Add existing first (preserves order priority)
	for _, s := range existing {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	// Add new subdomains from historic extraction
	for _, s := range additional {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// isStorageNotFound checks if an error indicates the data doesn't exist
func isStorageNotFound(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "does not exist") ||
		strings.Contains(errStr, "no such file")
}

// BuildWithRequired constructs a PhaseInput and fails if required dependencies are missing
func (b *Builder) BuildWithRequired(ctx context.Context, phase Phase, required []Phase) (*PhaseInput, error) {
	input := NewPhaseInput(b.target, b.scanID, b.cfg)

	deps := GetDependencies(phase)
	for _, dep := range deps {
		err := b.loadPhaseData(ctx, dep, input)

		// Check if this was a required dependency
		isRequired := false
		for _, req := range required {
			if req == dep {
				isRequired = true
				break
			}
		}

		if err != nil && isRequired {
			return nil, fmt.Errorf("required dependency %s not available: %w", dep, err)
		}
	}

	return input, nil
}

// loadPhaseData loads output from a specific phase into the input
func (b *Builder) loadPhaseData(ctx context.Context, phase Phase, input *PhaseInput) error {
	// Determine the output file path based on phase
	path := b.getPhaseOutputPath(phase)

	// Debug: Show what we're trying to load
	fullPath := filepath.Join(b.storage.BaseDir(), path)
	fmt.Printf("        [Builder] Loading %s data from: %s\n", phase, fullPath)

	data, err := b.storage.Read(ctx, path)
	if err != nil {
		// Check if file exists on disk to help debug
		if _, statErr := os.Stat(fullPath); os.IsNotExist(statErr) {
			fmt.Printf("        [Builder] File not found: %s (expected from previous scan)\n", fullPath)
		} else {
			fmt.Printf("        [Builder] Error reading %s: %v\n", path, err)
		}
		return fmt.Errorf("failed to load %s data from %s: %w", phase, path, err)
	}

	fmt.Printf("        [Builder] Loaded existing %s data (%d bytes)\n", phase, len(data))

	// Parse based on phase type
	switch phase {
	case PhaseIPRange:
		return b.parseIPRangeOutput(data, input)
	case PhaseSubdomain:
		return b.parseSubdomainOutput(data, input)
	case PhaseWAF:
		return b.parseWAFOutput(data, input)
	case PhasePorts:
		return b.parsePortsOutput(data, input)
	case PhaseVHost:
		// VHost data is consumed by report generation, not other phases
		// No parsing needed for pipeline dependencies
		return nil
	case PhaseHistoric:
		return b.parseHistoricOutput(data, input)
	case PhaseTech:
		return b.parseTechOutput(data, input)
	case PhaseVulnScan:
		return b.parseVulnOutput(data, input)
	case PhaseTakeover:
		return b.parseTakeoverOutput(data, input)
	case PhaseDirBrute:
		return b.parseDirBruteOutput(data, input)
	case PhaseSecHeaders:
		return b.parseSecHeadersOutput(data, input)
	case PhaseJSAnalysis:
		// JSAnalysis data is consumed by report generation, not other phases
		// No parsing needed for pipeline dependencies
		return nil
	case PhaseScreenshot:
		// Screenshot data is consumed by report generation, not other phases
		// No parsing needed for pipeline dependencies
		return nil
	case PhaseAIGuided:
		// AIGuided is a terminal phase, no downstream dependencies
		return nil
	}

	return nil
}

// getPhaseOutputPath returns the path to a phase's output JSON file
func (b *Builder) getPhaseOutputPath(phase Phase) string {
	// Map phase to directory name (matching current output structure)
	// IMPORTANT: These MUST match output/manager.go phaseDir() calls
	dirMap := map[Phase]string{
		PhaseIPRange:    "0-iprange",
		PhaseSubdomain:  "1-subdomains",
		PhaseWAF:        "2-waf",
		PhasePorts:      "3-ports",
		PhaseVHost:      "4-vhost",
		PhaseTakeover:   "4-takeover",
		PhaseHistoric:   "5-historic",
		PhaseTech:       "6-tech",
		PhaseJSAnalysis: "7b-jsanalysis",
		PhaseSecHeaders: "6b-secheaders", // FIXED: was 8-secheaders, must match output/manager.go
		PhaseDirBrute:   "7-dirbrute",
		PhaseVulnScan:   "8-vulnscan",
		PhaseScreenshot: "9-screenshots",
		PhaseAIGuided:   "10-aiguided",
	}

	// Map phase to JSON filename
	// IMPORTANT: These MUST match output/manager.go saveJSON() calls
	fileMap := map[Phase]string{
		PhaseIPRange:    "ip_discovery.json",
		PhaseSubdomain:  "subdomains.json",
		PhaseWAF:        "waf_detection.json",
		PhasePorts:      "port_scan.json",
		PhaseVHost:      "vhost.json",
		PhaseTakeover:   "takeover.json",
		PhaseHistoric:   "historic_urls.json",
		PhaseTech:       "tech_detection.json",
		PhaseJSAnalysis: "js_analysis.json",
		PhaseSecHeaders: "security_headers.json",
		PhaseDirBrute:   "dirbrute.json",
		PhaseVulnScan:   "vulnerabilities.json",
		PhaseScreenshot: "screenshot_results.json", // FIXED: was screenshot_clusters.json, must match output/manager.go
		PhaseAIGuided:   "ai_guided.json",
	}

	return filepath.Join(dirMap[phase], fileMap[phase])
}

// Phase-specific parsers

func (b *Builder) parseSubdomainOutput(data []byte, input *PhaseInput) error {
	var output struct {
		Subdomains    []string `json:"subdomains"`
		AllSubdomains []string `json:"all_subdomains"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		fmt.Printf("        [Builder] Failed to parse subdomain JSON: %v\n", err)
		return err
	}
	input.Subdomains = output.Subdomains
	input.AllSubdomains = output.AllSubdomains
	fmt.Printf("        [Builder] Parsed %d subdomains, %d all_subdomains\n", len(input.Subdomains), len(input.AllSubdomains))
	return nil
}

func (b *Builder) parseWAFOutput(data []byte, input *PhaseInput) error {
	var output struct {
		CDNHosts    []string `json:"cdn_hosts"`
		DirectHosts []string `json:"direct_hosts"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.CDNHosts = output.CDNHosts
	input.DirectHosts = output.DirectHosts
	return nil
}

func (b *Builder) parsePortsOutput(data []byte, input *PhaseInput) error {
	var output struct {
		AliveHosts []string            `json:"alive_hosts"`
		OpenPorts  map[string][]int    `json:"open_ports"`
		TLSInfo    json.RawMessage     `json:"tls_info"` // Skip parsing - complex struct not needed by downstream phases
		CDNHosts   []string            `json:"cdn_hosts"`
		NonCDN     []string            `json:"non_cdn_hosts"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		fmt.Printf("        [Builder] Failed to parse ports JSON: %v\n", err)
		return err
	}
	input.AliveHosts = output.AliveHosts
	input.OpenPorts = output.OpenPorts
	// TLSInfo is not used by downstream phases, only for report generation
	// CDN info can be used for filtering
	if len(output.NonCDN) > 0 {
		input.DirectHosts = output.NonCDN
	}
	if len(output.CDNHosts) > 0 {
		input.CDNHosts = output.CDNHosts
	}
	fmt.Printf("        [Builder] Parsed %d alive_hosts, %d non-CDN, %d CDN\n",
		len(input.AliveHosts), len(input.DirectHosts), len(input.CDNHosts))
	return nil
}

func (b *Builder) parseHistoricOutput(data []byte, input *PhaseInput) error {
	var output struct {
		URLs                []string `json:"urls"`
		ExtractedSubdomains []string `json:"extracted_subdomains"`
		Categorized         *struct {
			XSS       []string `json:"xss"`
			SQLi      []string `json:"sqli"`
			SSRF      []string `json:"ssrf"`
			LFI       []string `json:"lfi"`
			RCE       []string `json:"rce"`
			SSTI      []string `json:"ssti"`
			Redirect  []string `json:"redirect"`
			Debug     []string `json:"debug"`
			JSFiles   []string `json:"js_files"`
			APIFiles  []string `json:"api_files"`
			Sensitive []string `json:"sensitive"`
		} `json:"categorized"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.URLs = output.URLs
	input.ExtractedSubdomains = output.ExtractedSubdomains

	if output.Categorized != nil {
		input.CategorizedURLs = &CategorizedURLs{
			XSS:       output.Categorized.XSS,
			SQLi:      output.Categorized.SQLi,
			SSRF:      output.Categorized.SSRF,
			LFI:       output.Categorized.LFI,
			RCE:       output.Categorized.RCE,
			SSTI:      output.Categorized.SSTI,
			Redirect:  output.Categorized.Redirect,
			Debug:     output.Categorized.Debug,
			JSFiles:   output.Categorized.JSFiles,
			APIFiles:  output.Categorized.APIFiles,
			Sensitive: output.Categorized.Sensitive,
		}
	}
	return nil
}

func (b *Builder) parseTechOutput(data []byte, input *PhaseInput) error {
	var output struct {
		TechByHost map[string][]string `json:"tech_by_host"`
		TechCount  map[string]int      `json:"tech_count"`
		HttpxURLs  []string            `json:"httpx_urls"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.TechByHost = output.TechByHost
	input.TechCount = output.TechCount
	input.HttpxURLs = output.HttpxURLs
	fmt.Printf("        [Builder] Parsed tech: %d hosts, %d httpx_urls\n", len(input.TechByHost), len(input.HttpxURLs))
	return nil
}

func (b *Builder) parseVulnOutput(data []byte, input *PhaseInput) error {
	var output struct {
		Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.Vulnerabilities = output.Vulnerabilities
	return nil
}

func (b *Builder) parseTakeoverOutput(data []byte, input *PhaseInput) error {
	var output struct {
		Vulnerable []TakeoverVuln `json:"vulnerable"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.TakeoverVulns = output.Vulnerable
	return nil
}

func (b *Builder) parseDirBruteOutput(data []byte, input *PhaseInput) error {
	var output struct {
		Discoveries []Discovery `json:"discoveries"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.Discoveries = output.Discoveries
	return nil
}

func (b *Builder) parseIPRangeOutput(data []byte, input *PhaseInput) error {
	var output struct {
		Target      string   `json:"target"`
		IPs         []string `json:"ips"`
		Domains     []string `json:"domains"`
		BaseDomains []string `json:"base_domains"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.IPRangeIPs = output.IPs
	input.IPRangeDomains = output.Domains
	input.IPRangeBaseDomains = output.BaseDomains
	return nil
}

func (b *Builder) parseSecHeadersOutput(data []byte, input *PhaseInput) error {
	var output struct {
		HeaderFindings []struct {
			Missing []struct{} `json:"missing"`
		} `json:"header_findings"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	// Count hosts with missing security headers
	count := 0
	for _, finding := range output.HeaderFindings {
		if len(finding.Missing) > 0 {
			count++
		}
	}
	input.SecurityHeaderIssues = count
	fmt.Printf("        [Builder] Parsed security headers: %d hosts with issues\n", count)
	return nil
}
