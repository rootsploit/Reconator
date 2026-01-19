package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

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
	for _, dep := range deps {
		if err := b.loadPhaseData(ctx, dep, input); err != nil {
			// Dependencies are soft - phase can run with partial data
			// Log but don't fail
			fmt.Printf("        [Builder] Could not load %s data: %v\n", dep, err)
			continue
		}
	}

	return input, nil
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

	data, err := b.storage.Read(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to load %s data from %s: %w", phase, path, err)
	}

	fmt.Printf("        [Builder] Loaded existing %s data from %s\n", phase, path)

	// Parse based on phase type
	switch phase {
	case PhaseSubdomain:
		return b.parseSubdomainOutput(data, input)
	case PhaseWAF:
		return b.parseWAFOutput(data, input)
	case PhasePorts:
		return b.parsePortsOutput(data, input)
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
	}

	return nil
}

// getPhaseOutputPath returns the path to a phase's output JSON file
func (b *Builder) getPhaseOutputPath(phase Phase) string {
	// Map phase to directory name (matching current output structure)
	dirMap := map[Phase]string{
		PhaseIPRange:   "0-iprange",
		PhaseSubdomain: "1-subdomains",
		PhaseWAF:       "2-waf",
		PhasePorts:     "3-ports",
		PhaseTakeover:  "4-takeover",
		PhaseHistoric:  "5-historic",
		PhaseTech:      "6-tech",
		PhaseDirBrute:  "7-dirbrute",
		PhaseVulnScan:  "8-vulnscan",
		PhaseAIGuided:  "9-aiguided",
	}

	// Map phase to JSON filename
	fileMap := map[Phase]string{
		PhaseIPRange:   "ip_discovery.json",
		PhaseSubdomain: "subdomains.json",
		PhaseWAF:       "waf_detection.json",
		PhasePorts:     "port_scan.json",
		PhaseTakeover:  "takeover.json",
		PhaseHistoric:  "historic_urls.json",
		PhaseTech:      "tech_detection.json",
		PhaseDirBrute:  "dirbrute.json",
		PhaseVulnScan:  "vulnerabilities.json",
		PhaseAIGuided:  "ai_guided.json",
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
		return err
	}
	input.Subdomains = output.Subdomains
	input.AllSubdomains = output.AllSubdomains
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
		AliveHosts []string          `json:"alive_hosts"`
		OpenPorts  map[string][]int  `json:"open_ports"`
		TLSInfo    map[string]string `json:"tls_info"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.AliveHosts = output.AliveHosts
	input.OpenPorts = output.OpenPorts
	input.TLSInfo = output.TLSInfo
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
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	input.TechByHost = output.TechByHost
	input.TechCount = output.TechCount
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
