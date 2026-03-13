package output

import (
	"encoding/json"
	"time"
)

// UnifiedScanResult is the complete scan result in a single JSON document
type UnifiedScanResult struct {
	Meta            ScanMeta            `json:"meta"`
	Target          string              `json:"target"`
	Subdomains      []string            `json:"subdomains,omitempty"`
	AliveHosts      []string            `json:"alive_hosts,omitempty"`
	Ports           map[string][]int    `json:"ports,omitempty"`
	Technologies    map[string][]string `json:"technologies,omitempty"`
	Vulnerabilities []interface{}       `json:"vulnerabilities,omitempty"`
	AttackPaths     []interface{}       `json:"attack_paths,omitempty"`
	OSINT           interface{}         `json:"osint,omitempty"`
	AIAnalysis      interface{}         `json:"ai_analysis,omitempty"`
	Screenshots     interface{}         `json:"screenshots,omitempty"`
	SecHeaders      interface{}         `json:"security_headers,omitempty"`
	JSAnalysis      interface{}         `json:"js_analysis,omitempty"`
}

// ScanMeta contains metadata about the scan
type ScanMeta struct {
	Version   string   `json:"version"`
	ScanID    string   `json:"scan_id"`
	StartTime string   `json:"start_time"`
	EndTime   string   `json:"end_time"`
	Duration  float64  `json:"duration_sec"`
	Phases    []string `json:"phases_run"`
	Target    string   `json:"target"`
}

// UnifiedResultBuilder accumulates phase results and builds the final JSON
type UnifiedResultBuilder struct {
	result    *UnifiedScanResult
	startTime time.Time
}

// NewUnifiedResultBuilder creates a new builder
func NewUnifiedResultBuilder(target, version, scanID string) *UnifiedResultBuilder {
	now := time.Now().UTC()
	return &UnifiedResultBuilder{
		startTime: now,
		result: &UnifiedScanResult{
			Meta: ScanMeta{
				Version:   version,
				ScanID:    scanID,
				StartTime: now.Format(time.RFC3339),
				Target:    target,
			},
			Target:       target,
			Ports:        make(map[string][]int),
			Technologies: make(map[string][]string),
		},
	}
}

// SetSubdomains sets the subdomain results
func (b *UnifiedResultBuilder) SetSubdomains(subs []string) {
	b.result.Subdomains = subs
}

// SetAliveHosts sets the alive hosts
func (b *UnifiedResultBuilder) SetAliveHosts(hosts []string) {
	b.result.AliveHosts = hosts
}

// SetPorts sets the port scan results
func (b *UnifiedResultBuilder) SetPorts(ports map[string][]int) {
	b.result.Ports = ports
}

// SetTechnologies sets the technology detection results
func (b *UnifiedResultBuilder) SetTechnologies(tech map[string][]string) {
	b.result.Technologies = tech
}

// SetVulnerabilities sets the vulnerability scan results
func (b *UnifiedResultBuilder) SetVulnerabilities(vulns []interface{}) {
	b.result.Vulnerabilities = vulns
}

// SetAttackPaths sets the attack path analysis results
func (b *UnifiedResultBuilder) SetAttackPaths(paths []interface{}) {
	b.result.AttackPaths = paths
}

// SetOSINT sets the OSINT results
func (b *UnifiedResultBuilder) SetOSINT(osint interface{}) {
	b.result.OSINT = osint
}

// SetAIAnalysis sets the AI analysis results
func (b *UnifiedResultBuilder) SetAIAnalysis(ai interface{}) {
	b.result.AIAnalysis = ai
}

// SetScreenshots sets screenshot results
func (b *UnifiedResultBuilder) SetScreenshots(ss interface{}) {
	b.result.Screenshots = ss
}

// SetSecHeaders sets security header results
func (b *UnifiedResultBuilder) SetSecHeaders(sh interface{}) {
	b.result.SecHeaders = sh
}

// SetJSAnalysis sets JS analysis results
func (b *UnifiedResultBuilder) SetJSAnalysis(js interface{}) {
	b.result.JSAnalysis = js
}

// AddPhase records that a phase was run
func (b *UnifiedResultBuilder) AddPhase(phase string) {
	b.result.Meta.Phases = append(b.result.Meta.Phases, phase)
}

// Build finalizes and returns the result as JSON bytes
func (b *UnifiedResultBuilder) Build() ([]byte, error) {
	now := time.Now().UTC()
	b.result.Meta.EndTime = now.Format(time.RFC3339)
	b.result.Meta.Duration = now.Sub(b.startTime).Seconds()

	return json.MarshalIndent(b.result, "", "  ")
}

// BuildCompact returns compact JSON (no indentation)
func (b *UnifiedResultBuilder) BuildCompact() ([]byte, error) {
	now := time.Now().UTC()
	b.result.Meta.EndTime = now.Format(time.RFC3339)
	b.result.Meta.Duration = now.Sub(b.startTime).Seconds()

	return json.Marshal(b.result)
}
