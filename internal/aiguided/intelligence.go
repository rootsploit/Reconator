package aiguided

import (
	"encoding/json"
	"time"
)

// AIDecisions carries AI checkpoint outputs forward through the pipeline.
// Populated by Checkpoint 1 and Checkpoint 2, consumed by downstream phases.
// When no AI keys are configured, this remains nil and phases use defaults.
type AIDecisions struct {
	// From Checkpoint 1 (after subdomain + historic + JS analysis)
	PrioritizedHosts []HostPriority `json:"prioritized_hosts,omitempty"`
	AdaptiveWordlist []string       `json:"adaptive_wordlist,omitempty"` // Tech-specific paths for dirbrute
	SkipPhases       []string       `json:"skip_phases,omitempty"`       // Phases AI recommends skipping

	// From Checkpoint 2 (after ports + WAF + tech detection)
	NucleiTags       []string          `json:"nuclei_tags,omitempty"`        // AI-selected nuclei tags
	HostScanStrategy map[string]string `json:"host_scan_strategy,omitempty"` // host -> "full"|"light"|"skip"
	CustomDirWords   []string          `json:"custom_dir_words,omitempty"`   // Additional dirbrute words

	// From vulnerability validation (post-vulnscan)
	ValidatedVulns []ValidatedVuln `json:"validated_vulns,omitempty"`

	// Metadata
	Checkpoints []CheckpointMeta `json:"checkpoints"`
}

// HostPriority represents a host with AI-assigned priority
type HostPriority struct {
	Host     string `json:"host"`
	Priority int    `json:"priority"` // 1=highest, 5=lowest
	Reason   string `json:"reason,omitempty"`
}

// ValidatedVuln represents an AI-validated vulnerability
type ValidatedVuln struct {
	Host         string  `json:"host"`
	VulnName     string  `json:"vuln_name"`
	TemplateID   string  `json:"template_id"`
	OrigSeverity string  `json:"orig_severity"`
	IsReal       bool    `json:"is_real"`
	Confidence   float64 `json:"confidence"`    // 0.0-1.0
	AdjustedRisk string  `json:"adjusted_risk"` // critical/high/medium/low/info/false-positive
	Reasoning    string  `json:"reasoning"`
}

// CheckpointMeta records metadata about an AI checkpoint execution
type CheckpointMeta struct {
	Name         string        `json:"name"`
	Provider     string        `json:"provider"`
	Duration     time.Duration `json:"duration"`
	TokensUsed   int           `json:"tokens_used,omitempty"`
	UsedFallback bool          `json:"used_fallback"`
	Error        string        `json:"error,omitempty"`
}

// AttackPath represents an AI-generated exploitation path
type AttackPath struct {
	Name           string       `json:"name"`
	RiskLevel      string       `json:"risk_level"`  // critical/high/medium/low
	Probability    float64      `json:"probability"` // 0.0-1.0
	EntryPoint     string       `json:"entry_point"`
	Steps          []AttackStep `json:"steps"`
	Mitigations    []string     `json:"mitigations"`
	AffectedAssets []string     `json:"affected_assets,omitempty"`
}

// AttackStep represents a single step in an attack path
type AttackStep struct {
	Order       int    `json:"order"`
	Description string `json:"description"`
	Technique   string `json:"technique,omitempty"` // MITRE ATT&CK ID
	Target      string `json:"target,omitempty"`
}

// Merge combines two AIDecisions (e.g., checkpoint 1 + checkpoint 2)
func (d *AIDecisions) Merge(other *AIDecisions) {
	if other == nil {
		return
	}
	if len(other.PrioritizedHosts) > 0 {
		d.PrioritizedHosts = other.PrioritizedHosts
	}
	if len(other.AdaptiveWordlist) > 0 {
		d.AdaptiveWordlist = append(d.AdaptiveWordlist, other.AdaptiveWordlist...)
	}
	if len(other.SkipPhases) > 0 {
		d.SkipPhases = other.SkipPhases
	}
	if len(other.NucleiTags) > 0 {
		d.NucleiTags = other.NucleiTags
	}
	if other.HostScanStrategy != nil {
		if d.HostScanStrategy == nil {
			d.HostScanStrategy = make(map[string]string)
		}
		for k, v := range other.HostScanStrategy {
			d.HostScanStrategy[k] = v
		}
	}
	if len(other.CustomDirWords) > 0 {
		d.CustomDirWords = append(d.CustomDirWords, other.CustomDirWords...)
	}
	if len(other.ValidatedVulns) > 0 {
		d.ValidatedVulns = other.ValidatedVulns
	}
	d.Checkpoints = append(d.Checkpoints, other.Checkpoints...)
}

// ToJSON serializes AIDecisions to JSON
func (d *AIDecisions) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// FromJSON deserializes AIDecisions from JSON
func FromJSON(data []byte) (*AIDecisions, error) {
	var d AIDecisions
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// HasAdaptiveWordlist returns true if AI generated adaptive wordlist entries
func (d *AIDecisions) HasAdaptiveWordlist() bool {
	return len(d.AdaptiveWordlist) > 0 || len(d.CustomDirWords) > 0
}

// GetAllWordlistEntries returns combined adaptive wordlist + custom dir words
func (d *AIDecisions) GetAllWordlistEntries() []string {
	seen := make(map[string]bool)
	var result []string
	for _, w := range d.AdaptiveWordlist {
		if !seen[w] {
			seen[w] = true
			result = append(result, w)
		}
	}
	for _, w := range d.CustomDirWords {
		if !seen[w] {
			seen[w] = true
			result = append(result, w)
		}
	}
	return result
}

// HasNucleiTags returns true if AI selected specific nuclei tags
func (d *AIDecisions) HasNucleiTags() bool {
	return len(d.NucleiTags) > 0
}

// ShouldSkipPhase returns true if AI recommends skipping a phase
func (d *AIDecisions) ShouldSkipPhase(phase string) bool {
	for _, p := range d.SkipPhases {
		if p == phase {
			return true
		}
	}
	return false
}

// GetHostStrategy returns the scan strategy for a host ("full", "light", "skip")
func (d *AIDecisions) GetHostStrategy(host string) string {
	if d.HostScanStrategy == nil {
		return "full"
	}
	strategy, ok := d.HostScanStrategy[host]
	if !ok {
		return "full"
	}
	return strategy
}
