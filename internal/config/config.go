package config

// Config holds all configuration options for reconator
type Config struct {
	// Target configuration
	Target     string
	TargetFile string

	// Output configuration
	OutputDir string

	// Phase selection
	Phases         []string
	SkipValidation bool

	// Performance
	Threads    int
	DNSThreads int // Separate threads for DNS operations (puredns, dnsx)
	RateLimit  int

	// Passive mode - no active scanning
	PassiveMode bool // Only passive recon: no port scanning, no katana crawling, no wappalyzer

	// Favicon hash for favirecon
	FaviconHash string

	// Tool options
	UseOptional   bool
	ResolversFile string
	WordlistFile  string

	// AI API keys (for AI-guided nuclei template selection)
	OpenAIKey string
	ClaudeKey string
	GeminiKey string

	// Alerting
	NotifyConfigPath string // Path to notify provider config
	EnableNotify     bool   // Enable notifications

	// Phase-specific options
	SkipDirBrute   bool // Skip directory bruteforce
	SkipVulnScan   bool // Skip vulnerability scanning
	SkipAIGuided   bool // Skip AI-guided scanning

	// Debug
	Debug bool // Show detailed timing logs for each tool execution
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		OutputDir:   "./results",
		Phases:      []string{"all"},
		Threads:     50,
		DNSThreads:  100,
		UseOptional: true,
	}
}

// ShouldRunPhase checks if a specific phase should be run
func (c *Config) ShouldRunPhase(phase string) bool {
	for _, p := range c.Phases {
		if p == "all" || p == phase {
			return true
		}
	}
	return false
}

