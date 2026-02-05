package config

import (
	"os"
	"path/filepath"
)

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
	Threads        int
	DNSThreads     int    // Separate threads for DNS operations (puredns, dnsx)
	RateLimit      int
	MaxConcTargets int    // Max concurrent targets to scan in parallel (default: 1)
	Profile        string // Performance profile: auto, low, medium, high (default: auto)

	// Passive mode - no active scanning
	PassiveMode bool // Only passive recon: no port scanning, no katana crawling, no wappalyzer

	// Quick mode - fast scan skipping slow phases
	QuickMode bool // Skip dir bruteforce and full vuln scanning for faster results

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

	// Ollama (local AI) configuration
	OllamaURL   string // Ollama server URL (default: http://localhost:11434)
	OllamaModel string // Ollama model name (e.g., llama3.2, mistral, codellama)

	// Alerting
	NotifyConfigPath string // Path to notify provider config
	EnableNotify     bool   // Enable notifications

	// Phase-specific options
	SkipDirBrute bool // Skip directory bruteforce
	SkipVulnScan bool // Skip vulnerability scanning
	SkipAIGuided bool // Skip AI-guided scanning
	SkipDNSBrute bool // Skip DNS bruteforce and permutations (keeps passive enum + validation)

	// Vulnerability scanning options
	DeepScan       bool   // Run comprehensive nuclei scan (all templates, ~30 min)
	NucleiTags     string // Custom nuclei tags (comma-separated)
	NucleiTimeout  int    // Nuclei timeout in minutes (default: 10 for fast, 30 for deep)

	// Debug
	Debug bool // Show detailed timing logs for each tool execution

	// Verbose progress - show step-level progress within phases (Osmedeus-style)
	VerboseProgress bool // Show ✓/⏹/✗ icons for each tool within a phase

	// Timeouts
	ScanTimeout  int // Global scan timeout in minutes (default: 0 = no limit)
	PhaseTimeout int // Per-phase timeout in minutes (default: 30)
	VHostTimeout int // VHost phase timeout in minutes (default: 10)

	// Storage
	EnableSQLite bool // Enable SQLite persistence for dashboard queries (default: true)

	// Resume functionality
	Resume     bool // Resume an interrupted scan if one exists
	AutoResume bool // Automatically resume without prompting (default: true)

	// Features (default ON - use --no-* flags to disable)
	EnableScreenshots bool // Capture screenshots using gowitness (default: true)
	EnableGraphQL     bool // Detect GraphQL endpoints (default: true)
	EnableOSINT       bool // Run OSINT module (Google Dorks) (default: true)
	GenerateReport    bool // Generate HTML report (default: true)
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	// Default results directory: ~/reconator (binary is at ~/go/bin/reconator, no conflict)
	homeDir, err := os.UserHomeDir()
	outputDir := filepath.Join(homeDir, "reconator") // Default: ~/reconator
	if err != nil {
		// Fallback if home directory cannot be determined
		outputDir = "./reconator"
	}

	return &Config{
		OutputDir:         outputDir,
		Phases:            []string{"all"},
		Profile:           "auto", // Auto-detect system resources
		Threads:           0,      // 0 = auto-detect based on profile
		DNSThreads:        0,      // 0 = auto-detect based on profile
		MaxConcTargets:    0,      // 0 = auto-detect based on profile
		UseOptional:       true,
		ScanTimeout:       0,      // 0 = no global limit
		PhaseTimeout:      30,     // 30 minutes per phase max
		VHostTimeout:      10,     // 10 minutes for VHost (tends to hang)
		EnableSQLite:      true,   // Default ON - enables dashboard queries
		AutoResume:        true,   // Default ON - auto-resume interrupted scans
		EnableScreenshots: true,   // Default ON
		EnableGraphQL:     true,   // Default ON
		EnableOSINT:       true,   // Default ON
		GenerateReport:    true,   // Default ON
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
