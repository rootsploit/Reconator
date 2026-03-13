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
	DNSThreads     int // Separate threads for DNS operations (puredns, dnsx)
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
	DeepScan      bool   // Run comprehensive nuclei scan (all templates, ~30 min)
	NucleiTags    string // Custom nuclei tags (comma-separated)
	NucleiTimeout int    // Nuclei timeout in minutes (default: 10 for fast, 30 for deep)

	// Port scanning options
	PortScanMode string // Port scan mode: "connect" (default, -sT) or "syn" (-sS) for faster scanning

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

	// JSON output modes (for LLM agent consumption)
	JSONOutput    bool   // Output unified JSON result to stdout after scan
	JSONLOutput   bool   // Stream JSONL events to stdout during scan
	JSONProgress  bool   // Output structured JSON with progress updates (for AI agents)
	ProgressFile  string // Write progress to specified JSON file
	WatchMode     bool   // Watch output directory for incremental results
	Silent       bool   // Silent mode: suppress banner and progress output
	SubsOnly     bool   // Subdomains only mode: run subdomain phase only and output just the list

	// MCP Server mode (for AI agent integration)
	MCPMode bool // Run as MCP server (stdin/stdout JSON)

	// IP rotation (--iprotate flag on scan command)
	IPRotateEnabled bool   // Enable IP rotation via AWS API Gateway
	IPRotateRegions string // Comma-separated AWS regions for IP rotation

	// Distributed scanning (--distributed flag on scan command)
	DistributedScan bool   // Enable distributed scanning
	DistProvider    string // Cloud provider: "aws", "digitalocean"
	DistWorkers     int    // Number of cloud workers to provision
	DistSpot        bool   // Use spot/preemptible instances (AWS)
	DistRegion      string // Cloud region for provisioning
	DistSize        string // Instance size
	DistAPIKey      string // Cloud provider API key
	DistSSHKey      string // SSH private key path for connecting to workers
	DistSSHKeyID    string // Pre-uploaded SSH key ID in cloud provider
	DistSetupCmd    string // Custom setup command for workers
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
		PortScanMode:      "connect", // Default to CONNECT mode (more reliable, works everywhere)
		UseOptional:       true,
		ScanTimeout:       0,     // 0 = no global limit
		PhaseTimeout:      30,    // 30 minutes per phase max
		VHostTimeout:      10,    // 10 minutes for VHost (tends to hang)
		EnableSQLite:      true,  // Default ON - enables dashboard queries
		AutoResume:        true,  // Default ON - auto-resume interrupted scans
		EnableScreenshots: true,  // Default ON
		EnableGraphQL:     true,  // Default ON
		EnableOSINT:       true,  // Default ON
		GenerateReport:    true,  // Default ON
		JSONOutput:        false, // Default OFF
		JSONLOutput:       false, // Default OFF
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
