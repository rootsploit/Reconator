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

	// Stealth options
	StealthMode bool // Skip DNS bruteforce, permutations, scan only direct hosts

	// Speed options
	FastMode bool // Skip alterx, limit permutations for faster scans

	// Tool options
	UseOptional   bool
	ResolversFile string
	WordlistFile  string
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

