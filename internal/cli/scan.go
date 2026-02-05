package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/runner"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/spf13/cobra"
)

// Opt-out flags (features are enabled by default)
var (
	noScreenshots  bool
	noGraphQL      bool
	noOSINT        bool
	noAI           bool
	noReport       bool
	noSQLite       bool
	noResume       bool // Disable auto-resume of interrupted scans
	noDNSBrute     bool // Disable DNS bruteforce and permutations
	useLegacy      bool // Use legacy procedural runner instead of pipeline
	enableDirBrute bool // Opt-in: enable directory bruteforce (slow)
)

var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Run reconnaissance on a target domain",
	Long: `Run reconnaissance phases on a target domain or list of domains.

Uses pipeline executor by default for parallel phase execution and better performance.
Interrupted scans are automatically resumed from where they left off (use --no-resume to disable).
Use --parallel-targets N to scan multiple targets concurrently (useful with -l targets.txt).
Most features are enabled by default. Use --no-* flags to disable specific features.
Directory bruteforce is disabled by default (slow). Use --dir-brute to enable it.
Use --quick for a fast scan that also skips full vuln scan.
Use --passive for passive-only reconnaissance (no active probing).
Use --legacy to use the procedural runner instead of the pipeline executor.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	// Target options
	scanCmd.Flags().StringVarP(&cfg.TargetFile, "list", "l", "", "File containing list of domains")
	scanCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "", "Output directory (default: ~/reconator)")

	// Phase selection
	scanCmd.Flags().StringSliceVarP(&cfg.Phases, "phases", "p", []string{"all"}, "Phases to run (iprange,subdomain,waf,ports,vhost,takeover,historic,tech,jsanalysis,trufflehog,secheaders,dirbrute,vulnscan,screenshot,aiguided,all)")
	scanCmd.Flags().BoolVar(&cfg.SkipValidation, "skip-validation", false, "Skip DNS validation")

	// Performance (auto-detected based on system resources, override if needed)
	scanCmd.Flags().IntVarP(&cfg.Threads, "threads", "c", 0, "Concurrent threads (0=auto-detect)")
	scanCmd.Flags().IntVar(&cfg.DNSThreads, "dns-threads", 0, "DNS resolution threads (0=auto-detect)")
	scanCmd.Flags().IntVarP(&cfg.RateLimit, "rate", "r", 0, "Rate limit requests/sec (0=auto-detect)")
	scanCmd.Flags().IntVar(&cfg.MaxConcTargets, "parallel-targets", 0, "Parallel targets to scan (0=auto-detect)")

	// Tool options
	scanCmd.Flags().BoolVar(&cfg.UseOptional, "use-optional", true, "Use optional tools if available")
	scanCmd.Flags().StringVar(&cfg.ResolversFile, "resolvers", "", "Custom resolvers file")
	scanCmd.Flags().StringVar(&cfg.WordlistFile, "wordlist", "", "Custom wordlist for bruteforce")
	scanCmd.Flags().StringVar(&cfg.FaviconHash, "favicon-hash", "", "Favicon hash for favirecon reconnaissance")

	// AI options (Ollama for local AI)
	scanCmd.Flags().StringVar(&cfg.OllamaURL, "ollama-url", "", "Ollama server URL (default: http://localhost:11434)")
	scanCmd.Flags().StringVar(&cfg.OllamaModel, "ollama-model", "", "Ollama model name (e.g., llama3.2, mistral, codellama)")

	// Scan modes
	scanCmd.Flags().BoolVar(&cfg.PassiveMode, "passive", false, "Passive mode: skip active tools (port scan, katana, wappalyzer)")
	scanCmd.Flags().BoolVar(&cfg.QuickMode, "quick", false, "Quick mode: skip slow phases (dir bruteforce, full vuln scan)")
	scanCmd.Flags().BoolVar(&useLegacy, "legacy", false, "Use legacy procedural runner instead of pipeline")

	// Vulnerability scanning options
	scanCmd.Flags().BoolVar(&cfg.DeepScan, "deep", false, "Deep vuln scan: run all nuclei templates (~30 min)")
	scanCmd.Flags().StringVar(&cfg.NucleiTags, "nuclei-tags", "", "Custom nuclei tags (comma-separated, e.g., 'cve,rce,sqli')")
	scanCmd.Flags().IntVar(&cfg.NucleiTimeout, "nuclei-timeout", 0, "Nuclei timeout in minutes (default: 10 fast, 30 deep)")

	// Debug and progress options
	scanCmd.Flags().BoolVar(&cfg.Debug, "debug", false, "Show detailed timing logs for each tool execution")
	scanCmd.Flags().BoolVar(&cfg.VerboseProgress, "verbose", false, "Show step-level progress within phases (Osmedeus-style icons)")

	// Opt-out flags (features enabled by default, use these to disable)
	scanCmd.Flags().BoolVar(&noScreenshots, "no-screenshots", false, "Disable screenshot capture")
	scanCmd.Flags().BoolVar(&noGraphQL, "no-graphql", false, "Disable GraphQL endpoint detection")
	scanCmd.Flags().BoolVar(&noOSINT, "no-osint", false, "Disable OSINT (Google Dorks generation)")
	scanCmd.Flags().BoolVar(&noAI, "no-ai", false, "Disable AI-guided scanning")
	scanCmd.Flags().BoolVar(&noReport, "no-report", false, "Disable HTML report generation")
	scanCmd.Flags().BoolVar(&noSQLite, "no-sqlite", false, "Disable SQLite persistence (files only)")
	scanCmd.Flags().BoolVar(&noResume, "no-resume", false, "Disable auto-resume of interrupted scans")
	scanCmd.Flags().BoolVar(&noDNSBrute, "no-dns-brute", false, "Disable DNS bruteforce and permutations (keeps passive enum + validation)")

	// Opt-in flags (slow/aggressive features disabled by default)
	scanCmd.Flags().BoolVar(&enableDirBrute, "dir-brute", false, "Enable directory bruteforce (slow, disabled by default)")

	// Legacy opt-in flags (kept for backwards compatibility, now default to true)
	scanCmd.Flags().BoolVar(&cfg.EnableScreenshots, "screenshots", true, "Enable screenshot capture (default: true)")
	scanCmd.Flags().BoolVar(&cfg.EnableGraphQL, "graphql", true, "Enable GraphQL endpoint detection (default: true)")
	scanCmd.Flags().BoolVar(&cfg.EnableOSINT, "osint", true, "Enable OSINT (default: true)")
	scanCmd.Flags().BoolVar(&cfg.GenerateReport, "report", true, "Generate HTML report (default: true)")

	// Mark legacy flags as hidden (they still work but --no-* is preferred)
	scanCmd.Flags().MarkHidden("screenshots")
	scanCmd.Flags().MarkHidden("graphql")
	scanCmd.Flags().MarkHidden("osint")
	scanCmd.Flags().MarkHidden("report")
}

func runScan(cmd *cobra.Command, args []string) error {
	printBanner()

	if len(args) > 0 {
		cfg.Target = args[0]
	}

	if cfg.Target == "" && cfg.TargetFile == "" {
		return fmt.Errorf("target domain required: reconator scan <domain> or reconator scan -l <file>")
	}

	// If output directory not specified via -o flag, use default from config
	if cfg.OutputDir == "" {
		defaultCfg := config.DefaultConfig()
		cfg.OutputDir = defaultCfg.OutputDir
	}

	// Apply opt-out flags (these override defaults)
	if noScreenshots {
		cfg.EnableScreenshots = false
	}
	if noGraphQL {
		cfg.EnableGraphQL = false
	}
	if noOSINT {
		cfg.EnableOSINT = false
	}
	if noAI {
		cfg.SkipAIGuided = true
	}
	if noReport {
		cfg.GenerateReport = false
	}
	if noSQLite {
		cfg.EnableSQLite = false
	}
	if noResume {
		cfg.AutoResume = false
	}
	if noDNSBrute {
		cfg.SkipDNSBrute = true
	}

	// DirBrute is opt-in (disabled by default because it's slow)
	// Only enable if --dir-brute flag is explicitly passed
	cfg.SkipDirBrute = !enableDirBrute

	// Quick mode skips slow phases (reinforces dirbrute skip)
	if cfg.QuickMode {
		cfg.SkipDirBrute = true
		cfg.SkipVulnScan = true
	}

	// Passive mode skips generative subdomain methods (DNS brute, permutations)
	// but keeps API-based discovery and DNS validation for faster scans
	if cfg.PassiveMode {
		cfg.SkipDNSBrute = true

		// Warn if user selected active phases with passive mode
		hasActivePhases := false
		for _, phase := range cfg.Phases {
			if phase == "screenshot" || phase == "tech" || phase == "ports" || phase == "all" {
				hasActivePhases = true
				break
			}
		}
		if hasActivePhases || cfg.EnableScreenshots {
			fmt.Println("\n⚠️  Warning: Passive mode enabled with active scanning phases (screenshot/tech/ports)")
			fmt.Println("   These phases will actively interact with target assets during the scan.\n")
		}
	}

	// Load Ollama config from environment if not set via flags
	if cfg.OllamaURL == "" || cfg.OllamaModel == "" {
		envURL, envModel := aiguided.GetOllamaConfigFromEnv()
		if cfg.OllamaURL == "" {
			cfg.OllamaURL = envURL
		}
		if cfg.OllamaModel == "" {
			cfg.OllamaModel = envModel
		}
	}

	// Check if target is a URL (for single-target DAST mode)
	if isURL(cfg.Target) && isSinglePhaseVulnScan(cfg.Phases) {
		return runSingleURLScan(cfg.Target)
	}

	// Use legacy runner if requested, otherwise use pipeline (default)
	if useLegacy {
		r := runner.New(&cfg)
		return r.Run()
	}

	// Pipeline runner is the default (parallel phases, resumable)
	pr := runner.NewPipelineRunner(&cfg)
	return pr.Run()
}

// isURL checks if the target is a full URL (http:// or https://)
func isURL(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

// isSinglePhaseVulnScan checks if only vulnscan phase is requested
func isSinglePhaseVulnScan(phases []string) bool {
	if len(phases) == 1 && phases[0] == "vulnscan" {
		return true
	}
	return false
}

// runSingleURLScan runs vulnerability scanning on a single URL (DAST mode)
func runSingleURLScan(targetURL string) error {
	fmt.Println("\n[*] Single URL DAST Mode")
	fmt.Printf("    Target: %s\n\n", targetURL)

	start := time.Now()

	// Create output directory for results
	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = "./results"
	}
	// Extract hostname for subdirectory
	hostname := strings.TrimPrefix(targetURL, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.Split(hostname, "/")[0]
	hostname = strings.Split(hostname, ":")[0]

	scanDir := filepath.Join(outputDir, hostname)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize tools checker
	checker := tools.NewChecker()

	// Run vulnerability scanner
	fmt.Println("[*] Running vulnerability scanner...")
	scanner := vulnscan.NewScanner(&cfg, checker)
	result, err := scanner.Scan([]string{targetURL}, nil)
	if err != nil {
		fmt.Printf("    Error: %v\n", err)
	}

	// Print results
	if result != nil && len(result.Vulnerabilities) > 0 {
		fmt.Printf("\n[+] Found %d vulnerabilities:\n\n", len(result.Vulnerabilities))
		for _, v := range result.Vulnerabilities {
			fmt.Printf("    [%s] %s\n", strings.ToUpper(v.Severity), v.Name)
			fmt.Printf("        URL: %s\n", v.URL)
			if v.Description != "" {
				fmt.Printf("        Description: %s\n", v.Description)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("\n[*] No vulnerabilities found")
	}

	fmt.Printf("\n[*] Scan completed in %s\n", time.Since(start).Round(time.Second))
	return nil
}
