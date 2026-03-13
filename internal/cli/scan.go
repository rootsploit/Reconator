package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/apikeys"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/distscan"
	"github.com/rootsploit/reconator/internal/iprotate"
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
Use --legacy to use the procedural runner instead of the pipeline executor.

Distributed scanning (like axiom):
  reconator scan example.com --distributed --provider=aws --spot
  reconator scan -l targets.txt --distributed --provider=digitalocean --api-key=$DO_TOKEN

  Auto-provisions cloud workers, installs tools, distributes targets,
  consolidates results, and tears down infrastructure when done.`,
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
	scanCmd.Flags().BoolVar(&cfg.QuickMode, "quick", false, "Quick mode: skip slow phases (dir bruteforce, full vuln scan, DNS validation)")
	scanCmd.Flags().BoolVar(&cfg.SubsOnly, "subs-only", false, "Subdomains only mode: run subdomain phase only and output just the list")
	scanCmd.Flags().BoolVar(&useLegacy, "legacy", false, "Use legacy procedural runner instead of pipeline")

	// Vulnerability scanning options
	scanCmd.Flags().BoolVar(&cfg.DeepScan, "deep", false, "Deep vuln scan: run all nuclei templates (~30 min)")
	scanCmd.Flags().StringVar(&cfg.NucleiTags, "nuclei-tags", "", "Custom nuclei tags (comma-separated, e.g., 'cve,rce,sqli')")
	scanCmd.Flags().IntVar(&cfg.NucleiTimeout, "nuclei-timeout", 0, "Nuclei timeout in minutes (default: 10 fast, 30 deep)")

	// Port scanning options
	scanCmd.Flags().StringVar(&cfg.PortScanMode, "port-scan-mode", "connect", "Port scan mode: 'connect' (default, -sT) or 'syn' (-sS, faster but requires root)")

	// Debug and progress options
	scanCmd.Flags().BoolVar(&cfg.Debug, "debug", false, "Show detailed timing logs for each tool execution")
	scanCmd.Flags().BoolVar(&cfg.VerboseProgress, "verbose", false, "Show step-level progress within phases (Osmedeus-style icons)")
	scanCmd.Flags().BoolVar(&cfg.Silent, "silent", false, "Silent mode: suppress banner and progress output")

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

	// Distributed scanning flags (one-command cloud scanning, like axiom)
	scanCmd.Flags().BoolVar(&cfg.DistributedScan, "distributed", false, "Distribute scan across cloud workers (auto-provision, scan, consolidate, teardown)")
	scanCmd.Flags().StringVar(&cfg.DistProvider, "provider", "", "Cloud provider: aws, digitalocean (default: digitalocean)")
	scanCmd.Flags().IntVarP(&cfg.DistWorkers, "workers", "w", 3, "Number of cloud instances to provision (default: 3)")
	scanCmd.Flags().BoolVar(&cfg.DistSpot, "spot", false, "Use spot/preemptible instances (AWS)")
	scanCmd.Flags().StringVar(&cfg.DistRegion, "region", "", "Cloud region for workers (default: provider-specific)")
	scanCmd.Flags().StringVar(&cfg.DistSize, "size", "", "Instance size (e.g., t3.micro, s-1vcpu-1gb)")
	scanCmd.Flags().StringVar(&cfg.DistAPIKey, "api-key", "", "Cloud provider API key (or use DO_TOKEN/AWS env vars)")
	scanCmd.Flags().StringVar(&cfg.DistSSHKey, "ssh-key", "", "SSH private key path for connecting to workers")
	scanCmd.Flags().StringVar(&cfg.DistSSHKeyID, "ssh-key-id", "", "Pre-uploaded SSH key ID in cloud provider")
	scanCmd.Flags().StringVar(&cfg.DistSetupCmd, "setup-cmd", "", "Custom setup command for workers")

	// IP rotation flags (transparent per-request IP rotation via AWS API Gateway)
	scanCmd.Flags().BoolVar(&cfg.IPRotateEnabled, "iprotate", false, "Enable IP rotation via AWS API Gateway (each request gets a new IP)")
	scanCmd.Flags().StringVar(&cfg.IPRotateRegions, "iprotate-regions", "", "Comma-separated AWS regions for IP rotation (default: 10 diverse regions)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Print banner unless silent mode
	if !cfg.Silent {
		printBanner()
	}

	// Handle subs-only mode: run subdomain phase only
	if cfg.SubsOnly {
		cfg.Phases = []string{"subdomain"}
		cfg.SkipValidation = true  // Skip validation for speed
		cfg.SkipDNSBrute = true    // Skip DNS bruteforce and permutations for speed
		cfg.PassiveMode = true    // Ensure passive mode
		cfg.GenerateReport = false
		cfg.EnableSQLite = false
		cfg.SkipAIGuided = true
		cfg.EnableNotify = false
	}

	// If quick mode is also enabled with subs-only, ensure maximum speed
	if cfg.SubsOnly && cfg.QuickMode {
		cfg.SkipDNSBrute = true
		cfg.SkipValidation = true
	}

	if len(args) > 0 {
		cfg.Target = args[0]
	}

	if cfg.Target == "" && cfg.TargetFile == "" {
		return fmt.Errorf("target domain required: reconator scan <domain> or reconator scan -l <file>")
	}

	// --iprotate and --distributed are mutually exclusive
	if cfg.IPRotateEnabled && cfg.DistributedScan {
		return fmt.Errorf("--iprotate and --distributed cannot be used together\n" +
			"  --iprotate: rotates IPs from a single machine via AWS API Gateway\n" +
			"  --distributed: scans from multiple cloud instances (each already has a unique IP)")
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
		cfg.SkipValidation = true       // Quick mode skips DNS validation for speed
		cfg.SkipDNSBrute = true        // Quick mode skips DNS bruteforce and permutations for speed
	}

	// Passive mode skips generative subdomain methods (DNS brute, permutations)
	// but keeps API-based discovery and DNS validation for faster scans
	if cfg.PassiveMode {
		cfg.SkipDNSBrute = true

		// Warn if user selected active phases with passive mode (skip in silent mode)
		hasActivePhases := false
		for _, phase := range cfg.Phases {
			if phase == "screenshot" || phase == "tech" || phase == "ports" || phase == "all" {
				hasActivePhases = true
				break
			}
		}
		if (hasActivePhases || cfg.EnableScreenshots) && !cfg.Silent {
			fmt.Println("\n⚠️  Warning: Passive mode enabled with active scanning phases (screenshot/tech/ports)")
			fmt.Println("   These phases will actively interact with target assets during the scan.")
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

	// IP rotation: deploy AWS API Gateways, start local proxy, set HTTP_PROXY
	var rotator *iprotate.IPRotator
	if cfg.IPRotateEnabled {
		// Load config defaults
		iprCfgMgr := apikeys.NewManager()
		if err := iprCfgMgr.Load(); err == nil {
			iprDefaults := iprCfgMgr.GetConfig().IPRotate
			if !cmd.Flags().Changed("iprotate-regions") && len(iprDefaults.Regions) > 0 {
				cfg.IPRotateRegions = strings.Join(iprDefaults.Regions, ",")
			}
		}

		iprCfg := iprotate.DefaultIPRotateConfig()
		iprCfg.Enabled = true
		if cfg.IPRotateRegions != "" {
			iprCfg.Regions = splitAndTrim(cfg.IPRotateRegions)
		}

		// Construct target URL from scan target
		targetURL := "https://" + cfg.Target
		if isURL(cfg.Target) {
			targetURL = cfg.Target
		}

		yellow := color.New(color.FgYellow)
		yellow.Println("\n  [iprotate] Deploying AWS API Gateways for IP rotation...")
		fmt.Printf("    Target: %s, Regions: %d\n", targetURL, len(iprCfg.Regions))
		fmt.Println("    Press Ctrl+C within 5 seconds to cancel...")
		select {
		case <-time.After(5 * time.Second):
		default:
		}

		rotator = iprotate.New(iprCfg)
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		if err := rotator.Start(ctx, targetURL); err != nil {
			return fmt.Errorf("start IP rotation: %w", err)
		}
		defer func() {
			color.New(color.FgCyan).Println("\n[iprotate] Tearing down API Gateways...")
			if err := rotator.Stop(context.Background()); err != nil {
				color.New(color.FgYellow).Printf("[iprotate] Cleanup warning: %v\n", err)
			} else {
				color.New(color.FgGreen).Println("[iprotate] All gateways destroyed. Clean shutdown.")
			}
		}()

		// Set HTTP_PROXY so all child tools use the rotating proxy
		proxyURL := rotator.ProxyURL()
		os.Setenv("HTTP_PROXY", proxyURL)
		os.Setenv("HTTPS_PROXY", proxyURL)
		color.New(color.FgGreen).Printf("[iprotate] Proxy active: %s (%d gateways)\n", proxyURL, rotator.GatewayCount())
		color.New(color.FgGreen).Printf("[iprotate] HTTP_PROXY=%s set for all tools\n\n", proxyURL)
	}

	// Distributed scan: provision cloud workers, run scan, consolidate, teardown
	if cfg.DistributedScan {
		// Load config defaults for distributed scanning
		distCfgMgr := apikeys.NewManager()
		if err := distCfgMgr.Load(); err == nil {
			distDefaults := distCfgMgr.GetConfig().Fleet
			if !cmd.Flags().Changed("provider") && distDefaults.Provider != "" {
				cfg.DistProvider = distDefaults.Provider
			}
			if !cmd.Flags().Changed("workers") && distDefaults.Workers > 0 {
				cfg.DistWorkers = distDefaults.Workers
			}
			if !cmd.Flags().Changed("api-key") && distDefaults.APIKey != "" {
				cfg.DistAPIKey = distDefaults.APIKey
			}
			if !cmd.Flags().Changed("region") && distDefaults.Region != "" {
				cfg.DistRegion = distDefaults.Region
			}
			if !cmd.Flags().Changed("size") && distDefaults.Size != "" {
				cfg.DistSize = distDefaults.Size
			}
			if !cmd.Flags().Changed("ssh-key") && distDefaults.SSHKeyFile != "" {
				cfg.DistSSHKey = distDefaults.SSHKeyFile
			}
			if !cmd.Flags().Changed("ssh-key-id") && distDefaults.SSHKeyID != "" {
				cfg.DistSSHKeyID = distDefaults.SSHKeyID
			}
			if !cmd.Flags().Changed("spot") && distDefaults.SpotEnabled {
				cfg.DistSpot = distDefaults.SpotEnabled
			}
			if !cmd.Flags().Changed("setup-cmd") && distDefaults.SetupCmd != "" {
				cfg.DistSetupCmd = distDefaults.SetupCmd
			}
		}

		dr := distscan.New(&cfg)
		return dr.Run()
	}

	// Use legacy runner if requested, otherwise use pipeline (default)
	if useLegacy {
		r := runner.New(&cfg)
		return r.Run()
	}

	// Pipeline runner is the default (parallel phases, resumable)
	pr := runner.NewPipelineRunner(&cfg)
	err := pr.Run()

	// If subs-only mode, read and output subdomains
	if cfg.SubsOnly && err == nil {
		outputSubdomains(&cfg)
	}

	return err
}

// outputSubdomains reads the subdomain file and outputs each subdomain
func outputSubdomains(cfg *config.Config) error {
	// Find the subdomain output file
	outputDir := cfg.OutputDir
	if outputDir == "" {
		defaultCfg := config.DefaultConfig()
		outputDir = defaultCfg.OutputDir
	}

	target := cfg.Target

	// Find the latest scan directory for this target
	// The pipeline creates directories like: scanID_target
	subdomainsFile := ""
	entries, err := os.ReadDir(outputDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasSuffix(entry.Name(), "_"+target) {
				subdomainsFile = filepath.Join(outputDir, entry.Name(), "1-subdomains", "subdomains.txt")
				if _, err := os.Stat(subdomainsFile); err == nil {
					break
				}
			}
		}
	}

	if subdomainsFile == "" {
		// Fallback to direct path
		subdomainsFile = filepath.Join(outputDir, target, "1-subdomains", "subdomains.txt")
	}

	data, err := os.ReadFile(subdomainsFile)
	if err != nil {
		// Silently skip if no subdomains found
		return nil
	}

	// Print each subdomain
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			fmt.Println(line)
		}
	}

	return nil
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
