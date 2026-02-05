package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/apikeys"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/runner"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/spf13/cobra"
)

var (
	cfg     = *config.DefaultConfig()
	rootCmd = &cobra.Command{
		Use:   "reconator",
		Short: "AI-powered reconnaissance framework",
		Long: `Reconator - AI-powered reconnaissance framework for bug bounty and security testing.

Features: Subdomain enum • Port scanning • Vulnerability detection • AI analysis • Web dashboard

Install: go install github.com/rootsploit/reconator@latest`,
		RunE: runRecon,
	}
)

func init() {
	// Target flags
	rootCmd.Flags().StringVarP(&cfg.Target, "target", "t", "", "Target domain to scan")
	rootCmd.Flags().StringVarP(&cfg.TargetFile, "list", "l", "", "File containing list of domains")

	// Output flags
	rootCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "", "Output directory (default: ~/reconator)")

	// Phase selection
	rootCmd.Flags().StringSliceVarP(&cfg.Phases, "phases", "p", []string{"all"}, "Phases to run (iprange,subdomain,waf,ports,vhost,takeover,historic,tech,jsanalysis,secheaders,dirbrute,vulnscan,screenshot,aiguided,all)")
	rootCmd.Flags().BoolVar(&cfg.SkipValidation, "skip-validation", false, "Skip DNS validation")

	// Performance flags
	rootCmd.Flags().IntVarP(&cfg.Threads, "threads", "c", 50, "Number of concurrent threads")
	rootCmd.Flags().IntVar(&cfg.DNSThreads, "dns-threads", 100, "Threads for DNS resolution (puredns, dnsx)")
	rootCmd.Flags().IntVarP(&cfg.RateLimit, "rate", "r", 0, "Rate limit (requests per second, 0 = unlimited)")

	// Mode flags
	rootCmd.Flags().BoolVar(&cfg.PassiveMode, "passive", false, "Passive mode: skip active tools (port scan, katana, wappalyzer)")

	// Tool flags
	rootCmd.Flags().BoolVar(&cfg.UseOptional, "use-optional", true, "Use optional non-Go tools if available")
	rootCmd.Flags().StringVar(&cfg.ResolversFile, "resolvers", "", "Custom resolvers file for DNS validation")
	rootCmd.Flags().StringVar(&cfg.WordlistFile, "wordlist", "", "Custom wordlist for bruteforce")

	// Debug flag
	rootCmd.Flags().BoolVar(&cfg.Debug, "debug", false, "Show detailed timing logs for each tool execution")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(webscanCmd)
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
}

func Execute() error {
	// Ensure config files exist (creates templates if missing)
	aiguided.EnsureConfigExists()
	apikeys.EnsureConfigExists()
	return rootCmd.Execute()
}

func runRecon(cmd *cobra.Command, args []string) error {
	// Print banner
	printBanner()

	// Validate input
	if cfg.Target == "" && cfg.TargetFile == "" {
		return fmt.Errorf("either --target or --list is required")
	}

	// Run reconnaissance
	r := runner.New(&cfg)
	return r.Run()
}

func printBanner() {
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	white := color.New(color.FgWhite, color.Bold)
	gray := color.New(color.FgHiBlack)

	red.Print(`
    ____                             __
   / __ \___  _________  ____  ___ _/ /_____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ _ '/ __/ __ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / /_/ / /_/ /_/ / /
/_/ |_|\___/\___/\____/_/ /_/\__,_/\__/\____/_/
`)
	fmt.Println()
	cyan.Print("  AI-Powered Reconnaissance Framework")
	gray.Printf("  v%s\n", version.Version)
	fmt.Println()
	yellow.Print("  [*] ")
	white.Println("Secret Detection | Cloud Storage | CVE Intelligence")
	yellow.Print("  [*] ")
	white.Println("Token Validation | Admin Panels | AI Analysis")
	fmt.Println()
	gray.Println("  github.com/rootsploit/reconator | @RootSploit")
	fmt.Println()
}
