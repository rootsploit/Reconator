package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/runner"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/spf13/cobra"
)

var (
	cfg     = *config.DefaultConfig()
	rootCmd = &cobra.Command{
		Use:   "reconator",
		Short: "Reconator - Fast subdomain reconnaissance tool",
		Long: `Reconator is a high-performance reconnaissance tool for bug bounty hunters.
It combines multiple tools for subdomain enumeration, WAF detection, port scanning,
and vulnerability discovery.

Built with Go for easy installation: go install github.com/rootsploit/reconator@latest`,
		RunE: runRecon,
	}
)

func init() {
	// Target flags
	rootCmd.Flags().StringVarP(&cfg.Target, "target", "t", "", "Target domain to scan")
	rootCmd.Flags().StringVarP(&cfg.TargetFile, "list", "l", "", "File containing list of domains")

	// Output flags
	rootCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "./results", "Output directory")

	// Phase selection
	rootCmd.Flags().StringSliceVarP(&cfg.Phases, "phases", "p", []string{"all"}, "Phases to run (subdomain,waf,ports,takeover,historic,tech,all)")
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
}

func Execute() error {
	// Ensure AI config file exists (creates template if missing)
	aiguided.EnsureConfigExists()
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
