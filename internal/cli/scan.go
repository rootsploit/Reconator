package cli

import (
	"fmt"

	"github.com/rootsploit/reconator/internal/runner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Run reconnaissance on a target domain",
	Long:  `Run reconnaissance phases on a target domain or list of domains.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&cfg.TargetFile, "list", "l", "", "File containing list of domains")
	scanCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "./results", "Output directory")
	scanCmd.Flags().StringSliceVarP(&cfg.Phases, "phases", "p", []string{"all"}, "Phases to run (subdomain,waf,ports,takeover,historic,tech,all)")
	scanCmd.Flags().BoolVar(&cfg.SkipValidation, "skip-validation", false, "Skip DNS validation")
	scanCmd.Flags().IntVarP(&cfg.Threads, "threads", "c", 50, "Number of concurrent threads")
	scanCmd.Flags().IntVar(&cfg.DNSThreads, "dns-threads", 100, "Threads for DNS resolution")
	scanCmd.Flags().IntVarP(&cfg.RateLimit, "rate", "r", 0, "Rate limit (requests per second)")
	scanCmd.Flags().BoolVar(&cfg.UseOptional, "use-optional", true, "Use optional tools if available")
	scanCmd.Flags().StringVar(&cfg.ResolversFile, "resolvers", "", "Custom resolvers file")
	scanCmd.Flags().StringVar(&cfg.WordlistFile, "wordlist", "", "Custom wordlist for bruteforce")
	scanCmd.Flags().BoolVar(&cfg.PassiveMode, "passive", false, "Passive mode: skip active tools (port scan, katana, wappalyzer)")
	scanCmd.Flags().StringVar(&cfg.FaviconHash, "favicon-hash", "", "Favicon hash for favirecon reconnaissance")
	scanCmd.Flags().BoolVar(&cfg.Debug, "debug", false, "Show detailed timing logs for each tool execution")

	// New features
	scanCmd.Flags().BoolVar(&cfg.EnableScreenshots, "screenshots", false, "Enable screenshot capture (gowitness)")
	scanCmd.Flags().BoolVar(&cfg.EnableGraphQL, "graphql", false, "Enable GraphQL endpoint detection")
	scanCmd.Flags().BoolVar(&cfg.EnableOSINT, "osint", false, "Enable OSINT (Google Dorks generation)")
	scanCmd.Flags().BoolVar(&cfg.GenerateReport, "report", true, "Generate HTML report")
}

func runScan(cmd *cobra.Command, args []string) error {
	printBanner()

	if len(args) > 0 {
		cfg.Target = args[0]
	}

	if cfg.Target == "" && cfg.TargetFile == "" {
		return fmt.Errorf("target domain required: reconator scan <domain> or reconator scan -l <file>")
	}

	r := runner.New(&cfg)
	return r.Run()
}
