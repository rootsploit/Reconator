package cli

import (
	"context"
	"fmt"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/apikeys"
	"github.com/rootsploit/reconator/internal/iprotate"
	"github.com/spf13/cobra"
)

var (
	iprotateTarget  string
	iprotatePort    int
	iprotateRegions string
)

var iprotateCmd = &cobra.Command{
	Use:   "iprotate",
	Short: "IP rotation via AWS API Gateway",
	Long: `Start an IP rotation proxy using AWS API Gateway.

Each request through the proxy gets a new source IP from AWS's IP pool.
Deploys API Gateways across multiple regions and round-robins requests.
Based on the fireprox/IP Rotate technique.

Requires: AWS CLI configured with valid credentials.

Examples:
  reconator iprotate start --target https://example.com
  reconator iprotate start --target https://example.com --port 9090
  reconator iprotate stop`,
}

var iprotateStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Deploy API Gateways and start IP rotation proxy",
	RunE:  runIPRotateStart,
}

var iprotateStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Teardown API Gateways (cleanup)",
	RunE:  runIPRotateStop,
}

func init() {
	iprotateStartCmd.Flags().StringVarP(&iprotateTarget, "target", "t", "", "Target base URL to proxy (required)")
	iprotateStartCmd.Flags().IntVarP(&iprotatePort, "port", "p", 8888, "Local proxy listen port")
	iprotateStartCmd.Flags().StringVar(&iprotateRegions, "regions", "", "Comma-separated AWS regions (default: 10 diverse regions)")
	iprotateStartCmd.MarkFlagRequired("target")

	iprotateCmd.AddCommand(iprotateStartCmd)
	iprotateCmd.AddCommand(iprotateStopCmd)
}

func runIPRotateStart(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	yellow := color.New(color.FgYellow)

	// Load config defaults from ~/.reconator/config.yaml
	cfgMgr := apikeys.NewManager()
	if err := cfgMgr.Load(); err != nil {
		// Config loading is best-effort; continue with CLI flags only
		_ = err
	}
	cfgDefaults := cfgMgr.GetConfig().IPRotate

	// Apply config defaults, then let CLI flags override
	if !cmd.Flags().Changed("port") && cfgDefaults.ProxyPort > 0 {
		iprotatePort = cfgDefaults.ProxyPort
	}
	if !cmd.Flags().Changed("regions") && len(cfgDefaults.Regions) > 0 {
		iprotateRegions = strings.Join(cfgDefaults.Regions, ",")
	}

	cfg := iprotate.DefaultIPRotateConfig()
	cfg.Enabled = true
	cfg.TargetURL = iprotateTarget
	cfg.ProxyPort = iprotatePort

	if iprotateRegions != "" {
		cfg.Regions = splitAndTrim(iprotateRegions)
	}

	// Warning before deploying AWS API Gateway resources
	yellow.Println("\n  WARNING: This deploys AWS API Gateway resources (pay-per-request).")
	fmt.Printf("    Regions: %d\n", len(cfg.Regions))
	fmt.Println("    Continue? (Press Ctrl+C to cancel, waiting 5 seconds...)")
	select {
	case <-time.After(5 * time.Second):
		// User did not cancel, proceed
	case <-ctx.Done():
		fmt.Println("\n[iprotate] Cancelled.")
		return nil
	}

	rotator := iprotate.New(cfg)

	if err := rotator.Start(ctx, iprotateTarget); err != nil {
		return fmt.Errorf("start IP rotation: %w", err)
	}

	green := color.New(color.FgGreen)
	green.Printf("\n[iprotate] Proxy running at %s\n", rotator.ProxyURL())
	green.Printf("[iprotate] Gateways: %d regions\n", rotator.GatewayCount())
	fmt.Println()
	fmt.Println("Configure your tools:")
	fmt.Printf("  export HTTP_PROXY=%s\n", rotator.ProxyURL())
	fmt.Printf("  export HTTPS_PROXY=%s\n", rotator.ProxyURL())
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop and cleanup gateways.")

	// Wait for signal
	<-ctx.Done()

	fmt.Println("\n[iprotate] Shutting down...")
	cleanupCtx := context.Background()
	if err := rotator.Stop(cleanupCtx); err != nil {
		color.New(color.FgRed).Printf("[iprotate] Cleanup error: %v\n", err)
		fmt.Println("[iprotate] Manual cleanup: aws apigateway get-rest-apis | grep reconator-iprotate")
		return err
	}
	color.New(color.FgGreen).Println("[iprotate] All gateways destroyed. Clean shutdown.")
	return nil
}

func runIPRotateStop(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan)
	cyan.Println("[iprotate] To clean up leftover API Gateways:")
	fmt.Println()
	fmt.Println("List reconator gateways:")
	fmt.Println("  for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-central-1 ap-southeast-1 ap-northeast-1 ap-south-1; do")
	fmt.Println("    aws apigateway get-rest-apis --region $region --query \"items[?contains(name,'reconator-iprotate')].{id:id,name:name}\" --output table")
	fmt.Println("  done")
	fmt.Println()
	fmt.Println("Delete a specific gateway:")
	fmt.Println("  aws apigateway delete-rest-api --rest-api-id <API_ID> --region <REGION>")
	return nil
}

func splitAndTrim(s string) []string {
	var parts []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
