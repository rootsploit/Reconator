package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/runner"
	"github.com/rootsploit/reconator/internal/storage"
	"github.com/spf13/cobra"
)

var (
	monitorInterval  time.Duration
	monitorWebhook   string
	monitorSlack     string
	monitorDiscord   string
	monitorOnce      bool
	monitorQuiet     bool

	monitorCmd = &cobra.Command{
		Use:   "monitor [domain]",
		Short: "Continuously monitor targets for changes",
		Long: `Monitor targets for attack surface changes over time.

Performs periodic scans and compares results with previous scans to detect:
- New subdomains discovered
- New open ports detected
- New vulnerabilities found
- Subdomain takeover opportunities
- Technology stack changes

Alerts can be sent via webhook, Slack, or Discord when changes are detected.

Examples:
  reconator monitor target.com --interval 24h
  reconator monitor target.com --interval 6h --slack https://hooks.slack.com/...
  reconator monitor -l targets.txt --interval 12h --webhook https://example.com/webhook
  reconator monitor target.com --once  # Single comparison scan`,
		Args: cobra.MaximumNArgs(1),
		RunE: runMonitor,
	}
)

func init() {
	monitorCmd.Flags().DurationVar(&monitorInterval, "interval", 24*time.Hour, "Scan interval (e.g., 6h, 12h, 24h)")
	monitorCmd.Flags().StringVar(&monitorWebhook, "webhook", "", "Webhook URL for alerts")
	monitorCmd.Flags().StringVar(&monitorSlack, "slack", "", "Slack webhook URL for alerts")
	monitorCmd.Flags().StringVar(&monitorDiscord, "discord", "", "Discord webhook URL for alerts")
	monitorCmd.Flags().BoolVar(&monitorOnce, "once", false, "Run once and compare with last scan (no continuous monitoring)")
	monitorCmd.Flags().BoolVar(&monitorQuiet, "quiet", false, "Only output when changes are detected")

	// Inherit common flags from scan
	monitorCmd.Flags().StringVarP(&cfg.TargetFile, "list", "l", "", "File containing list of domains")
	monitorCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "", "Output directory (default: ~/reconator)")
	monitorCmd.Flags().IntVarP(&cfg.Threads, "threads", "c", 50, "Number of concurrent threads")
	monitorCmd.Flags().BoolVar(&cfg.PassiveMode, "passive", false, "Passive mode only")
}

// ChangeReport represents detected changes between scans
type ChangeReport struct {
	Target          string    `json:"target"`
	ScanTime        time.Time `json:"scan_time"`
	PreviousScanID  string    `json:"previous_scan_id,omitempty"`
	CurrentScanID   string    `json:"current_scan_id"`
	NewSubdomains   []string  `json:"new_subdomains,omitempty"`
	LostSubdomains  []string  `json:"lost_subdomains,omitempty"`
	NewPorts        []string  `json:"new_ports,omitempty"`
	NewVulns        []VulnChange `json:"new_vulnerabilities,omitempty"`
	NewTakeovers    []string  `json:"new_takeovers,omitempty"`
	TechChanges     []string  `json:"tech_changes,omitempty"`
	HasChanges      bool      `json:"has_changes"`
}

// VulnChange represents a new vulnerability
type VulnChange struct {
	Host     string `json:"host"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

func runMonitor(cmd *cobra.Command, args []string) error {
	printBanner()

	if len(args) > 0 {
		cfg.Target = args[0]
	}

	if cfg.Target == "" && cfg.TargetFile == "" {
		return fmt.Errorf("target domain required: reconator monitor <domain> or reconator monitor -l <file>")
	}

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	if monitorOnce {
		cyan.Println("[+] Running single comparison scan...")
		return runSingleMonitor()
	}

	cyan.Printf("[+] Starting continuous monitoring (interval: %s)\n", monitorInterval)
	if monitorWebhook != "" || monitorSlack != "" || monitorDiscord != "" {
		green.Println("[+] Alerts configured")
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run initial scan
	if !monitorQuiet {
		yellow.Println("[*] Running initial scan...")
	}
	if err := runScanAndCompare(); err != nil {
		yellow.Printf("[!] Initial scan failed: %v\n", err)
	}

	// Start monitoring loop
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sigChan:
			yellow.Println("\n[*] Shutting down monitor...")
			return nil
		case <-ticker.C:
			if !monitorQuiet {
				cyan.Printf("[*] Running scheduled scan at %s\n", time.Now().Format(time.RFC3339))
			}
			if err := runScanAndCompare(); err != nil {
				yellow.Printf("[!] Scan failed: %v\n", err)
			}
		}
	}
}

func runSingleMonitor() error {
	return runScanAndCompare()
}

func runScanAndCompare() error {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	// Enable SQLite for monitoring
	cfg.EnableSQLite = true

	// Run the scan using pipeline runner
	pr := runner.NewPipelineRunner(&cfg)
	if err := pr.Run(); err != nil {
		return err
	}

	// Compare with previous scan
	target := cfg.Target
	if target == "" {
		// Read first target from file
		targets, err := readTargetsFromFile(cfg.TargetFile)
		if err != nil || len(targets) == 0 {
			return fmt.Errorf("no targets found")
		}
		target = targets[0]
	}

	report, err := compareWithPreviousScan(target)
	if err != nil {
		yellow.Printf("[!] Could not compare with previous scan: %v\n", err)
		return nil // Not a fatal error for first scan
	}

	if !report.HasChanges {
		if !monitorQuiet {
			green.Println("[+] No changes detected since last scan")
		}
		return nil
	}

	// Print changes
	red.Println("\n[!] CHANGES DETECTED")
	fmt.Println("────────────────────────────────────────")

	if len(report.NewSubdomains) > 0 {
		green.Printf("[+] New subdomains (%d):\n", len(report.NewSubdomains))
		for _, sub := range report.NewSubdomains {
			fmt.Printf("    + %s\n", sub)
		}
	}

	if len(report.LostSubdomains) > 0 {
		yellow.Printf("[!] Lost subdomains (%d):\n", len(report.LostSubdomains))
		for _, sub := range report.LostSubdomains {
			fmt.Printf("    - %s\n", sub)
		}
	}

	if len(report.NewPorts) > 0 {
		green.Printf("[+] New open ports (%d):\n", len(report.NewPorts))
		for _, port := range report.NewPorts {
			fmt.Printf("    + %s\n", port)
		}
	}

	if len(report.NewVulns) > 0 {
		red.Printf("[!] New vulnerabilities (%d):\n", len(report.NewVulns))
		for _, vuln := range report.NewVulns {
			fmt.Printf("    [%s] %s - %s\n", vuln.Severity, vuln.Host, vuln.Name)
		}
	}

	if len(report.NewTakeovers) > 0 {
		red.Printf("[!] Subdomain takeover opportunities (%d):\n", len(report.NewTakeovers))
		for _, t := range report.NewTakeovers {
			fmt.Printf("    ! %s\n", t)
		}
	}

	fmt.Println("────────────────────────────────────────")

	// Send alerts
	if err := sendAlerts(report); err != nil {
		yellow.Printf("[!] Failed to send alerts: %v\n", err)
	}

	return nil
}

func compareWithPreviousScan(target string) (*ChangeReport, error) {
	report := &ChangeReport{
		Target:   target,
		ScanTime: time.Now(),
	}

	// Open SQLite database
	db, err := storage.NewSQLiteStorage(filepath.Join(cfg.OutputDir, target))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ctx := context.Background()

	// Get the two most recent scans
	scans, err := db.ListScans(ctx, target, 2)
	if err != nil || len(scans) < 2 {
		return report, fmt.Errorf("not enough scans for comparison (need at least 2, found %d)", len(scans))
	}

	currentScan := scans[0]
	previousScan := scans[1]
	report.CurrentScanID = currentScan.ID
	report.PreviousScanID = previousScan.ID

	// Compare subdomains
	currentSubs, _ := db.GetSubdomains(ctx, currentScan.ID)
	previousSubs, _ := db.GetSubdomains(ctx, previousScan.ID)

	prevSubSet := make(map[string]bool)
	for _, s := range previousSubs {
		prevSubSet[s] = true
	}
	currSubSet := make(map[string]bool)
	for _, s := range currentSubs {
		currSubSet[s] = true
	}

	for _, s := range currentSubs {
		if !prevSubSet[s] {
			report.NewSubdomains = append(report.NewSubdomains, s)
		}
	}
	for _, s := range previousSubs {
		if !currSubSet[s] {
			report.LostSubdomains = append(report.LostSubdomains, s)
		}
	}

	// Compare alive hosts (ports)
	currentHosts, _ := db.GetAliveHosts(ctx, currentScan.ID)
	previousHosts, _ := db.GetAliveHosts(ctx, previousScan.ID)

	prevHostSet := make(map[string]bool)
	for _, h := range previousHosts {
		prevHostSet[h] = true
	}
	for _, h := range currentHosts {
		if !prevHostSet[h] {
			report.NewPorts = append(report.NewPorts, h)
		}
	}

	// Compare vulnerabilities
	currentVulns, _ := db.GetVulnerabilities(ctx, currentScan.ID)
	previousVulns, _ := db.GetVulnerabilities(ctx, previousScan.ID)

	prevVulnSet := make(map[string]bool)
	for _, v := range previousVulns {
		key := fmt.Sprintf("%s|%s", v.Host, v.TemplateID)
		prevVulnSet[key] = true
	}
	for _, v := range currentVulns {
		key := fmt.Sprintf("%s|%s", v.Host, v.TemplateID)
		if !prevVulnSet[key] {
			report.NewVulns = append(report.NewVulns, VulnChange{
				Host:     v.Host,
				Name:     v.Name,
				Severity: v.Severity,
			})
		}
	}

	// Compare takeovers
	currentTakeovers, _ := db.GetTakeovers(ctx, currentScan.ID)
	previousTakeovers, _ := db.GetTakeovers(ctx, previousScan.ID)

	prevTakeoverSet := make(map[string]bool)
	for _, t := range previousTakeovers {
		prevTakeoverSet[t.Subdomain] = true
	}
	for _, t := range currentTakeovers {
		if !prevTakeoverSet[t.Subdomain] {
			report.NewTakeovers = append(report.NewTakeovers, t.Subdomain)
		}
	}

	// Determine if there are changes
	report.HasChanges = len(report.NewSubdomains) > 0 ||
		len(report.LostSubdomains) > 0 ||
		len(report.NewPorts) > 0 ||
		len(report.NewVulns) > 0 ||
		len(report.NewTakeovers) > 0

	return report, nil
}

func sendAlerts(report *ChangeReport) error {
	if !report.HasChanges {
		return nil
	}

	// Build alert message
	msg := buildAlertMessage(report)

	var lastErr error

	// Send to webhook
	if monitorWebhook != "" {
		if err := sendWebhook(monitorWebhook, report); err != nil {
			lastErr = err
		}
	}

	// Send to Slack
	if monitorSlack != "" {
		if err := sendSlackAlert(monitorSlack, msg); err != nil {
			lastErr = err
		}
	}

	// Send to Discord
	if monitorDiscord != "" {
		if err := sendDiscordAlert(monitorDiscord, msg); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

func buildAlertMessage(report *ChangeReport) string {
	var msg string
	msg = fmt.Sprintf("*Reconator Alert: %s*\n", report.Target)
	msg += fmt.Sprintf("Scan Time: %s\n\n", report.ScanTime.Format(time.RFC3339))

	if len(report.NewSubdomains) > 0 {
		msg += fmt.Sprintf("*New Subdomains (%d):*\n", len(report.NewSubdomains))
		for i, sub := range report.NewSubdomains {
			if i >= 10 {
				msg += fmt.Sprintf("... and %d more\n", len(report.NewSubdomains)-10)
				break
			}
			msg += fmt.Sprintf("  + %s\n", sub)
		}
	}

	if len(report.NewPorts) > 0 {
		msg += fmt.Sprintf("\n*New Open Ports (%d):*\n", len(report.NewPorts))
		for i, port := range report.NewPorts {
			if i >= 10 {
				msg += fmt.Sprintf("... and %d more\n", len(report.NewPorts)-10)
				break
			}
			msg += fmt.Sprintf("  + %s\n", port)
		}
	}

	if len(report.NewVulns) > 0 {
		msg += fmt.Sprintf("\n*New Vulnerabilities (%d):*\n", len(report.NewVulns))
		for _, vuln := range report.NewVulns {
			msg += fmt.Sprintf("  [%s] %s - %s\n", vuln.Severity, vuln.Host, vuln.Name)
		}
	}

	if len(report.NewTakeovers) > 0 {
		msg += fmt.Sprintf("\n*Subdomain Takeover Opportunities (%d):*\n", len(report.NewTakeovers))
		for _, t := range report.NewTakeovers {
			msg += fmt.Sprintf("  ! %s\n", t)
		}
	}

	return msg
}

func sendWebhook(url string, report *ChangeReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func sendSlackAlert(webhookURL, message string) error {
	payload := map[string]string{
		"text": message,
	}
	data, _ := json.Marshal(payload)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func sendDiscordAlert(webhookURL, message string) error {
	payload := map[string]string{
		"content": message,
	}
	data, _ := json.Marshal(payload)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func readTargetsFromFile(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, line := range bytes.Split(content, []byte("\n")) {
		if len(line) > 0 {
			targets = append(targets, string(line))
		}
	}
	return targets, nil
}
