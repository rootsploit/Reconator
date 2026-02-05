package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/jsanalysis"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/report"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/rootsploit/reconator/internal/vhost"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [target-directory]",
	Short: "Regenerate HTML report from existing scan results",
	Long: `Regenerate the HTML report from existing JSON scan results.

Use this command to recreate a deleted report or generate a fresh report
from scan data in the specified target directory.

Examples:
  reconator report ./results/example.com
  reconator report ./results/AS13335`,
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	outDir := args[0]

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	// Verify directory exists
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return fmt.Errorf("directory not found: %s", outDir)
	}

	// Extract target name from directory
	target := filepath.Base(outDir)

	cyan.Printf("\n[*] Regenerating report for: %s\n", target)
	fmt.Printf("    Directory: %s\n\n", outDir)

	// Create report data with metadata
	reportData := &report.Data{
		Target:  target,
		Version: version.Version,
		Date:    time.Now().Format(time.RFC1123),
	}

	// Load all available phase results
	loadedCount := 0

	// Subdomain results
	if data := loadJSON[subdomain.Result](filepath.Join(outDir, "1-subdomains", "subdomains.json")); data != nil {
		reportData.Subdomain = data
		fmt.Printf("    ✓ Loaded subdomain data: %d subdomains\n", len(data.Subdomains))
		loadedCount++
	}

	// WAF results
	if data := loadJSON[waf.Result](filepath.Join(outDir, "2-waf", "waf_detection.json")); data != nil {
		reportData.WAF = data
		fmt.Printf("    ✓ Loaded WAF data: %d direct, %d CDN hosts\n", len(data.DirectHosts), len(data.CDNHosts))
		loadedCount++
	}

	// Port results
	if data := loadJSON[portscan.Result](filepath.Join(outDir, "3-ports", "port_scan.json")); data != nil {
		reportData.Ports = data
		fmt.Printf("    ✓ Loaded port data: %d alive hosts\n", data.AliveCount)
		loadedCount++
	}

	// Takeover results
	if data := loadJSON[takeover.Result](filepath.Join(outDir, "4-takeover", "takeover.json")); data != nil {
		reportData.Takeover = data
		fmt.Printf("    ✓ Loaded takeover data: %d vulnerable\n", len(data.Vulnerable))
		loadedCount++
	}

	// VHost results
	if data := loadJSON[vhost.Result](filepath.Join(outDir, "4-vhost", "vhost.json")); data != nil {
		reportData.VHost = data
		fmt.Printf("    ✓ Loaded VHost data: %d vhosts\n", len(data.VHosts))
		loadedCount++
	}

	// Historic results
	if data := loadJSON[historic.Result](filepath.Join(outDir, "5-historic", "historic_urls.json")); data != nil {
		reportData.Historic = data
		fmt.Printf("    ✓ Loaded historic data: %d URLs\n", len(data.URLs))
		loadedCount++
	}

	// Tech results
	if data := loadJSON[techdetect.Result](filepath.Join(outDir, "6-tech", "tech_detection.json")); data != nil {
		reportData.Tech = data
		fmt.Printf("    ✓ Loaded tech data: %d hosts\n", len(data.TechByHost))
		loadedCount++
	}

	// Security Headers results
	if data := loadJSON[secheaders.Result](filepath.Join(outDir, "6b-secheaders", "security_headers.json")); data != nil {
		reportData.SecHeaders = data
		fmt.Printf("    ✓ Loaded security headers data: %d findings, %d email issues\n", len(data.HeaderFindings), data.EmailIssues)
		loadedCount++
	}

	// DirBrute results
	if data := loadJSON[dirbrute.Result](filepath.Join(outDir, "7-dirbrute", "dirbrute.json")); data != nil {
		reportData.DirBrute = data
		fmt.Printf("    ✓ Loaded dirbrute data: %d discoveries\n", len(data.Discoveries))
		loadedCount++
	}

	// JSAnalysis results
	if data := loadJSON[jsanalysis.Result](filepath.Join(outDir, "7b-jsanalysis", "js_analysis.json")); data != nil {
		reportData.JSAnalysis = data
		fmt.Printf("    ✓ Loaded JS analysis data: %d endpoints, %d DOM XSS sinks\n", len(data.Endpoints), len(data.DOMXSSSinks))
		loadedCount++
	}

	// VulnScan results
	if data := loadJSON[vulnscan.Result](filepath.Join(outDir, "8-vulnscan", "vulnerabilities.json")); data != nil {
		reportData.VulnScan = data
		fmt.Printf("    ✓ Loaded vulnscan data: %d vulnerabilities\n", len(data.Vulnerabilities))
		loadedCount++
	}

	// Screenshot results (try both paths for compatibility)
	if data := loadJSON[screenshot.Result](filepath.Join(outDir, "9-screenshots", "screenshot_results.json")); data != nil {
		reportData.Screenshot = data
		fmt.Printf("    ✓ Loaded screenshot data: %d images\n", len(data.Screenshots))
		loadedCount++
	} else if data := loadJSON[screenshot.Result](filepath.Join(outDir, "screenshots", "screenshot_clusters.json")); data != nil {
		// Legacy path fallback
		reportData.Screenshot = data
		fmt.Printf("    ✓ Loaded screenshot data (legacy path): %d images\n", len(data.Screenshots))
		loadedCount++
	}

	// AI-guided results
	if data := loadJSON[aiguided.Result](filepath.Join(outDir, "10-aiguided", "ai_guided.json")); data != nil {
		reportData.AIGuided = data
		fmt.Printf("    ✓ Loaded AI-guided data\n")
		loadedCount++
	} else if data := loadJSON[aiguided.Result](filepath.Join(outDir, "9-aiguided", "ai_guided.json")); data != nil {
		// Legacy path fallback
		reportData.AIGuided = data
		fmt.Printf("    ✓ Loaded AI-guided data (legacy path)\n")
		loadedCount++
	}

	// IP Range results (for ASN targets)
	if data := loadJSON[iprange.Result](filepath.Join(outDir, "0-iprange", "ip_discovery.json")); data != nil {
		reportData.IPRange = data
		fmt.Printf("    ✓ Loaded IP range data: %d IPs, %d domains\n", len(data.IPs), len(data.Domains))
		loadedCount++
	}

	if loadedCount == 0 {
		return fmt.Errorf("no scan data found in %s", outDir)
	}

	fmt.Printf("\n    Loaded %d data sources\n\n", loadedCount)

	// Generate the report
	if err := report.Generate(reportData, outDir); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	reportPath := filepath.Join(outDir, fmt.Sprintf("report_%s.html", target))
	green.Printf("✓ Report regenerated: %s\n\n", reportPath)

	// Show severity summary if vulnerabilities exist
	if reportData.VulnScan != nil && len(reportData.VulnScan.Vulnerabilities) > 0 {
		showVulnSummary(reportData.VulnScan.Vulnerabilities)
	}

	return nil
}

// loadJSON is a generic helper to load JSON files into structs
func loadJSON[T any](path string) *T {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return &result
}

// showVulnSummary prints a vulnerability severity breakdown
func showVulnSummary(vulns []vulnscan.Vulnerability) {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, v := range vulns {
		sev := v.Severity
		if _, ok := counts[sev]; ok {
			counts[sev]++
		} else {
			counts["info"]++
		}
	}

	red := color.New(color.FgRed, color.Bold)
	orange := color.New(color.FgHiRed)
	yellow := color.New(color.FgYellow)
	blue := color.New(color.FgBlue)
	gray := color.New(color.FgHiBlack)

	fmt.Println("    Vulnerability Summary:")
	if counts["critical"] > 0 {
		red.Printf("      Critical: %d\n", counts["critical"])
	}
	if counts["high"] > 0 {
		orange.Printf("      High: %d\n", counts["high"])
	}
	if counts["medium"] > 0 {
		yellow.Printf("      Medium: %d\n", counts["medium"])
	}
	if counts["low"] > 0 {
		blue.Printf("      Low: %d\n", counts["low"])
	}
	if counts["info"] > 0 {
		gray.Printf("      Info: %d\n", counts["info"])
	}
	fmt.Println()
}
