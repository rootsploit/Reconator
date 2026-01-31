package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/export"
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
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
	"github.com/spf13/cobra"
)

var exportFormat string

var exportCmd = &cobra.Command{
	Use:   "export [target-directory]",
	Short: "Export scan results to various formats",
	Long: `Export scan results to CSV, JSON, Markdown, or SARIF formats.

Available formats:
  - csv:      Export subdomains, vulnerabilities, ports, and endpoints to CSV files
  - json:     Export complete structured scan data as JSON
  - markdown: Export a summary report in Markdown format
  - sarif:    Export vulnerabilities in SARIF format (GitHub Security tab)
  - all:      Export to all formats

Examples:
  reconator export ./results/example.com
  reconator export ./results/example.com --format csv
  reconator export ./results/example.com --format json
  reconator export ./results/example.com --format markdown
  reconator export ./results/example.com --format sarif
  reconator export ./results/example.com --format all`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "all", "Export format: csv, json, markdown, sarif, all")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	outDir := args[0]
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)

	// Extract target name from directory
	target := filepath.Base(outDir)

	cyan.Printf("\n[*] Exporting results for: %s\n", target)
	fmt.Printf("    Directory: %s\n", outDir)
	fmt.Printf("    Format: %s\n\n", exportFormat)

	// Load scan data (reuse report loading logic)
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
		loadedCount++
	}

	// WAF results
	if data := loadJSON[waf.Result](filepath.Join(outDir, "2-waf", "waf_detection.json")); data != nil {
		reportData.WAF = data
		loadedCount++
	}

	// Port results
	if data := loadJSON[portscan.Result](filepath.Join(outDir, "3-ports", "port_scan.json")); data != nil {
		reportData.Ports = data
		loadedCount++
	}

	// Takeover results
	if data := loadJSON[takeover.Result](filepath.Join(outDir, "4-takeover", "takeover.json")); data != nil {
		reportData.Takeover = data
		loadedCount++
	}

	// Historic results
	if data := loadJSON[historic.Result](filepath.Join(outDir, "5-historic", "historic_urls.json")); data != nil {
		reportData.Historic = data
		loadedCount++
	}

	// Tech results
	if data := loadJSON[techdetect.Result](filepath.Join(outDir, "6-tech", "tech_detection.json")); data != nil {
		reportData.Tech = data
		loadedCount++
	}

	// Security Headers results
	if data := loadJSON[secheaders.Result](filepath.Join(outDir, "6b-secheaders", "security_headers.json")); data != nil {
		reportData.SecHeaders = data
		loadedCount++
	}

	// DirBrute results
	if data := loadJSON[dirbrute.Result](filepath.Join(outDir, "7-dirbrute", "dirbrute.json")); data != nil {
		reportData.DirBrute = data
		loadedCount++
	}

	// JSAnalysis results
	if data := loadJSON[jsanalysis.Result](filepath.Join(outDir, "7b-jsanalysis", "js_analysis.json")); data != nil {
		reportData.JSAnalysis = data
		loadedCount++
	}

	// VulnScan results
	if data := loadJSON[vulnscan.Result](filepath.Join(outDir, "8-vulnscan", "vulnerabilities.json")); data != nil {
		reportData.VulnScan = data
		loadedCount++
	}

	// AI-guided results
	if data := loadJSON[aiguided.Result](filepath.Join(outDir, "9-aiguided", "ai_guided.json")); data != nil {
		reportData.AIGuided = data
		loadedCount++
	}

	// Screenshot results
	if data := loadJSON[screenshot.Result](filepath.Join(outDir, "screenshots", "screenshot_clusters.json")); data != nil {
		reportData.Screenshot = data
		loadedCount++
	}

	// IP Range results
	if data := loadJSON[iprange.Result](filepath.Join(outDir, "0-iprange", "ip_discovery.json")); data != nil {
		reportData.IPRange = data
		loadedCount++
	}

	if loadedCount == 0 {
		return fmt.Errorf("no scan data found in %s", outDir)
	}

	fmt.Printf("    Loaded %d data sources\n\n", loadedCount)

	// Create exporter
	exporter := export.NewExporter(reportData, outDir)

	// Export based on format
	switch exportFormat {
	case "all":
		files, err := exporter.ExportAll()
		if err != nil {
			return fmt.Errorf("export failed: %w", err)
		}
		green.Printf("    Exported to %d formats:\n", len(files))
		for _, f := range files {
			fmt.Printf("      - %s\n", f)
		}

	case "csv":
		path, err := exporter.ExportCSV()
		if err != nil {
			return fmt.Errorf("CSV export failed: %w", err)
		}
		green.Printf("    CSV files exported to: %s\n", path)

	case "json":
		path, err := exporter.ExportJSON()
		if err != nil {
			return fmt.Errorf("JSON export failed: %w", err)
		}
		green.Printf("    JSON exported to: %s\n", path)

	case "markdown", "md":
		path, err := exporter.ExportMarkdown()
		if err != nil {
			return fmt.Errorf("Markdown export failed: %w", err)
		}
		green.Printf("    Markdown exported to: %s\n", path)

	case "sarif":
		path, err := exporter.ExportSARIF()
		if err != nil {
			return fmt.Errorf("SARIF export failed: %w", err)
		}
		green.Printf("    SARIF exported to: %s\n", path)
		fmt.Println("    Upload to GitHub: gh code-scanning upload-sarif --sarif-file=" + path)

	default:
		yellow.Printf("    Unknown format: %s\n", exportFormat)
		fmt.Println("    Available formats: csv, json, markdown, sarif, all")
		return nil
	}

	fmt.Println()
	return nil
}
