package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/spf13/cobra"
)

var webscanCmd = &cobra.Command{
	Use:   "webscan [url]",
	Short: "Run vulnerability scan on a single URL (DAST mode)",
	Long: `Run vulnerability scanning on a single URL target.

This is a DAST (Dynamic Application Security Testing) mode for scanning
individual web applications or endpoints.

Examples:
  reconator webscan https://example.com
  reconator webscan https://api.example.com/v1
  reconator webscan https://example.com --deep
  reconator webscan https://example.com --nuclei-tags "cve,rce,sqli"`,
	Args: cobra.ExactArgs(1),
	RunE: runWebscan,
}

var webscanFast bool

func init() {
	// Vulnerability scanning options
	webscanCmd.Flags().BoolVar(&cfg.DeepScan, "deep", false, "Deep vuln scan: run all nuclei templates (~30 min)")
	webscanCmd.Flags().StringVar(&cfg.NucleiTags, "nuclei-tags", "", "Custom nuclei tags (comma-separated, e.g., 'cve,rce,sqli')")
	webscanCmd.Flags().IntVar(&cfg.NucleiTimeout, "nuclei-timeout", 0, "Nuclei timeout in minutes (default: 10 fast, 30 deep)")

	// Output options
	webscanCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "./results", "Output directory")

	// Performance
	webscanCmd.Flags().IntVarP(&cfg.Threads, "threads", "c", 0, "Concurrent threads (0=auto-detect)")
	webscanCmd.Flags().BoolVar(&webscanFast, "fast", false, "Fast mode: skip tech detection and headers, run nuclei -as only")

	// Scan features
	webscanCmd.Flags().BoolVar(&cfg.EnableScreenshots, "screenshots", false, "Capture screenshots")

	// Debug
	webscanCmd.Flags().BoolVar(&cfg.Debug, "debug", false, "Show detailed timing logs")
}

func runWebscan(cmd *cobra.Command, args []string) error {
	printBanner()

	targetURL := args[0]

	// Validate URL format
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		return fmt.Errorf("invalid URL: must start with http:// or https://")
	}

	fmt.Println("\n[*] DAST Mode - Single URL Vulnerability Scan")
	fmt.Printf("    Target: %s\n\n", targetURL)

	start := time.Now()

	// Extract hostname for output directory
	hostname := strings.TrimPrefix(targetURL, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.Split(hostname, "/")[0]
	hostname = strings.Split(hostname, ":")[0]

	// Create output directory
	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = "./results"
	}
	scanDir := filepath.Join(outputDir, hostname)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize tools checker
	checker := tools.NewChecker()

	var vulns []NucleiVuln

	if webscanFast {
		// Fast mode: skip tech detection and headers, run nuclei -as only
		fmt.Println("[*] Fast Mode: Running nuclei automatic scan only")
		vulns = runNucleiAutoScan(targetURL, checker)
	} else {
		// Full mode: tech detection, headers, then nuclei

		// Phase 1: Technology Detection
		fmt.Println("[*] Phase 1: Technology Detection")
		techDetector := techdetect.NewDetector(&cfg, checker)
		techResult, err := techDetector.Detect([]string{targetURL})
		if err != nil {
			fmt.Printf("    Warning: tech detection error: %v\n", err)
		} else if techResult != nil {
			printTechResults(techResult, hostname)
		}

		// Phase 2: Security Headers Check
		fmt.Println("\n[*] Phase 2: Security Headers Analysis")
		headersChecker := secheaders.NewChecker(&cfg, checker)
		headersResult, err := headersChecker.Check(hostname, []string{targetURL})
		if err != nil {
			fmt.Printf("    Warning: headers check error: %v\n", err)
		} else if headersResult != nil {
			printHeadersResults(headersResult)
		}

		// Phase 3: Vulnerability Scanning (using nuclei -as for automatic tech-based scanning)
		fmt.Println("\n[*] Phase 3: Vulnerability Scanning")
		vulns = runNucleiAutoScan(targetURL, checker)
	}

	// Print vulnerability results
	printVulnResultsDirect(vulns)

	// Summary
	fmt.Printf("\n[*] Scan completed in %s\n", time.Since(start).Round(time.Second))
	fmt.Printf("    Results saved to: %s\n", scanDir)

	return nil
}

// printTechResults displays technology detection results
func printTechResults(result *techdetect.Result, hostname string) {
	if len(result.TechByHost) == 0 {
		fmt.Println("    No technologies detected")
		return
	}

	for host, techs := range result.TechByHost {
		if len(techs) > 0 {
			fmt.Printf("    Technologies: %s\n", strings.Join(techs, ", "))
		}

		// Show versions if detected
		if versions, ok := result.VersionByHost[host]; ok && len(versions) > 0 {
			fmt.Printf("    Versions: %s\n", strings.Join(versions, ", "))
		}
	}
}

// printHeadersResults displays security headers analysis
func printHeadersResults(result *secheaders.Result) {
	if len(result.HeaderFindings) == 0 {
		fmt.Println("    No headers analyzed")
		return
	}

	// Summary
	if result.MissingHeaders > 0 {
		fmt.Printf("    Missing security headers: %d\n", result.MissingHeaders)
	}
	if result.WeakHeaders > 0 {
		fmt.Printf("    Weak headers: %d\n", result.WeakHeaders)
	}
	if result.MisconfigCount > 0 {
		fmt.Printf("    Misconfigurations: %d\n", result.MisconfigCount)
	}

	// Details for first finding
	if len(result.HeaderFindings) > 0 {
		finding := result.HeaderFindings[0]
		if len(finding.Missing) > 0 && len(finding.Missing) <= 5 {
			var headers []string
			for _, h := range finding.Missing {
				headers = append(headers, h.Header)
			}
			fmt.Printf("    Missing: %s\n", strings.Join(headers, ", "))
		}
	}
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
	colorOrange = "\033[38;5;208m"
)

// getSeverityColor returns ANSI color code for severity level
func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return colorRed
	case "high":
		return colorOrange
	case "medium":
		return colorYellow
	case "low":
		return colorBlue
	default:
		return colorGray
	}
}

// truncate shortens a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// NucleiVuln represents a vulnerability found by nuclei
type NucleiVuln struct {
	TemplateID  string   `json:"template-id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Type        string   `json:"type"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched-at"`
	Description string   `json:"description,omitempty"`
	MatcherName string   `json:"matcher-name,omitempty"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	Info        struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		Tags        []string `json:"tags"`
	} `json:"info"`
}

// runNucleiAutoScan runs nuclei with automatic scan mode (-as)
// This does tech detection + runs targeted templates based on detected tech
func runNucleiAutoScan(targetURL string, checker *tools.Checker) []NucleiVuln {
	if !checker.IsInstalled("nuclei") {
		fmt.Println("    Warning: nuclei not installed")
		return nil
	}

	fmt.Println("    Running nuclei automatic scan (tech-detect + targeted templates)...")

	// nuclei -as -u <url> -jsonl (JSON Lines output)
	// Note: -silent suppresses progress but findings still go to stdout
	args := []string{
		"-as", // Automatic scan: tech detect + run relevant templates
		"-u", targetURL,
		"-jsonl",    // JSON Lines output format
		"-nc",       // No color
		"-omit-raw", // Don't include raw request/response (reduces output from MB to KB)
	}

	// Add timeout (nuclei -as can take 2-3 minutes)
	timeout := 5 * time.Minute
	if cfg.DeepScan {
		timeout = 30 * time.Minute
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: timeout})

	// Debug: show output info
	if cfg.Debug {
		fmt.Printf("    [debug] nuclei stdout length: %d bytes\n", len(r.Stdout))
		fmt.Printf("    [debug] nuclei stderr length: %d bytes\n", len(r.Stderr))
		if r.Error != nil {
			fmt.Printf("    [debug] nuclei error: %v\n", r.Error)
		}
	}

	// Parse JSON Lines output
	var vulns []NucleiVuln
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		// Skip non-JSON lines (nuclei outputs some text even with -jsonl)
		if !strings.HasPrefix(line, "{") {
			if cfg.Debug {
				fmt.Printf("    [debug] skipping non-JSON line: %s\n", truncate(line, 60))
			}
			continue
		}
		var vuln NucleiVuln
		if err := json.Unmarshal([]byte(line), &vuln); err != nil {
			if cfg.Debug {
				fmt.Printf("    [debug] JSON parse error: %v\n", err)
			}
			continue
		}
		// Use info.name if name is empty
		if vuln.Name == "" && vuln.Info.Name != "" {
			vuln.Name = vuln.Info.Name
		}
		if vuln.Severity == "" && vuln.Info.Severity != "" {
			vuln.Severity = vuln.Info.Severity
		}
		if vuln.Description == "" && vuln.Info.Description != "" {
			vuln.Description = vuln.Info.Description
		}
		vulns = append(vulns, vuln)
	}

	// Deduplicate findings by URL + TemplateID
	seen := make(map[string]bool)
	var uniqueVulns []NucleiVuln
	for _, v := range vulns {
		key := fmt.Sprintf("%s|%s|%s", v.MatchedAt, v.Host, v.TemplateID)
		if !seen[key] {
			seen[key] = true
			uniqueVulns = append(uniqueVulns, v)
		}
	}

	fmt.Printf("    nuclei auto-scan: %d findings\n", len(uniqueVulns))
	return uniqueVulns
}

// printVulnResultsDirect displays vulnerability results from direct nuclei scan
func printVulnResultsDirect(vulns []NucleiVuln) {
	if len(vulns) == 0 {
		fmt.Println("    No vulnerabilities found")
		return
	}

	// Count by severity
	severityCounts := make(map[string]int)
	for _, v := range vulns {
		severityCounts[strings.ToLower(v.Severity)]++
	}

	fmt.Printf("\n[+] Found %d findings:\n", len(vulns))
	if severityCounts["critical"] > 0 {
		fmt.Printf("    Critical: %d\n", severityCounts["critical"])
	}
	if severityCounts["high"] > 0 {
		fmt.Printf("    High: %d\n", severityCounts["high"])
	}
	if severityCounts["medium"] > 0 {
		fmt.Printf("    Medium: %d\n", severityCounts["medium"])
	}
	if severityCounts["low"] > 0 {
		fmt.Printf("    Low: %d\n", severityCounts["low"])
	}
	if severityCounts["info"] > 0 {
		fmt.Printf("    Info: %d\n", severityCounts["info"])
	}

	fmt.Println("\n    Details:")
	for _, v := range vulns {
		severityColor := getSeverityColor(v.Severity)
		fmt.Printf("    %s[%s]%s %s\n", severityColor, strings.ToUpper(v.Severity), colorReset, v.Name)
		if v.MatchedAt != "" {
			fmt.Printf("        URL: %s\n", v.MatchedAt)
		} else if v.Host != "" {
			fmt.Printf("        Host: %s\n", v.Host)
		}
		if v.Description != "" {
			// Truncate long descriptions
			desc := v.Description
			if len(desc) > 100 {
				desc = desc[:100] + "..."
			}
			fmt.Printf("        Description: %s\n", desc)
		}
	}
}
