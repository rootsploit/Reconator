package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/vulnscan"
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

	// Scan features (screenshots enabled by default to match scan command)
	webscanCmd.Flags().BoolVar(&cfg.EnableScreenshots, "screenshots", true, "Capture screenshots (default: true)")

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
	var versionVulns []vulnscan.Vulnerability

	if webscanFast {
		// Fast mode: skip tech detection and headers, run nuclei -as only
		fmt.Println("[*] Fast Mode: Running nuclei automatic scan only")
		vulns = runNucleiAutoScan(targetURL, checker)
	} else {
		// Full mode: tech detection, headers, CVE detection, XSS scanning, then nuclei

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

		// Phase 3: CVE Version Detection (based on detected tech)
		fmt.Println("\n[*] Phase 3: CVE Version Detection")
		if techResult != nil && (len(techResult.TechByHost) > 0 || len(techResult.VersionByHost) > 0) {
			// Merge TechByHost and VersionByHost for CVE lookup
			techForCVE := make(map[string][]string)
			for host, techs := range techResult.TechByHost {
				techForCVE[host] = append(techForCVE[host], techs...)
			}
			for host, versions := range techResult.VersionByHost {
				techForCVE[host] = append(techForCVE[host], versions...)
			}

			cveResult := vulnscan.DetectVersionVulnerabilitiesWithChecker(techForCVE, checker)
			if cveResult != nil && len(cveResult.Vulnerabilities) > 0 {
				versionVulns = cveResult.Vulnerabilities
				fmt.Printf("    Found %d version-based CVEs\n", len(versionVulns))
				// Show sources used
				for source, count := range cveResult.Sources {
					fmt.Printf("        %s: %d\n", source, count)
				}
			} else {
				fmt.Println("    No version-based CVEs found")
			}

			// Show outdated software warnings
			if cveResult != nil && len(cveResult.Warnings) > 0 {
				fmt.Printf("    Outdated software warnings: %d\n", len(cveResult.Warnings))
			}
		} else {
			fmt.Println("    Skipped: no technologies detected")
		}

		// Phase 4: XSS Scanning (dalfox + sxss)
		fmt.Println("\n[*] Phase 4: XSS Scanning")
		xssVulns := runXSSScan(targetURL, checker)
		if len(xssVulns) > 0 {
			// Convert XSS vulns to NucleiVuln format for unified display
			for _, xv := range xssVulns {
				vulns = append(vulns, NucleiVuln{
					TemplateID:  xv.TemplateID,
					Name:        xv.Name,
					Severity:    xv.Severity,
					Type:        xv.Type,
					Host:        xv.Host,
					MatchedAt:   xv.URL,
					Description: xv.Description,
				})
			}
		}

		// Phase 5: Nuclei Vulnerability Scanning
		fmt.Println("\n[*] Phase 5: Nuclei Vulnerability Scanning")
		nucleiVulns := runNucleiAutoScan(targetURL, checker)
		vulns = append(vulns, nucleiVulns...)
	}

	// Add version-based CVE findings to results
	for _, vv := range versionVulns {
		vulns = append(vulns, NucleiVuln{
			TemplateID:  vv.TemplateID,
			Name:        vv.Name,
			Severity:    vv.Severity,
			Type:        vv.Type,
			Host:        vv.Host,
			MatchedAt:   vv.URL,
			Description: vv.Description,
		})
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

// XSSVuln represents an XSS vulnerability found by dalfox or sxss
type XSSVuln struct {
	URL         string
	TemplateID  string
	Name        string
	Severity    string
	Type        string
	Host        string
	Description string
	Tool        string
}

// runXSSScan runs XSS scanning using dalfox and sxss in parallel
func runXSSScan(targetURL string, checker *tools.Checker) []XSSVuln {
	var allVulns []XSSVuln
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Check if URL has parameters (needed for XSS scanning)
	hasParams := strings.Contains(targetURL, "?") && strings.Contains(targetURL, "=")

	if !hasParams {
		fmt.Println("    URL has no parameters - generating test URLs with common params")
		// Generate URLs with common XSS-prone parameters
		targetURL = generateXSSTestURL(targetURL)
	}

	// Run dalfox (parallel)
	if checker.IsInstalled("dalfox") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("    Running dalfox XSS scan...")
			vulns := runDalfoxScan(targetURL)
			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
			fmt.Printf("    dalfox: %d XSS vulnerabilities found\n", len(vulns))
		}()
	} else {
		fmt.Println("    dalfox not installed - skipping")
	}

	// Run sxss (parallel)
	if checker.IsInstalled("sxss") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("    Running sxss XSS reflection scan...")
			vulns := runSxssScan(targetURL)
			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
			fmt.Printf("    sxss: %d XSS reflections found\n", len(vulns))
		}()
	} else {
		fmt.Println("    sxss not installed - skipping")
	}

	wg.Wait()

	if !checker.IsInstalled("dalfox") && !checker.IsInstalled("sxss") {
		fmt.Println("    No XSS tools installed. Install with: go install github.com/hahwul/dalfox/v2@latest")
	}

	return allVulns
}

// generateXSSTestURL adds common XSS-prone parameters to a URL
func generateXSSTestURL(baseURL string) string {
	// Common parameters that are often vulnerable to XSS
	params := []string{"q", "search", "query", "s", "keyword", "id", "page", "name", "url", "redirect", "return", "callback"}

	// Add first few params with test value
	testParams := make([]string, 0, 3)
	for i := 0; i < 3 && i < len(params); i++ {
		testParams = append(testParams, params[i]+"=test")
	}

	separator := "?"
	if strings.Contains(baseURL, "?") {
		separator = "&"
	}
	return baseURL + separator + strings.Join(testParams, "&")
}

// runDalfoxScan runs dalfox for XSS scanning
func runDalfoxScan(targetURL string) []XSSVuln {
	var vulns []XSSVuln

	outFile, err := os.CreateTemp("", "dalfox-*.json")
	if err != nil {
		return vulns
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := []string{
		"url", targetURL,
		"--silence",
		"--format", "json",
		"--output", outPath,
		"--no-color",
	}

	// Dalfox timeout: 5 min for webscan
	timeout := 5 * time.Minute
	if cfg.DeepScan {
		timeout = 10 * time.Minute
	}

	r := exec.Run("dalfox", args, &exec.Options{Timeout: timeout})
	if r.Error != nil && cfg.Debug {
		fmt.Printf("    [debug] dalfox error: %v\n", r.Error)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		return vulns
	}

	for _, line := range strings.Split(string(content), "\n") {
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var entry struct {
			URL        string `json:"url"`
			Param      string `json:"param"`
			MessageStr string `json:"message_str"`
			Severity   string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.URL != "" {
			severity := entry.Severity
			if severity == "" {
				severity = "high"
			}
			vulns = append(vulns, XSSVuln{
				URL:         entry.URL,
				TemplateID:  "dalfox-xss",
				Name:        fmt.Sprintf("XSS via %s parameter", entry.Param),
				Severity:    severity,
				Type:        "xss",
				Description: entry.MessageStr,
				Tool:        "dalfox",
			})
		}
	}

	return vulns
}

// runSxssScan runs sxss for fast XSS reflection scanning
func runSxssScan(targetURL string) []XSSVuln {
	var vulns []XSSVuln

	// Run sxss: echo URL | sxss -concurrency 50 -retries 3
	cmd := fmt.Sprintf("echo '%s' | sxss -concurrency 50 -retries 3", targetURL)

	timeout := 3 * time.Minute
	if cfg.DeepScan {
		timeout = 5 * time.Minute
	}

	r := exec.Run("sh", []string{"-c", cmd}, &exec.Options{Timeout: timeout})
	if r.Error != nil && cfg.Debug {
		fmt.Printf("    [debug] sxss error: %v\n", r.Error)
	}

	// Parse sxss output - each line is a vulnerable URL with reflected parameter info
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}

		vulns = append(vulns, XSSVuln{
			URL:         line,
			TemplateID:  "sxss-xss-reflection",
			Name:        "XSS Reflection Detected",
			Severity:    "medium",
			Type:        "xss",
			Description: fmt.Sprintf("Parameter reflection detected: %s", line),
			Tool:        "sxss",
		})
	}

	return vulns
}
