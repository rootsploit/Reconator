package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/dirscan"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/output"
	"github.com/rootsploit/reconator/internal/report"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/storage"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/trufflehog"
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
  reconator webscan https://example.com --wordlist /path/to/wordlist.txt
  reconator webscan https://example.com --nuclei-tags "cve,rce,sqli"`,
	Args: cobra.ExactArgs(1),
	RunE: runWebscan,
}

var (
	webscanFast        bool
	webscanDirWordlist string
	webscanDirTimeout  int
)

func init() {
	// Vulnerability scanning options
	webscanCmd.Flags().BoolVar(&cfg.DeepScan, "deep", false, "Deep vuln scan: run all nuclei templates (~30 min)")
	webscanCmd.Flags().StringVar(&cfg.NucleiTags, "nuclei-tags", "", "Custom nuclei tags (comma-separated, e.g., 'cve,rce,sqli')")
	webscanCmd.Flags().IntVar(&cfg.NucleiTimeout, "nuclei-timeout", 0, "Nuclei timeout in minutes (default: 10 fast, 30 deep)")

	// Directory bruteforce options (runs by default)
	webscanCmd.Flags().StringVar(&webscanDirWordlist, "wordlist", "", "Custom wordlist for directory bruteforce (default: common.txt ~4,700 entries)")
	webscanCmd.Flags().IntVar(&webscanDirTimeout, "dir-timeout", 10, "Directory scan timeout in minutes (default: 10)")

	// Output options
	webscanCmd.Flags().StringVarP(&cfg.OutputDir, "output", "o", "", "Output directory (default: ~/reconator)")

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

	// Generate unique scan ID (short format, matches regular scan)
	// Example: a1b2c3d4
	scanID := storage.GenerateScanID()

	// Create output directory with scan ID to prevent conflicts
	outputDir := cfg.OutputDir
	if outputDir == "" {
		// Use same default as DefaultConfig: ~/reconator
		homeDir, err := os.UserHomeDir()
		if err != nil {
			outputDir = "./results" // Fallback if home dir cannot be determined
		} else {
			outputDir = filepath.Join(homeDir, "reconator")
		}
	}
	scanDir := filepath.Join(outputDir, fmt.Sprintf("%s_%s", scanID, hostname))
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize output manager with SQLite for database persistence using the generated scan ID
	outMgr, err := output.NewManagerWithScanID(scanDir, scanID)
	if err != nil {
		return fmt.Errorf("failed to initialize output manager: %w", err)
	}
	defer outMgr.Close()

	// Set scan metadata
	outMgr.SetScanMeta(hostname, "v1.1.0")

	// Initialize tools checker
	checker := tools.NewChecker()

	var vulns []NucleiVuln
	var versionVulns []vulnscan.Vulnerability
	var dirResults *dirscan.Result
	var dependencyFindings []VulnFinding

	// Declare result structs at function level so they're accessible for saving
	type Group1Results struct {
		Tech       *techdetect.Result
		SecHeaders *secheaders.Result
		Historic   *historic.Result
	}
	var g1Results Group1Results

	if webscanFast {
		// Fast mode: skip tech detection and headers, run nuclei -as only
		fmt.Println("[*] Fast Mode: Running nuclei automatic scan only")
		vulns = runNucleiAutoScan(targetURL, checker)
	} else {
		// Full mode: Parallelized phases for maximum performance

		// ============================================================================
		// GROUP 1: Initial reconnaissance (run in parallel)
		// ============================================================================
		fmt.Println("[*] Group 1: Initial Reconnaissance (Parallel)")
		fmt.Println("    → Tech Detection | Security Headers | Historic URLs")
		fmt.Println()

		var wg1 sync.WaitGroup
		wg1.Add(3)

		// Phase 1.1: Technology Detection (parallel)
		go func() {
			defer wg1.Done()
			fmt.Println("[*] Phase 1.1: Technology Detection")
			techDetector := techdetect.NewDetector(&cfg, checker)
			result, err := techDetector.Detect([]string{targetURL})
			if err != nil {
				fmt.Printf("    Warning: tech detection error: %v\n", err)
			} else if result != nil {
				g1Results.Tech = result
				printTechResults(result, hostname)
			}
		}()

		// Phase 1.2: Security Headers Check (parallel)
		go func() {
			defer wg1.Done()
			fmt.Println("[*] Phase 1.2: Security Headers Analysis")
			headersChecker := secheaders.NewChecker(&cfg, checker)
			result, err := headersChecker.Check(hostname, []string{targetURL})
			if err != nil {
				fmt.Printf("    Warning: headers check error: %v\n", err)
			} else if result != nil {
				g1Results.SecHeaders = result
				printHeadersResults(result)
			}
		}()

		// Phase 1.3: Historic URL Collection (parallel - moved early!)
		go func() {
			defer wg1.Done()
			fmt.Println("[*] Phase 1.3: Historic URL Collection (Early)")
			historicCollector := historic.NewCollector(&cfg, checker)

			// Extract domain from URL
			historicDomain := strings.TrimPrefix(targetURL, "https://")
			historicDomain = strings.TrimPrefix(historicDomain, "http://")
			historicDomain = strings.Split(historicDomain, "/")[0]
			historicDomain = strings.Split(historicDomain, ":")[0]

			result, err := historicCollector.Collect(historicDomain, []string{targetURL})
			if err != nil {
				fmt.Printf("    Warning: historic URL collection error: %v\n", err)
			} else if result != nil && result.Total > 0 {
				g1Results.Historic = result
				fmt.Printf("    Found %d historic URLs\n", result.Total)
				fmt.Printf("    Sources: ")
				for source, count := range result.Sources {
					fmt.Printf("%s=%d ", source, count)
				}
				fmt.Println()

				if result.Categorized.XSS != nil || result.Categorized.SQLi != nil {
					fmt.Printf("    Categorized: XSS=%d SQLi=%d SSRF=%d LFI=%d JS=%d Sensitive=%d\n",
						len(result.Categorized.XSS), len(result.Categorized.SQLi),
						len(result.Categorized.SSRF), len(result.Categorized.LFI),
						len(result.Categorized.JSFiles), len(result.Categorized.Sensitive))
				}
				if len(result.ExtractedSubdomains) > 0 {
					fmt.Printf("    Extracted %d subdomain(s) from URLs\n", len(result.ExtractedSubdomains))
				}
			} else {
				fmt.Println("    No historic URLs found")
			}
		}()

		wg1.Wait()
		fmt.Println("\n[✓] Group 1 Complete\n")

		// Store references for later use
		techResult := g1Results.Tech

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

		// Phase 4: Directory Bruteforce (runs by default with short wordlist)
		fmt.Println("\n[*] Phase 4: Directory Bruteforce")
		dirScanner := dirscan.NewScanner(checker, time.Duration(webscanDirTimeout)*time.Minute, cfg.Threads)
		var err error
		dirResults, err = dirScanner.Scan(targetURL, webscanDirWordlist)
		if err != nil {
			fmt.Printf("    Warning: directory scan error: %v\n", err)
		} else if dirResults != nil {
			printDirResults(dirResults)
		}

		// Phase 4.5: GraphQL Endpoint Discovery
		fmt.Println("\n[*] Phase 4.5: GraphQL Endpoint Discovery")
		graphqlScanner := vulnscan.NewGraphQLScanner(&cfg, checker)
		graphqlResult, err := graphqlScanner.ScanGraphQL(context.Background(), []string{targetURL})
		if err != nil {
			fmt.Printf("    Warning: GraphQL scan error: %v\n", err)
		} else if graphqlResult != nil && graphqlResult.TotalFound > 0 {
			fmt.Printf("    Found %d GraphQL endpoint(s)\n", graphqlResult.TotalFound)
			if graphqlResult.Introspectable > 0 {
				fmt.Printf("    %d endpoints have introspection enabled (HIGH RISK)\n", graphqlResult.Introspectable)
			}
			for _, endpoint := range graphqlResult.Endpoints {
				fmt.Printf("    [%s] %s (%s)\n", endpoint.Type, endpoint.URL,
					map[bool]string{true: "INTROSPECTION ENABLED", false: "introspection disabled"}[endpoint.IntrospectionEnabled])
				if len(endpoint.Vulnerabilities) > 0 {
					for _, vuln := range endpoint.Vulnerabilities {
						fmt.Printf("        -> %s\n", vuln)
					}
				}
			}
		} else {
			fmt.Println("    No GraphQL endpoints found")
		}

		// Phase 4.6: Admin Panel Detection
		fmt.Println("\n[*] Phase 4.6: Admin Panel Detection")
		adminScanner := vulnscan.NewAdminPanelScanner(&cfg)
		adminResult, err := adminScanner.ScanAdminPanels(context.Background(), []string{targetURL})
		if err != nil {
			fmt.Printf("    Warning: admin panel scan error: %v\n", err)
		} else if adminResult != nil && adminResult.Total > 0 {
			fmt.Printf("    Found %d admin panel(s)\n", adminResult.Total)
			for _, panel := range adminResult.Panels {
				authStatus := ""
				if panel.HasLogin {
					authStatus = fmt.Sprintf(" [LOGIN REQUIRED - %s auth]", panel.AuthType)
				}
				fmt.Printf("    [%d] %s%s\n", panel.StatusCode, panel.URL, authStatus)
				if panel.Title != "" {
					fmt.Printf("        Title: %s\n", panel.Title)
				}
			}
		} else {
			fmt.Println("    No admin panels found")
		}

		// Phase 4.6b: Dependency & Supply Chain Scanning (exposed manifests, vulnerable packages)
		fmt.Println("\n[*] Phase 4.6b: Dependency & Supply Chain Scanning")
		// Check for exposed dependency manifests and vulnerable packages
		dependencyFindings = runNucleiTaggedScan([]string{targetURL}, "exposure,config,composer,npm,dependency", checker)
		if len(dependencyFindings) > 0 {
			fmt.Printf("    Found %d dependency/supply chain issues\n", len(dependencyFindings))
			// Count exposed manifests vs vulnerabilities
			exposedCount := 0
			for _, finding := range dependencyFindings {
				if strings.Contains(strings.ToLower(finding.Name), "exposed") ||
				   strings.Contains(strings.ToLower(finding.Name), "disclosure") {
					exposedCount++
				}
			}
			if exposedCount > 0 {
				fmt.Printf("    Exposed manifests/configs: %d\n", exposedCount)
			}
		} else {
			fmt.Println("    No dependency issues found")
		}

		// Phase 4.7: TruffleHog Secret Scanning (web + JS files from historic collection)
		fmt.Println("\n[*] Phase 4.7: TruffleHog Secret Scanning")

		if checker.IsInstalled("trufflehog") {
			truffleScanner := trufflehog.NewScanner(checker)

			// Collect JS files from historic results if available
			var jsFilesForScanning []string
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.JSFiles) > 0 {
				jsFilesForScanning = g1Results.Historic.Categorized.JSFiles
			}

			truffleResult, err := truffleScanner.ScanWebTarget(context.Background(), targetURL, jsFilesForScanning)
			if err != nil {
				fmt.Printf("    Warning: TruffleHog scan error: %v\n", err)
			} else if truffleResult != nil && truffleResult.TotalFound > 0 {
				fmt.Printf("    Found %d secrets (%d verified)\n", truffleResult.TotalFound, truffleResult.Verified)
				if len(truffleResult.ByDetector) > 0 {
					fmt.Print("    By detector: ")
					for detector, count := range truffleResult.ByDetector {
						fmt.Printf("%s=%d ", detector, count)
					}
					fmt.Println()
				}
				// Show sample secrets (limit to 5)
				if len(truffleResult.Secrets) > 0 {
					fmt.Println("    Sample findings:")
					for i, secret := range truffleResult.Secrets {
						if i >= 5 {
							fmt.Printf("        ... and %d more\n", len(truffleResult.Secrets)-5)
							break
						}
						verifiedBadge := ""
						if secret.Verified {
							verifiedBadge = " [VERIFIED]"
						}
						fmt.Printf("        [%s] %s in %s%s\n", secret.DetectorName, secret.SourceType, secret.SourceURL, verifiedBadge)
					}
				}
			} else {
				fmt.Println("    No secrets found")
			}
		} else {
			fmt.Println("    trufflehog not installed - skipping")
			fmt.Println("    Install: go install github.com/trufflesecurity/trufflehog/v3@latest")
		}

		// ============================================================================
		// GROUP 2: Targeted Vulnerability Scanning (run in parallel)
		// Uses categorized URLs from historic collection and detected tech stack
		// ============================================================================
		fmt.Println("\n[*] Group 2: Targeted Vulnerability Scanning (Parallel)")
		fmt.Println("    → XSS | SSTI | SSRF | SQLi | LFI | Open Redirect | Host Header | CORS | CVE")
		fmt.Println("    → Misconfig | Exposed Panels | Default Logins | Command Injection | XXE")
		fmt.Println()

		type Group2Results struct {
			XSS            []VulnFinding
			SSTI           []VulnFinding
			SSRF           []VulnFinding
			SQLi           []VulnFinding
			LFI            []VulnFinding
			OpenRedirect   []VulnFinding
			HostHeader     []VulnFinding
			CORS           []VulnFinding
			CVE            []VulnFinding
			Misconfig      []VulnFinding
			ExposedPanels  []VulnFinding
			DefaultLogins  []VulnFinding
			CMDi           []VulnFinding
			XXE            []VulnFinding
		}
		var g2Results Group2Results
		var wg2 sync.WaitGroup
		var mu2 sync.Mutex

		// Phase 2.1: XSS Scanning (dalfox + sxss) - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.1: XSS Scanning (dalfox + sxss)")

			// Use categorized XSS URLs if available, otherwise generate test URLs
			targetURLs := []string{targetURL}
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.XSS) > 0 {
				targetURLs = g1Results.Historic.Categorized.XSS
				fmt.Printf("    Using %d historic XSS-prone URLs\n", len(targetURLs))
			}

			xssVulns := runXSSScan(targetURLs[0], checker) // Start with first URL
			mu2.Lock()
			for _, xv := range xssVulns {
				g2Results.XSS = append(g2Results.XSS, VulnFinding{
					TemplateID:  xv.TemplateID,
					Name:        xv.Name,
					Severity:    xv.Severity,
					Type:        xv.Type,
					Host:        xv.Host,
					URL:         xv.URL,
					Description: xv.Description,
					Tool:        xv.Tool,
				})
			}
			mu2.Unlock()
			fmt.Printf("    XSS scan complete: %d findings\n", len(xssVulns))
		}()

		// Phase 2.2: SSTI Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.2: SSTI Scanning (nuclei templates)")

			var sstiFin []VulnFinding
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.SSTI) > 0 {
				fmt.Printf("    Testing %d SSTI-prone URLs\n", len(g1Results.Historic.Categorized.SSTI))
				sstiFin = runNucleiTaggedScan(g1Results.Historic.Categorized.SSTI, "ssti", checker)
			} else {
				fmt.Println("    No SSTI-prone URLs from historic collection")
			}

			mu2.Lock()
			g2Results.SSTI = sstiFin
			mu2.Unlock()
			fmt.Printf("    SSTI scan complete: %d findings\n", len(sstiFin))
		}()

		// Phase 2.3: SSRF Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.3: SSRF Scanning (nuclei templates)")

			var ssrfFin []VulnFinding
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.SSRF) > 0 {
				fmt.Printf("    Testing %d SSRF-prone URLs\n", len(g1Results.Historic.Categorized.SSRF))
				ssrfFin = runNucleiTaggedScan(g1Results.Historic.Categorized.SSRF, "ssrf", checker)
			} else {
				fmt.Println("    No SSRF-prone URLs from historic collection")
			}

			mu2.Lock()
			g2Results.SSRF = ssrfFin
			mu2.Unlock()
			fmt.Printf("    SSRF scan complete: %d findings\n", len(ssrfFin))
		}()

		// Phase 2.4: SQLi Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.4: SQLi Scanning (nuclei templates)")

			var sqliFin []VulnFinding
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.SQLi) > 0 {
				fmt.Printf("    Testing %d SQLi-prone URLs\n", len(g1Results.Historic.Categorized.SQLi))
				sqliFin = runNucleiTaggedScan(g1Results.Historic.Categorized.SQLi, "sqli", checker)
			} else {
				fmt.Println("    No SQLi-prone URLs from historic collection")
			}

			mu2.Lock()
			g2Results.SQLi = sqliFin
			mu2.Unlock()
			fmt.Printf("    SQLi scan complete: %d findings\n", len(sqliFin))
		}()

		// Phase 2.5: LFI/RFI Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.5: LFI/RFI Scanning (nuclei templates)")

			var lfiFin []VulnFinding
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.LFI) > 0 {
				fmt.Printf("    Testing %d LFI-prone URLs\n", len(g1Results.Historic.Categorized.LFI))
				// Use both lfi and rfi tags to catch all variants, then filter FPs
				lfiFin = runNucleiTaggedScan(g1Results.Historic.Categorized.LFI, "lfi,rfi,file-inclusion", checker)
				// Filter common false positives
				lfiFin = filterLFIFalsePositives(lfiFin)
			} else {
				fmt.Println("    No LFI-prone URLs from historic collection")
			}

			mu2.Lock()
			g2Results.LFI = lfiFin
			mu2.Unlock()
			fmt.Printf("    LFI scan complete: %d findings\n", len(lfiFin))
		}()

		// Phase 2.6: Open Redirect Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.6: Open Redirect Scanning (nuclei templates)")

			var redirectFin []VulnFinding
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.Redirect) > 0 {
				fmt.Printf("    Testing %d redirect-prone URLs\n", len(g1Results.Historic.Categorized.Redirect))
				redirectFin = runNucleiTaggedScan(g1Results.Historic.Categorized.Redirect, "redirect", checker)
			} else {
				fmt.Println("    No redirect-prone URLs from historic collection")
			}

			mu2.Lock()
			g2Results.OpenRedirect = redirectFin
			mu2.Unlock()
			fmt.Printf("    Open Redirect scan complete: %d findings\n", len(redirectFin))
		}()

		// Phase 2.7: Host Header Injection - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.7: Host Header Injection (nuclei templates)")

			// Test main target for host header injection
			hostHeaderFin := runNucleiTaggedScan([]string{targetURL}, "host-header-injection", checker)

			mu2.Lock()
			g2Results.HostHeader = hostHeaderFin
			mu2.Unlock()
			fmt.Printf("    Host Header Injection scan complete: %d findings\n", len(hostHeaderFin))
		}()

		// Phase 2.7b: CORS Misconfiguration - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.7b: CORS Misconfiguration (nuclei templates)")

			// Test main target for CORS misconfiguration
			corsFin := runNucleiTaggedScan([]string{targetURL}, "cors,misconfiguration", checker)

			mu2.Lock()
			g2Results.CORS = corsFin
			mu2.Unlock()
			fmt.Printf("    CORS scan complete: %d findings\n", len(corsFin))
		}()

		// Phase 2.8: Nuclei CVE Scanning (based on detected tech stack) - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.8: Nuclei CVE Scanning (tech-specific CVE templates)")

			var cveFin []VulnFinding
			if techResult != nil && len(techResult.TechByHost) > 0 {
				// Build list of detected technologies for CVE scanning
				var detectedTechs []string
				for _, techs := range techResult.TechByHost {
					detectedTechs = append(detectedTechs, techs...)
				}

				if len(detectedTechs) > 0 {
					fmt.Printf("    Running CVE templates for: %s\n", strings.Join(detectedTechs[:min(3, len(detectedTechs))], ", "))
					// Run nuclei with CVE tag on target URL
					cveFin = runNucleiTaggedScan([]string{targetURL}, "cve", checker)
				} else {
					fmt.Println("    No technologies detected for CVE scanning")
				}
			} else {
				fmt.Println("    No technologies detected for CVE scanning")
			}

			mu2.Lock()
			g2Results.CVE = cveFin
			mu2.Unlock()
			fmt.Printf("    Nuclei CVE scan complete: %d findings\n", len(cveFin))
		}()

		// Phase 2.9: Misconfiguration Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.9: Misconfiguration Scanning (nuclei templates)")

			misconfigFin := runNucleiTaggedScan([]string{targetURL}, "misconfig,misconfiguration", checker)

			mu2.Lock()
			g2Results.Misconfig = misconfigFin
			mu2.Unlock()
			fmt.Printf("    Misconfiguration scan complete: %d findings\n", len(misconfigFin))
		}()

		// Phase 2.10: Exposed Panels Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.10: Exposed Panels Scanning (nuclei templates)")

			exposedFin := runNucleiTaggedScan([]string{targetURL}, "panel,exposure,exposed-panels", checker)

			mu2.Lock()
			g2Results.ExposedPanels = exposedFin
			mu2.Unlock()
			fmt.Printf("    Exposed Panels scan complete: %d findings\n", len(exposedFin))
		}()

		// Phase 2.11: Default Logins Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.11: Default Logins Scanning (nuclei templates)")

			loginsFin := runNucleiTaggedScan([]string{targetURL}, "default-login,default-creds", checker)

			mu2.Lock()
			g2Results.DefaultLogins = loginsFin
			mu2.Unlock()
			fmt.Printf("    Default Logins scan complete: %d findings\n", len(loginsFin))
		}()

		// Phase 2.12: Command Injection Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.12: Command Injection Scanning (nuclei templates)")

			var cmdiF []VulnFinding
			// Use RCE URLs if available from historic collection
			if g1Results.Historic != nil && len(g1Results.Historic.Categorized.RCE) > 0 {
				fmt.Printf("    Testing %d RCE/CMDi-prone URLs\n", len(g1Results.Historic.Categorized.RCE))
				cmdiF = runNucleiTaggedScan(g1Results.Historic.Categorized.RCE, "rce,cmdi,command-injection", checker)
			} else {
				// Test main URL if no historic URLs
				cmdiF = runNucleiTaggedScan([]string{targetURL}, "rce,cmdi,command-injection", checker)
			}

			mu2.Lock()
			g2Results.CMDi = cmdiF
			mu2.Unlock()
			fmt.Printf("    Command Injection scan complete: %d findings\n", len(cmdiF))
		}()

		// Phase 2.13: XXE (XML External Entity) Scanning - parallel
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			fmt.Println("[*] Phase 2.13: XXE Scanning (nuclei templates)")

			xxeFin := runNucleiTaggedScan([]string{targetURL}, "xxe", checker)

			mu2.Lock()
			g2Results.XXE = xxeFin
			mu2.Unlock()
			fmt.Printf("    XXE scan complete: %d findings\n", len(xxeFin))
		}()

		wg2.Wait()
		fmt.Println("\n[✓] Group 2 Complete\n")

		// Consolidate Group 2 results into main vulns slice
		for _, v := range g2Results.XSS {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.OpenRedirect {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.HostHeader {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.CORS {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.CVE {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.SSTI {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.SSRF {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.SQLi {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.LFI {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.Misconfig {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.ExposedPanels {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.DefaultLogins {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.CMDi {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}
		for _, v := range g2Results.XXE {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}

		// Add dependency findings from Phase 4.6b
		for _, v := range dependencyFindings {
			vulns = append(vulns, NucleiVuln{
				TemplateID:  v.TemplateID,
				Name:        v.Name,
				Severity:    v.Severity,
				Type:        v.Type,
				Host:        v.Host,
				MatchedAt:   v.URL,
				Description: v.Description,
			})
		}

		// Phase 6: Nuclei General Vulnerability Scanning
		fmt.Println("\n[*] Phase 6: Nuclei General Vulnerability Scanning")
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

	// Print directory scan summary if available
	if dirResults != nil && dirResults.TotalFound > 0 {
		fmt.Printf("\n[*] Directory Scan Summary:\n")
		fmt.Printf("    Tool: %s\n", dirResults.Tool)
		fmt.Printf("    Total found: %d (%d directories, %d files)\n",
			dirResults.TotalFound, len(dirResults.Directories), len(dirResults.Files))

		interesting := dirResults.GetInterestingPaths()
		if len(interesting) > 0 {
			fmt.Printf("    Interesting paths: %d\n", len(interesting))
			for i, path := range interesting {
				if i >= 10 {
					fmt.Printf("        ... and %d more\n", len(interesting)-10)
					break
				}
				fmt.Printf("        - %s\n", path)
			}
		}
	}

	// ============================================================================
	// SAVE ALL RESULTS - Generate JSON files, database records, and HTML report
	// ============================================================================
	fmt.Println("\n[*] Saving scan results...")

	// Save technology detection results
	if !webscanFast && g1Results.Tech != nil {
		if err := outMgr.SaveTechResults(g1Results.Tech); err != nil {
			fmt.Printf("    Warning: failed to save tech results: %v\n", err)
		}
	}

	// Save security headers results
	if !webscanFast && g1Results.SecHeaders != nil {
		if err := outMgr.SaveSecHeadersResults(g1Results.SecHeaders); err != nil {
			fmt.Printf("    Warning: failed to save security headers: %v\n", err)
		}
	}

	// Save historic URL results
	if !webscanFast && g1Results.Historic != nil {
		if err := outMgr.SaveHistoricResults(g1Results.Historic); err != nil {
			fmt.Printf("    Warning: failed to save historic URLs: %v\n", err)
		}
	}

	// Save vulnerability results (both database and JSON files)
	vulnResult := &vulnscan.Result{
		TotalScanned:    1,
		Vulnerabilities: make([]vulnscan.Vulnerability, 0),
		Duration:        time.Since(start),
		ScanMode:        "webscan",
	}

	// Convert NucleiVuln to vulnscan.Vulnerability format
	for _, v := range vulns {
		vulnResult.Vulnerabilities = append(vulnResult.Vulnerabilities, vulnscan.Vulnerability{
			Host:        v.Host,
			URL:         v.MatchedAt,
			TemplateID:  v.TemplateID,
			Name:        v.Name,
			Severity:    v.Severity,
			Type:        v.Type,
			Description: v.Description,
			Tool:        "nuclei",
		})
	}

	if err := outMgr.SaveVulnResults(vulnResult); err != nil {
		fmt.Printf("    Warning: failed to save vulnerability results: %v\n", err)
	}

	// Save scan summary
	if err := outMgr.SaveSummary(hostname); err != nil {
		fmt.Printf("    Warning: failed to save summary: %v\n", err)
	}

	// Mark scan as completed in database
	if outMgr.HasSQLite() {
		ctx := context.Background()
		duration := time.Since(start)
		if err := outMgr.SQLiteDB().CompleteScan(ctx, outMgr.ScanID(), duration); err != nil {
			fmt.Printf("    Warning: failed to mark scan as completed: %v\n", err)
		}
	}

	// Summary
	fmt.Printf("\n[*] Scan completed in %s\n", time.Since(start).Round(time.Second))
	fmt.Printf("    Results saved to: %s\n", scanDir)
	fmt.Printf("    Scan ID: %s\n", outMgr.ScanID())

	// Generate HTML report
	fmt.Println("\n[*] Generating HTML report...")
	if err := generateWebscanReport(scanDir, hostname); err != nil {
		fmt.Printf("    Warning: failed to generate HTML report: %v\n", err)
	} else {
		reportPath := filepath.Join(scanDir, fmt.Sprintf("report_%s.html", hostname))
		fmt.Printf("    ✓ HTML report: %s\n", reportPath)
	}

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

// VulnFinding represents a vulnerability finding
type VulnFinding struct {
	TemplateID  string
	Name        string
	Severity    string
	Type        string
	Host        string
	URL         string
	Description string
	Tool        string
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// filterLFIFalsePositives removes common false positives from LFI findings
func filterLFIFalsePositives(findings []VulnFinding) []VulnFinding {
	var filtered []VulnFinding

	for _, f := range findings {
		// Skip common false positives
		isFP := false

		// Skip if it's just detecting common file paths without actual inclusion
		fpPatterns := []string{
			"robots.txt",         // Common file, not LFI
			"sitemap.xml",        // Common file, not LFI
			".well-known",        // Common directory, not LFI
			"favicon.ico",        // Common file, not LFI
			"manifest.json",      // Common file, not LFI
		}

		urlLower := strings.ToLower(f.URL)
		for _, pattern := range fpPatterns {
			if strings.Contains(urlLower, pattern) {
				isFP = true
				break
			}
		}

		// Skip low-confidence findings with generic template IDs
		if strings.Contains(f.TemplateID, "-detect") && f.Severity == "info" {
			isFP = true
		}

		if !isFP {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// runNucleiTaggedScan runs nuclei with specific tags on a list of URLs
func runNucleiTaggedScan(urls []string, tag string, checker *tools.Checker) []VulnFinding {
	if !checker.IsInstalled("nuclei") {
		return nil
	}

	// Limit URLs to prevent excessive scan time (use first 50 URLs max)
	maxURLs := 50
	if len(urls) > maxURLs {
		urls = urls[:maxURLs]
	}

	// Create temp file with URLs
	tmpFile, err := os.CreateTemp("", "nuclei-urls-*.txt")
	if err != nil {
		return nil
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	for _, url := range urls {
		tmpFile.WriteString(url + "\n")
	}
	tmpFile.Close()

	args := []string{
		"-list", tmpPath,
		"-tags", tag,
		"-jsonl",
		"-nc",
		"-omit-raw",
		"-silent",
	}

	timeout := 5 * time.Minute
	if cfg.DeepScan {
		timeout = 15 * time.Minute
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: timeout})

	var findings []VulnFinding
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var vuln NucleiVuln
		if err := json.Unmarshal([]byte(line), &vuln); err != nil {
			continue
		}
		// Use info fields if main fields are empty
		if vuln.Name == "" && vuln.Info.Name != "" {
			vuln.Name = vuln.Info.Name
		}
		if vuln.Severity == "" && vuln.Info.Severity != "" {
			vuln.Severity = vuln.Info.Severity
		}
		if vuln.Description == "" && vuln.Info.Description != "" {
			vuln.Description = vuln.Info.Description
		}

		findings = append(findings, VulnFinding{
			TemplateID:  vuln.TemplateID,
			Name:        vuln.Name,
			Severity:    vuln.Severity,
			Type:        tag,
			Host:        vuln.Host,
			URL:         vuln.MatchedAt,
			Description: vuln.Description,
			Tool:        "nuclei",
		})
	}

	return findings
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

// printDirResults displays directory bruteforce results
func printDirResults(result *dirscan.Result) {
	if result.TotalFound == 0 {
		fmt.Println("    No directories or files found")
		return
	}

	fmt.Printf("    Tool: %s\n", result.Tool)
	fmt.Printf("    Found: %d total (%d directories, %d files)\n",
		result.TotalFound, len(result.Directories), len(result.Files))

	// Show interesting paths
	interesting := result.GetInterestingPaths()
	if len(interesting) > 0 {
		fmt.Printf("    Interesting paths (%d):\n", len(interesting))
		for i, path := range interesting {
			if i >= 5 {
				fmt.Printf("        ... and %d more (see full results)\n", len(interesting)-5)
				break
			}
			fmt.Printf("        %s\n", path)
		}
	}

	// Show sample directories
	if len(result.Directories) > 0 {
		fmt.Printf("    Sample directories:\n")
		for i, dir := range result.Directories {
			if i >= 3 {
				fmt.Printf("        ... and %d more\n", len(result.Directories)-3)
				break
			}
			fmt.Printf("        [%d] %s\n", dir.StatusCode, dir.Path)
		}
	}

	// Show sample files
	if len(result.Files) > 0 {
		fmt.Printf("    Sample files:\n")
		for i, file := range result.Files {
			if i >= 3 {
				fmt.Printf("        ... and %d more\n", len(result.Files)-3)
				break
			}
			fmt.Printf("        [%d] %s\n", file.StatusCode, file.Path)
		}
	}
}

// generateWebscanReport generates an HTML report from the saved JSON files
func generateWebscanReport(scanDir, hostname string) error {
	// Load all available phase results
	reportData := &report.Data{
		Target:  hostname,
		Version: "v1.1.0",
		Date:    time.Now().Format(time.RFC1123),
	}

	// Load tech results
	if data := loadJSON[techdetect.Result](filepath.Join(scanDir, "6-tech", "tech_detection.json")); data != nil {
		reportData.Tech = data
	}

	// Load security headers
	if data := loadJSON[secheaders.Result](filepath.Join(scanDir, "6b-secheaders", "security_headers.json")); data != nil {
		reportData.SecHeaders = data
	}

	// Load historic URLs
	if data := loadJSON[historic.Result](filepath.Join(scanDir, "5-historic", "historic_urls.json")); data != nil {
		reportData.Historic = data
	}

	// Load vulnerabilities
	if data := loadJSON[vulnscan.Result](filepath.Join(scanDir, "8-vulnscan", "vulnerabilities.json")); data != nil {
		reportData.VulnScan = data
	}

	// Generate the report
	if err := report.Generate(reportData, scanDir); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}
