package runner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/alerting"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/debug"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/output"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

type Runner struct {
	cfg *config.Config
	c   *tools.Checker
	out *output.Manager
}

func New(cfg *config.Config) *Runner {
	return &Runner{cfg: cfg, c: tools.NewChecker()}
}

func (r *Runner) Run() error {
	start := time.Now()
	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)

	// Enable debug logging if requested
	if r.cfg.Debug {
		debug.Enable()
		cyan.Println("[DEBUG MODE ENABLED] Detailed timing logs will be shown")
		fmt.Println()
	}

	if missing := r.c.GetMissingRequired(); len(missing) > 0 {
		yellow.Printf("\n⚠ Missing required tools: %v\n", missing)
		fmt.Println("  Run 'reconator install' to install them\n")
	}

	targets, err := r.getTargets()
	if err != nil {
		return err
	}

	cyan.Printf("\n[+] Starting reconnaissance for %d target(s)\n\n", len(targets))

	for _, t := range targets {
		if err := r.process(t); err != nil {
			yellow.Printf("⚠ Error processing %s: %v\n", t, err)
		}
	}

	green.Printf("\n[+] Reconnaissance complete! Total time: %s\n", time.Since(start).Round(time.Second))

	// Show debug summary if enabled
	debug.Summary()

	return nil
}

func (r *Runner) process(target string) error {
	start := time.Now()
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	// Check if target is ASN - if so, discover CIDR ranges first
	if iprange.IsASN(target) {
		return r.processASNTarget(target)
	}

	// Check if target is IP/CIDR - if so, discover domains first
	if iprange.IsIPTarget(target) {
		return r.processIPTarget(target)
	}

	cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	cyan.Printf("  Target: %s", target)
	if r.cfg.PassiveMode {
		cyan.Printf(" [PASSIVE]")
	}
	cyan.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	outDir := filepath.Join(r.cfg.OutputDir, target)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	r.out = output.NewManager(outDir)

	var subs, allSubs, alive, directHosts []string
	var subRes *subdomain.Result
	var takeoverRes *takeover.Result
	var historicRes *historic.Result
	var takeoverDone, historicDone chan struct{}

	// Start historic URL collection FIRST (runs in parallel with subdomain enumeration)
	// This is more efficient - wayback/gau run once and we extract both URLs and subdomains
	if r.cfg.ShouldRunPhase("historic") || r.cfg.ShouldRunPhase("all") {
		historicDone = make(chan struct{})
		go func() {
			defer close(historicDone)
			hc := historic.NewCollector(r.cfg, r.c)
			if res, err := hc.Collect(target, nil); err == nil {
				historicRes = res
			}
		}()
	}

	// Phase 1: Subdomain Enumeration (runs in parallel with historic)
	if r.cfg.ShouldRunPhase("subdomain") || r.cfg.ShouldRunPhase("all") {
		cyan.Println("[Phase 1] Subdomain Enumeration")
		fmt.Println("─────────────────────────────────────────────────")
		e := subdomain.NewEnumerator(r.cfg, r.c)
		res, err := e.Enumerate(target)
		if err != nil {
			return err
		}
		subRes = res
		subs = res.Subdomains
		allSubs = res.AllSubdomains

		// Wait for historic and merge extracted subdomains
		if historicDone != nil {
			<-historicDone
			if historicRes != nil && len(historicRes.ExtractedSubdomains) > 0 {
				// Merge historic subdomains into allSubs
				seen := make(map[string]bool)
				for _, s := range allSubs {
					seen[s] = true
				}
				newFromHistoric := 0
				for _, s := range historicRes.ExtractedSubdomains {
					if !seen[s] {
						allSubs = append(allSubs, s)
						seen[s] = true
						newFromHistoric++
					}
				}
				if newFromHistoric > 0 {
					fmt.Printf("        historic_subs: %d (new: %d)\n", len(historicRes.ExtractedSubdomains), newFromHistoric)
					subRes.Sources["historic_subs"] = newFromHistoric
					subRes.AllSubdomains = allSubs
					subRes.TotalAll = len(allSubs)
				}
			}
			// Mark historic as processed (we'll display results later but collection is done)
			historicDone = nil
		}

		green.Printf("    ┌─ Summary ─────────────────────────────────\n")
		for source, count := range subRes.Sources {
			green.Printf("    │ %-18s %d\n", source+":", count)
		}
		green.Printf("    ├─────────────────────────────────────────\n")
		green.Printf("    │ All discovered:    %d\n", subRes.TotalAll)
		green.Printf("    └─ Validated alive:  %d\n\n", len(subs))
		r.out.SaveSubdomains(subRes)
	}

	// Start takeover check in background (uses ALL discovered subs including historic)
	if (r.cfg.ShouldRunPhase("takeover") || r.cfg.ShouldRunPhase("all")) && len(allSubs) > 0 {
		takeoverDone = make(chan struct{})
		go func() {
			defer close(takeoverDone)
			tc := takeover.NewChecker(r.cfg, r.c)
			if res, err := tc.Check(allSubs); err == nil {
				takeoverRes = res
			}
		}()
	}

	// Phase 2: WAF/CDN Detection (skip in passive mode - requires connecting to target)
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("waf") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		cyan.Println("[Phase 2] WAF/CDN Detection")
		fmt.Println("─────────────────────────────────────────────────")
		d := waf.NewDetector(r.cfg, r.c)
		if res, err := d.Detect(subs); err == nil {
			directHosts = res.DirectHosts
			green.Printf("    CDN: %d, Direct: %d\n\n", len(res.CDNHosts), len(directHosts))
			r.out.SaveWAFResults(res)
		}
	} else if r.cfg.PassiveMode {
		yellow.Println("[Phase 2] WAF/CDN Detection... SKIPPED (passive mode)")
		fmt.Println()
	}

	// Phase 3: Port Scanning + TLS (skip in passive mode - requires connecting to target)
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("ports") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		cyan.Println("[Phase 3] Port Scanning + TLS")
		fmt.Println("─────────────────────────────────────────────────")

		s := portscan.NewScanner(r.cfg, r.c)
		if res, err := s.Scan(subs); err == nil {
			alive = res.AliveHosts
			green.Printf("    Ports: %d, Alive: %d, TLS: %d\n\n", res.TotalPorts, len(alive), len(res.TLSInfo))
			r.out.SavePortResults(res)
		}
	} else if r.cfg.PassiveMode {
		yellow.Println("[Phase 3] Port Scanning... SKIPPED (passive mode)")
		fmt.Println()
	}

	// Phase 4: Subdomain Takeover Results (wait for background task)
	if takeoverDone != nil {
		cyan.Println("[Phase 4] Subdomain Takeover Check")
		fmt.Println("─────────────────────────────────────────────────")
		<-takeoverDone
		if takeoverRes != nil {
			if len(takeoverRes.Vulnerable) > 0 {
				color.New(color.FgRed, color.Bold).Printf("    ⚠ %d potentially vulnerable!\n\n", len(takeoverRes.Vulnerable))
			} else {
				green.Println("    No takeover vulnerabilities\n")
			}
			r.out.SaveTakeoverResults(takeoverRes)
		}
	}

	// Phase 5: Historic URL Results (already collected in parallel with subdomain enum)
	// Now run katana if we have alive hosts (katana needs alive hosts to crawl)
	if historicRes != nil {
		cyan.Println("[Phase 5] Historic URL Collection")
		fmt.Println("─────────────────────────────────────────────────")

		// Run katana now that we have alive hosts (skip in passive mode)
		if !r.cfg.PassiveMode && len(alive) > 0 {
			hc := historic.NewCollector(r.cfg, r.c)
			katanaURLs := hc.RunKatana(alive)
			if len(katanaURLs) > 0 {
				// Merge katana URLs into historic results
				seen := make(map[string]bool)
				for _, u := range historicRes.URLs {
					seen[u] = true
				}
				newCount := 0
				for _, u := range katanaURLs {
					if !seen[u] {
						historicRes.URLs = append(historicRes.URLs, u)
						seen[u] = true
						newCount++
					}
				}
				historicRes.Sources["katana"] = len(katanaURLs)
				historicRes.Total = len(historicRes.URLs)
				fmt.Printf("        katana: %d URLs (new: %d)\n", len(katanaURLs), newCount)
			}
		}

		green.Printf("    ┌─ Summary ─────────────────────────────────\n")
		for source, count := range historicRes.Sources {
			green.Printf("    │ %-15s %d URLs\n", source+":", count)
		}
		green.Printf("    │ %-15s %d subdomains\n", "extracted:", len(historicRes.ExtractedSubdomains))
		green.Printf("    └─ Total: %d unique URLs\n\n", len(historicRes.URLs))
		r.out.SaveHistoricResults(historicRes)
	}

	// Phase 6: Technology Detection (skip in passive mode - requires connecting to target)
	var techRes *techdetect.Result
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("tech") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		cyan.Println("[Phase 6] Technology Detection")
		fmt.Println("─────────────────────────────────────────────────")
		td := techdetect.NewDetector(r.cfg, r.c)
		if res, err := td.Detect(subs); err == nil {
			techRes = res
			green.Printf("    Hosts scanned: %d, Unique techs: %d\n\n", res.Total, len(res.TechCount))
			r.out.SaveTechResults(res)
		}
	} else if r.cfg.PassiveMode {
		yellow.Println("[Phase 6] Technology Detection... SKIPPED (passive mode)")
		fmt.Println()
	}

	// Categorize URLs from historic phase for targeted scanning
	var categorizedURLs *historic.CategorizedURLs
	if historicRes != nil && len(historicRes.URLs) > 0 {
		hc := historic.NewCollector(r.cfg, r.c)
		cat := hc.CategorizeURLs(historicRes.URLs)
		categorizedURLs = &cat
	}

	// Phase 7: Directory Bruteforce (skip in passive mode)
	if !r.cfg.PassiveMode && !r.cfg.SkipDirBrute && (r.cfg.ShouldRunPhase("dirbrute") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		cyan.Println("[Phase 7] Directory Bruteforce")
		fmt.Println("─────────────────────────────────────────────────")
		ds := dirbrute.NewScanner(r.cfg, r.c)
		if res, err := ds.Scan(alive); err == nil {
			green.Printf("    Discoveries: %d across %d hosts\n\n", len(res.Discoveries), len(res.ByHost))
			r.out.SaveDirBruteResults(res)
		}
	} else if r.cfg.PassiveMode || r.cfg.SkipDirBrute {
		yellow.Println("[Phase 7] Directory Bruteforce... SKIPPED")
		fmt.Println()
	}

	// Phase 8: Vulnerability Scanning (skip in passive mode)
	var vulnRes *vulnscan.Result
	if !r.cfg.PassiveMode && !r.cfg.SkipVulnScan && (r.cfg.ShouldRunPhase("vulnscan") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		cyan.Println("[Phase 8] Vulnerability Scanning")
		fmt.Println("─────────────────────────────────────────────────")
		vs := vulnscan.NewScanner(r.cfg, r.c)
		if res, err := vs.Scan(alive, categorizedURLs); err == nil {
			vulnRes = res
			green.Printf("    Vulnerabilities: %d (Critical: %d, High: %d)\n\n",
				len(res.Vulnerabilities), res.BySeverity["critical"], res.BySeverity["high"])
			r.out.SaveVulnResults(res)
		}
	} else if r.cfg.PassiveMode || r.cfg.SkipVulnScan {
		yellow.Println("[Phase 8] Vulnerability Scanning... SKIPPED")
		fmt.Println()
	}

	// Phase 9: AI-Guided Scanning (skip in passive mode or if no AI keys)
	var aiRes *aiguided.Result
	hasAIKeys := r.cfg.OpenAIKey != "" || r.cfg.ClaudeKey != "" || r.cfg.GeminiKey != ""
	if !r.cfg.PassiveMode && !r.cfg.SkipAIGuided && hasAIKeys && (r.cfg.ShouldRunPhase("aiguided") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		cyan.Println("[Phase 9] AI-Guided Scanning")
		fmt.Println("─────────────────────────────────────────────────")

		// Build target context for AI
		ctx := &aiguided.TargetContext{
			Domain: target,
		}
		if techRes != nil {
			for tech := range techRes.TechCount {
				ctx.Technologies = append(ctx.Technologies, tech)
			}
		}
		if categorizedURLs != nil {
			ctx.JSFiles = categorizedURLs.JSFiles
			ctx.APIEndpoints = categorizedURLs.APIFiles
			ctx.Endpoints = categorizedURLs.Sensitive
		}

		as := aiguided.NewScanner(r.cfg, r.c)
		if res, err := as.Scan(alive, ctx); err == nil {
			aiRes = res
			green.Printf("    AI Provider: %s, Vulnerabilities: %d\n\n", res.AIProvider, len(res.Vulnerabilities))
			r.out.SaveAIGuidedResults(res)
		}
	} else if r.cfg.SkipAIGuided || !hasAIKeys {
		yellow.Println("[Phase 9] AI-Guided Scanning... SKIPPED (no AI keys or disabled)")
		fmt.Println()
	}

	// Phase 10: Alerting (send notifications if enabled)
	if r.cfg.EnableNotify && r.c.IsInstalled("notify") {
		cyan.Println("[Phase 10] Sending Alerts")
		fmt.Println("─────────────────────────────────────────────────")

		summary := &alerting.Summary{
			Domain:          target,
			TotalSubdomains: len(allSubs),
			AliveHosts:      len(alive),
			ScanDuration:    time.Since(start),
		}

		if subRes != nil {
			summary.NewSubdomains = subRes.Total
		}
		if takeoverRes != nil {
			summary.TakeoverVulns = len(takeoverRes.Vulnerable)
		}
		if vulnRes != nil {
			summary.Vulnerabilities = len(vulnRes.Vulnerabilities)
			summary.CriticalFindings = vulnRes.BySeverity["critical"]
			summary.HighFindings = vulnRes.BySeverity["high"]
		}
		if aiRes != nil {
			summary.Vulnerabilities += len(aiRes.Vulnerabilities)
		}

		// Add notable findings as alerts
		if takeoverRes != nil {
			for _, v := range takeoverRes.Vulnerable {
				summary.Alerts = append(summary.Alerts, alerting.AlertFromTakeover(v.Subdomain, v.Service, v.Severity, v.Tool))
			}
		}
		if vulnRes != nil {
			for _, v := range vulnRes.Vulnerabilities {
				if v.Severity == "critical" || v.Severity == "high" {
					summary.Alerts = append(summary.Alerts, alerting.AlertFromVulnerability(v.Host, v.TemplateID, v.Name, v.Severity, v.Type))
				}
			}
		}

		notifier := alerting.NewNotifier(r.cfg, r.c)
		if err := notifier.Notify(summary); err != nil {
			yellow.Printf("    ⚠ Failed to send notification: %v\n", err)
		} else {
			green.Println("    Notification sent successfully")
		}
		fmt.Println()
	}

	r.out.SaveSummary(target)
	return nil
}

// processASNTarget handles ASN targets (e.g., AS13335, AS15169)
// It discovers CIDR ranges via asnmap, then domains from those IPs
func (r *Runner) processASNTarget(target string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	// Normalize ASN format for display
	displayASN := strings.ToUpper(strings.TrimSpace(target))
	if !strings.HasPrefix(displayASN, "AS") {
		displayASN = "AS" + displayASN
	}

	cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	cyan.Printf("  Target: %s [ASN]", displayASN)
	if r.cfg.PassiveMode {
		cyan.Printf(" [PASSIVE]")
	}
	cyan.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Create output directory using sanitized target name
	outDirName := sanitizeTargetName(displayASN)
	outDir := filepath.Join(r.cfg.OutputDir, outDirName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	r.out = output.NewManager(outDir)

	// Phase 0: ASN to CIDR/Domain Discovery
	cyan.Println("[Phase 0] ASN to Domain Discovery")
	fmt.Println("─────────────────────────────────────────────────")

	disc := iprange.NewDiscoverer(r.cfg, r.c)
	asnRes, err := disc.DiscoverFromASN(target)
	if err != nil {
		yellow.Printf("    ⚠ ASN discovery failed: %v\n", err)
		return err
	}

	// Extract base domains (TLDs) from discovered domains
	tlds := iprange.ExtractTLDs(asnRes.Domains)

	green.Printf("    ┌─ Summary ─────────────────────────────────\n")
	for source, count := range asnRes.Sources {
		green.Printf("    │ %-15s %d\n", source+":", count)
	}
	green.Printf("    ├─────────────────────────────────────────\n")
	green.Printf("    │ Total IPs:       %d\n", len(asnRes.IPs))
	green.Printf("    │ Total domains:   %d\n", len(asnRes.Domains))
	green.Printf("    └─ Base domains:   %d\n\n", len(tlds))

	// Save ASN discovery results
	r.out.SaveIPRangeResults(asnRes)

	if len(tlds) == 0 {
		yellow.Println("    No domains discovered from ASN")
		yellow.Println("    This ASN may not have publicly resolvable domains")
		return nil
	}

	// Group discovered subdomains by their base domain
	subsByBase := make(map[string][]string)
	for _, domain := range asnRes.Domains {
		base := extractBaseDomain(domain)
		if base != "" {
			subsByBase[base] = append(subsByBase[base], domain)
		}
	}

	// Process each discovered base domain
	fmt.Printf("    [*] Running subdomain enumeration for %d base domain(s)...\n\n", len(tlds))

	for _, domain := range tlds {
		preDiscovered := subsByBase[domain]
		if err := r.processDomain(domain, preDiscovered); err != nil {
			yellow.Printf("    ⚠ Error processing %s: %v\n", domain, err)
		}
	}

	return nil
}

// processIPTarget handles IP address or CIDR range targets
// It discovers domains via reverse DNS and certificate transparency, then runs subdomain enum
func (r *Runner) processIPTarget(target string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	cyan.Printf("  Target: %s [IP RANGE]", target)
	if r.cfg.PassiveMode {
		cyan.Printf(" [PASSIVE]")
	}
	cyan.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Create output directory using sanitized target name
	outDirName := sanitizeTargetName(target)
	outDir := filepath.Join(r.cfg.OutputDir, outDirName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	r.out = output.NewManager(outDir)

	// Phase 0: IP Range Discovery
	cyan.Println("[Phase 0] IP Range to Domain Discovery")
	fmt.Println("─────────────────────────────────────────────────")

	disc := iprange.NewDiscoverer(r.cfg, r.c)
	ipRes, err := disc.Discover(target)
	if err != nil {
		yellow.Printf("    ⚠ IP discovery failed: %v\n", err)
		return err
	}

	// Extract base domains (TLDs) from discovered domains
	tlds := iprange.ExtractTLDs(ipRes.Domains)

	green.Printf("    ┌─ Summary ─────────────────────────────────\n")
	for source, count := range ipRes.Sources {
		green.Printf("    │ %-15s %d domains\n", source+":", count)
	}
	green.Printf("    ├─────────────────────────────────────────\n")
	green.Printf("    │ Total domains:   %d\n", len(ipRes.Domains))
	green.Printf("    └─ Base domains:   %d\n\n", len(tlds))

	// Save IP discovery results
	r.out.SaveIPRangeResults(ipRes)

	if len(tlds) == 0 {
		yellow.Println("    No domains discovered from IP range")
		yellow.Println("    Try: reconator install --extras  (installs hakrevdns, cero)")
		return nil
	}

	// Group discovered subdomains by their base domain
	subsByBase := make(map[string][]string)
	for _, domain := range ipRes.Domains {
		base := extractBaseDomain(domain)
		if base != "" {
			subsByBase[base] = append(subsByBase[base], domain)
		}
	}

	// Process each discovered base domain
	fmt.Printf("    [*] Running subdomain enumeration for %d base domain(s)...\n\n", len(tlds))

	for _, domain := range tlds {
		preDiscovered := subsByBase[domain]
		if err := r.processDomain(domain, preDiscovered); err != nil {
			yellow.Printf("    ⚠ Error processing %s: %v\n", domain, err)
		}
	}

	return nil
}

// extractBaseDomain extracts the base domain from a subdomain
func extractBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	// Handle common multi-part TLDs
	multiPartTLDs := map[string]bool{
		"co.uk": true, "com.au": true, "co.nz": true, "co.jp": true,
		"com.br": true, "co.in": true, "org.uk": true, "net.au": true,
	}
	if len(parts) >= 3 {
		possibleMultiTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if multiPartTLDs[possibleMultiTLD] {
			return parts[len(parts)-3] + "." + possibleMultiTLD
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// processDomain runs the full recon pipeline on a domain (extracted from IP range)
// preDiscoveredSubs are subdomains already discovered from IP range (cero, hakrevdns, etc.)
func (r *Runner) processDomain(domain string, preDiscoveredSubs []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Printf("  ── Domain: %s ──\n\n", domain)

	// Create subdirectory for this domain
	domainDir := filepath.Join(r.out.BaseDir(), domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}
	domainOut := output.NewManager(domainDir)

	var subs, allSubs, alive, directHosts []string
	var subRes *subdomain.Result
	var historicRes *historic.Result

	// Start historic URL collection in parallel
	var historicDone chan struct{}
	if r.cfg.ShouldRunPhase("historic") || r.cfg.ShouldRunPhase("all") {
		historicDone = make(chan struct{})
		go func() {
			defer close(historicDone)
			hc := historic.NewCollector(r.cfg, r.c)
			if res, err := hc.Collect(domain, nil); err == nil {
				historicRes = res
			}
		}()
	}

	// Phase 1: Subdomain Enumeration
	if r.cfg.ShouldRunPhase("subdomain") || r.cfg.ShouldRunPhase("all") {
		fmt.Println("    [*] Subdomain enumeration...")
		e := subdomain.NewEnumerator(r.cfg, r.c)
		res, err := e.Enumerate(domain)
		if err != nil {
			return err
		}
		subRes = res
		subs = res.Subdomains
		allSubs = res.AllSubdomains

		// Merge pre-discovered subdomains from IP range (cero, hakrevdns, etc.)
		if len(preDiscoveredSubs) > 0 {
			seen := make(map[string]bool)
			for _, s := range allSubs {
				seen[s] = true
			}
			for _, s := range subs {
				seen[s] = true
			}
			newFromIPRange := 0
			for _, s := range preDiscoveredSubs {
				if !seen[s] {
					allSubs = append(allSubs, s)
					subs = append(subs, s) // Pre-discovered are already validated (from SSL certs)
					seen[s] = true
					newFromIPRange++
				}
			}
			if newFromIPRange > 0 {
				fmt.Printf("        ip_range_subs: %d (new: %d)\n", len(preDiscoveredSubs), newFromIPRange)
				subRes.Sources["ip_range"] = newFromIPRange
			}
		}

		// Wait for historic and merge
		if historicDone != nil {
			<-historicDone
			if historicRes != nil && len(historicRes.ExtractedSubdomains) > 0 {
				seen := make(map[string]bool)
				for _, s := range allSubs {
					seen[s] = true
				}
				for _, s := range historicRes.ExtractedSubdomains {
					if !seen[s] {
						allSubs = append(allSubs, s)
						seen[s] = true
					}
				}
			}
			historicDone = nil
		}

		subRes.Subdomains = subs
		subRes.AllSubdomains = allSubs
		subRes.Total = len(subs)
		subRes.TotalAll = len(allSubs)

		green.Printf("        Validated: %d subdomains\n", len(subs))
		domainOut.SaveSubdomains(subRes)
	}

	// Phase 2: WAF/CDN Detection (skip in passive mode)
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("waf") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		d := waf.NewDetector(r.cfg, r.c)
		if res, err := d.Detect(subs); err == nil {
			directHosts = res.DirectHosts
			green.Printf("        CDN: %d, Direct: %d\n", len(res.CDNHosts), len(directHosts))
			domainOut.SaveWAFResults(res)
		}
	}

	// Phase 3: Port Scanning (skip in passive mode)
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("ports") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		s := portscan.NewScanner(r.cfg, r.c)
		if res, err := s.Scan(subs); err == nil {
			alive = res.AliveHosts
			green.Printf("        Ports: %d, Alive: %d\n", res.TotalPorts, len(alive))
			domainOut.SavePortResults(res)
		}
	}

	// Phase 4: Takeover check
	if (r.cfg.ShouldRunPhase("takeover") || r.cfg.ShouldRunPhase("all")) && len(allSubs) > 0 {
		tc := takeover.NewChecker(r.cfg, r.c)
		if res, err := tc.Check(allSubs); err == nil {
			if len(res.Vulnerable) > 0 {
				yellow.Printf("        ⚠ %d potential takeovers!\n", len(res.Vulnerable))
			}
			domainOut.SaveTakeoverResults(res)
		}
	}

	// Phase 5: Historic URLs
	if historicRes != nil {
		if !r.cfg.PassiveMode && len(alive) > 0 {
			hc := historic.NewCollector(r.cfg, r.c)
			katanaURLs := hc.RunKatana(alive)
			if len(katanaURLs) > 0 {
				seen := make(map[string]bool)
				for _, u := range historicRes.URLs {
					seen[u] = true
				}
				for _, u := range katanaURLs {
					if !seen[u] {
						historicRes.URLs = append(historicRes.URLs, u)
						seen[u] = true
					}
				}
				historicRes.Sources["katana"] = len(katanaURLs)
				historicRes.Total = len(historicRes.URLs)
			}
		}
		green.Printf("        URLs: %d\n", len(historicRes.URLs))
		domainOut.SaveHistoricResults(historicRes)
	}

	// Phase 6: Tech Detection (skip in passive mode)
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("tech") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		td := techdetect.NewDetector(r.cfg, r.c)
		if res, err := td.Detect(subs); err == nil {
			green.Printf("        Tech: %d hosts, %d unique\n", res.Total, len(res.TechCount))
			domainOut.SaveTechResults(res)
		}
	}

	domainOut.SaveSummary(domain)
	fmt.Println()
	return nil
}

// sanitizeTargetName converts CIDR notation to safe directory name
func sanitizeTargetName(target string) string {
	// Replace / with _ for CIDR notation
	return filepath.Clean(replaceSlash(target))
}

func replaceSlash(s string) string {
	result := ""
	for _, c := range s {
		if c == '/' {
			result += "_"
		} else {
			result += string(c)
		}
	}
	return result
}

func (r *Runner) getTargets() ([]string, error) {
	if r.cfg.Target != "" {
		return []string{r.cfg.Target}, nil
	}
	if r.cfg.TargetFile == "" {
		return nil, fmt.Errorf("no target specified")
	}
	f, err := os.Open(r.cfg.TargetFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if t := s.Text(); t != "" {
			targets = append(targets, t)
		}
	}
	return targets, s.Err()
}
