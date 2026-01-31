package runner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/alerting"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/debug"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/jsanalysis"
	"github.com/rootsploit/reconator/internal/osint"
	"github.com/rootsploit/reconator/internal/output"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/report"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

type Runner struct {
	cfg *config.Config
	c   *tools.Checker
	out *output.Manager
}

// ProgressUpdate represents a scan progress update for WebSocket broadcasting
type ProgressUpdate struct {
	Phase    string `json:"phase"`
	Progress int    `json:"progress"` // 0-100
	Message  string `json:"message,omitempty"`
}

func New(cfg *config.Config) *Runner {
	return &Runner{cfg: cfg, c: tools.NewChecker()}
}

// RunWithContext runs the scan with context cancellation and progress updates
// This method is used by the web dashboard for live progress tracking
func (r *Runner) RunWithContext(ctx context.Context, progressCh chan<- ProgressUpdate) error {
	start := time.Now()

	if missing := r.c.GetMissingRequired(); len(missing) > 0 {
		progressCh <- ProgressUpdate{Phase: "init", Progress: 0, Message: fmt.Sprintf("Missing tools: %v", missing)}
	}

	targets, err := r.getTargets()
	if err != nil {
		return err
	}

	progressCh <- ProgressUpdate{Phase: "init", Progress: 0, Message: fmt.Sprintf("Starting reconnaissance for %d target(s)", len(targets))}

	// Process each target
	totalTargets := len(targets)
	for i, t := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			baseProgress := (i * 95 / totalTargets) // 0-95% range
			if err := r.processWithContext(ctx, t, progressCh, baseProgress); err != nil {
				progressCh <- ProgressUpdate{Phase: "error", Progress: baseProgress, Message: fmt.Sprintf("Error processing %s: %v", t, err)}
			}
		}
	}

	progressCh <- ProgressUpdate{Phase: "complete", Progress: 100, Message: fmt.Sprintf("Reconnaissance complete in %s", time.Since(start).Round(time.Second))}
	return nil
}

// processWithContext processes a single target with context support
func (r *Runner) processWithContext(ctx context.Context, target string, progressCh chan<- ProgressUpdate, baseProgress int) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check if target is ASN or IP range
	if iprange.IsASN(target) || iprange.IsIPTarget(target) {
		progressCh <- ProgressUpdate{Phase: "discovery", Progress: baseProgress, Message: fmt.Sprintf("Processing %s as IP/ASN target", target)}
		// For now, skip these in web dashboard (complex multi-domain processing)
		return nil
	}

	outDir := filepath.Join(r.cfg.OutputDir, target)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// Initialize output manager
	if r.cfg.EnableSQLite {
		var err error
		r.out, err = output.NewManagerWithSQLite(outDir)
		if err != nil {
			r.out = output.NewManager(outDir)
		}
	} else {
		r.out = output.NewManager(outDir)
	}
	defer r.out.Close()
	r.out.SetScanMeta(target, version.Version)

	var subs, allSubs, alive, directHosts []string
	var subRes *subdomain.Result
	var takeoverRes *takeover.Result
	var historicRes *historic.Result
	var wafRes *waf.Result
	var portsRes *portscan.Result

	// Phase 1: Subdomain Enumeration
	if r.cfg.ShouldRunPhase("subdomain") || r.cfg.ShouldRunPhase("all") {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		progressCh <- ProgressUpdate{Phase: "subdomain", Progress: baseProgress, Message: "Enumerating subdomains"}
		e := subdomain.NewEnumerator(r.cfg, r.c)
		res, err := e.Enumerate(target)
		if err != nil {
			return err
		}
		subRes = res
		subs = res.Subdomains
		allSubs = res.AllSubdomains
		r.out.SaveSubdomains(subRes)
		progressCh <- ProgressUpdate{Phase: "subdomain", Progress: baseProgress + 10, Message: fmt.Sprintf("Found %d subdomains", len(subs))}
	}

	// Phase 2: WAF Detection (parallel with takeover)
	var wg sync.WaitGroup
	var wafMu, takeoverMu, historicMu sync.Mutex

	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("waf") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := waf.NewDetector(r.cfg, r.c)
			if res, err := d.Detect(subs); err == nil {
				wafMu.Lock()
				wafRes = res
				directHosts = res.DirectHosts
				wafMu.Unlock()
				r.out.SaveWAFResults(res)
			}
		}()
	}

	// Phase 4: Takeover Check (parallel)
	if (r.cfg.ShouldRunPhase("takeover") || r.cfg.ShouldRunPhase("all")) && len(allSubs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc := takeover.NewChecker(r.cfg, r.c)
			if res, err := tc.Check(allSubs); err == nil {
				takeoverMu.Lock()
				takeoverRes = res
				takeoverMu.Unlock()
				r.out.SaveTakeoverResults(res)
			}
		}()
	}

	// Phase 5: Historic URLs (parallel)
	if r.cfg.ShouldRunPhase("historic") || r.cfg.ShouldRunPhase("all") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hc := historic.NewCollector(r.cfg, r.c)
			if res, err := hc.Collect(target, nil); err == nil {
				historicMu.Lock()
				historicRes = res
				historicMu.Unlock()
			}
		}()
	}

	progressCh <- ProgressUpdate{Phase: "parallel", Progress: baseProgress + 20, Message: "Running WAF/Takeover/Historic checks"}
	wg.Wait()

	// Save historic results
	if historicRes != nil {
		r.out.SaveHistoricResults(historicRes)
	}

	// Phase 3: Port Scanning
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("ports") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		progressCh <- ProgressUpdate{Phase: "ports", Progress: baseProgress + 30, Message: "Scanning ports"}
		s := portscan.NewScanner(r.cfg, r.c)
		if res, err := s.Scan(subs); err == nil {
			portsRes = res
			alive = res.AliveHosts
			r.out.SavePortResults(res)
			progressCh <- ProgressUpdate{Phase: "ports", Progress: baseProgress + 40, Message: fmt.Sprintf("Found %d open ports, %d alive hosts", res.TotalPorts, len(alive))}
		}
	}

	// Phase 6: Tech Detection
	var techRes *techdetect.Result
	// Run tech detection if not in passive mode OR if explicitly selected with passive mode
	if (r.cfg.ShouldRunPhase("tech") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		// Skip only if passive mode AND not explicitly requested
		skipTech := r.cfg.PassiveMode && !r.cfg.ShouldRunPhase("tech")
		if !skipTech {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			progressCh <- ProgressUpdate{Phase: "tech", Progress: baseProgress + 50, Message: "Detecting technologies"}
			td := techdetect.NewDetector(r.cfg, r.c)
			if res, err := td.Detect(subs); err == nil {
				techRes = res
				r.out.SaveTechResults(res)
			}
		}
	}

	// Phase 6b: Screenshots (run after tech detection)
	var screenshotRes *screenshot.Result
	// Use alive hosts if available (from port scan), otherwise use validated subdomains
	hostsForScreenshots := alive
	if len(hostsForScreenshots) == 0 && len(subs) > 0 {
		hostsForScreenshots = subs
	}

	if r.cfg.EnableScreenshots && len(hostsForScreenshots) > 0 {
		// Skip only if passive mode AND not explicitly requested
		skipScreenshots := r.cfg.PassiveMode && !r.cfg.ShouldRunPhase("screenshot")
		if !skipScreenshots {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			progressCh <- ProgressUpdate{Phase: "screenshot", Progress: baseProgress + 55, Message: "Capturing screenshots"}
			sc := screenshot.NewCapturer(r.cfg, r.c)

			// Use port-aware capture if we have portscan results
			var err error
			if portsRes != nil && len(portsRes.OpenPorts) > 0 {
				screenshotRes, err = sc.CaptureWithPorts(hostsForScreenshots, portsRes.OpenPorts, r.cfg.OutputDir)
			} else {
				screenshotRes, err = sc.CaptureWithResult(hostsForScreenshots)
			}

			if err == nil && screenshotRes != nil && !screenshotRes.Skipped {
				r.out.SaveScreenshotResults(screenshotRes)
				progressCh <- ProgressUpdate{Phase: "screenshot", Progress: baseProgress + 60, Message: fmt.Sprintf("Captured %d screenshots", screenshotRes.TotalCaptures)}
			}
		}
	}

	// Phase 7: Directory Bruteforce
	var dirRes *dirbrute.Result
	if !r.cfg.PassiveMode && !r.cfg.SkipDirBrute && (r.cfg.ShouldRunPhase("dirbrute") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		progressCh <- ProgressUpdate{Phase: "dirbrute", Progress: baseProgress + 65, Message: "Running directory bruteforce"}
		hostsToScan, _ := filterNonWAFHosts(alive, directHosts)
		if len(hostsToScan) > 0 {
			ds := dirbrute.NewScanner(r.cfg, r.c)
			if res, err := ds.Scan(hostsToScan); err == nil {
				dirRes = res
				r.out.SaveDirBruteResults(res)
			}
		}
	}

	// Phase 8: Vulnerability Scanning
	var vulnRes *vulnscan.Result
	if !r.cfg.PassiveMode && !r.cfg.SkipVulnScan && (r.cfg.ShouldRunPhase("vulnscan") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		progressCh <- ProgressUpdate{Phase: "vulnscan", Progress: baseProgress + 75, Message: "Scanning for vulnerabilities"}
		vs := vulnscan.NewScanner(r.cfg, r.c)
		if res, err := vs.Scan(alive, nil); err == nil {
			vulnRes = res
			r.out.SaveVulnResults(res)
			progressCh <- ProgressUpdate{Phase: "vulnscan", Progress: baseProgress + 85, Message: fmt.Sprintf("Found %d vulnerabilities", len(res.Vulnerabilities))}
		}
	}

	// Generate HTML Report
	if r.cfg.GenerateReport {
		progressCh <- ProgressUpdate{Phase: "report", Progress: baseProgress + 90, Message: "Generating report"}
		reportData := &report.Data{
			Target:     target,
			Version:    version.Version,
			Date:       time.Now().Format(time.RFC1123),
			Duration:   time.Since(time.Now()).Round(time.Second).String(),
			Subdomain:  subRes,
			WAF:        wafRes,
			Ports:      portsRes,
			Takeover:   takeoverRes,
			Historic:   historicRes,
			Tech:       techRes,
			Screenshot: screenshotRes,
			DirBrute:   dirRes,
			VulnScan:   vulnRes,
		}
		report.Generate(reportData, outDir)
	}

	r.out.SaveSummary(target)

	// Suppress unused variable warnings
	_ = baseProgress

	return nil
}

func (r *Runner) Run() error {
	start := time.Now()
	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	// Deprecation Warning
	red.Println("\n[DEPRECATED] You are using the legacy sequential runner.")
	red.Println("             This runner will be removed in v2.2. Please migrate to the new pipeline executor.")
	red.Println("             Run without '--legacy' flag to use the new default pipeline.")
	fmt.Println()

	// Enable debug logging if requested
	if r.cfg.Debug {
		debug.Enable()
		cyan.Println("[DEBUG MODE ENABLED] Detailed timing logs will be shown")
		fmt.Println()
	}

	if missing := r.c.GetMissingRequired(); len(missing) > 0 {
		yellow.Printf("\n⚠ Missing required tools: %v\n", missing)
		fmt.Println("  Run 'reconator install' to install them")
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

	// Initialize output manager (with SQLite if enabled)
	if r.cfg.EnableSQLite {
		var err error
		r.out, err = output.NewManagerWithSQLite(outDir)
		if err != nil {
			// Non-fatal, warning already printed by NewManagerWithSQLite
			r.out = output.NewManager(outDir)
		}
	} else {
		r.out = output.NewManager(outDir)
	}
	defer r.out.Close()
	r.out.SetScanMeta(target, version.Version)

	var subs, allSubs, alive, directHosts []string
	var subRes *subdomain.Result
	var takeoverRes *takeover.Result
	var historicRes *historic.Result
	var wafRes *waf.Result
	var portsRes *portscan.Result
	var osintRes interface{}
	var graphqlRes *vulnscan.GraphQLResult

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 1: Subdomain Enumeration (foundation for all other phases)
	// ═══════════════════════════════════════════════════════════════════════
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

		green.Printf("    ┌─ Summary ─────────────────────────────────\n")
		for source, count := range subRes.Sources {
			green.Printf("    │ %-18s %d\n", source+":", count)
		}
		green.Printf("    ├─────────────────────────────────────────\n")
		green.Printf("    │ All discovered:    %d\n", subRes.TotalAll)
		green.Printf("    └─ Validated alive:  %d\n\n", len(subs))
		r.out.SaveSubdomains(subRes)
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 2-5: WAF + Takeover + Historic (run concurrently)
	// These phases only depend on subdomains, not on each other
	// CRITICAL: WAF must complete before Ports can start
	// ═══════════════════════════════════════════════════════════════════════
	cyan.Println("[Phase 2/4/5] WAF Detection + Takeover + Historic (parallel)")
	fmt.Println("───────────────────────────────────────────────────")

	var wg sync.WaitGroup
	var wafMu, takeoverMu, historicMu, osintMu sync.Mutex

	// OSINT (parallel)
	if r.cfg.EnableOSINT && (r.cfg.ShouldRunPhase("osint") || r.cfg.ShouldRunPhase("all")) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			phaseStart := debug.LogPhaseStart("OSINT")
			osc := osint.NewScanner(r.cfg, r.c)
			if res, err := osc.Scan(target); err == nil {
				osintMu.Lock()
				osintRes = res
				osintMu.Unlock()
			}
			debug.LogPhaseEnd("OSINT", phaseStart)
		}()
	}

	// WAF Detection (parallel)
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("waf") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			phaseStart := debug.LogPhaseStart("WAF Detection")
			d := waf.NewDetector(r.cfg, r.c)
			if res, err := d.Detect(subs); err == nil {
				wafMu.Lock()
				wafRes = res
				directHosts = res.DirectHosts
				wafMu.Unlock()
			}
			debug.LogPhaseEnd("WAF Detection", phaseStart)
		}()
	}

	// Takeover Check (parallel)
	if (r.cfg.ShouldRunPhase("takeover") || r.cfg.ShouldRunPhase("all")) && len(allSubs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			phaseStart := debug.LogPhaseStart("Takeover Check")
			tc := takeover.NewChecker(r.cfg, r.c)
			if res, err := tc.Check(allSubs); err == nil {
				takeoverMu.Lock()
				takeoverRes = res
				takeoverMu.Unlock()
			}
			debug.LogPhaseEnd("Takeover Check", phaseStart)
		}()
	}

	// Historic URL Collection (parallel)
	if r.cfg.ShouldRunPhase("historic") || r.cfg.ShouldRunPhase("all") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			phaseStart := debug.LogPhaseStart("Historic Collection")
			hc := historic.NewCollector(r.cfg, r.c)
			if res, err := hc.Collect(target, nil); err == nil {
				historicMu.Lock()
				historicRes = res
				// Merge extracted subdomains into allSubs
				if len(res.ExtractedSubdomains) > 0 {
					seen := make(map[string]bool)
					for _, s := range allSubs {
						seen[s] = true
					}
					for _, s := range res.ExtractedSubdomains {
						if !seen[s] {
							allSubs = append(allSubs, s)
							seen[s] = true
						}
					}
				}
				historicMu.Unlock()
			}
			debug.LogPhaseEnd("Historic Collection", phaseStart)
		}()
	}

	// Wait for Phase 2/4/5 to complete
	wg.Wait()

	// Print Phase 2/4/5 results
	if wafRes != nil {
		green.Printf("    WAF:      CDN: %d, Direct: %d\n", len(wafRes.CDNHosts), len(wafRes.DirectHosts))
		r.out.SaveWAFResults(wafRes)
	} else if r.cfg.PassiveMode {
		yellow.Println("    WAF:      SKIPPED (passive mode)")
	}

	if takeoverRes != nil {
		if len(takeoverRes.Vulnerable) > 0 {
			color.New(color.FgRed, color.Bold).Printf("    Takeover: ⚠ %d potentially vulnerable!\n", len(takeoverRes.Vulnerable))
		} else {
			green.Println("    Takeover: No vulnerabilities found")
		}
		r.out.SaveTakeoverResults(takeoverRes)
	}

	if historicRes != nil {
		green.Printf("    Historic: %d URLs, %d extracted subdomains\n", len(historicRes.URLs), len(historicRes.ExtractedSubdomains))
	}
	if osintRes != nil {
		green.Printf("    OSINT:    Dorks generated\n")
	}
	fmt.Println()

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 3: Port Scanning (MUST wait for WAF to complete)
	// Only scan non-WAF hosts to avoid triggering rate limits
	// ═══════════════════════════════════════════════════════════════════════
	if !r.cfg.PassiveMode && (r.cfg.ShouldRunPhase("ports") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		cyan.Println("[Phase 3] Port Scanning + TLS")
		fmt.Println("─────────────────────────────────────────────────")

		s := portscan.NewScanner(r.cfg, r.c)
		if res, err := s.Scan(subs); err == nil {
			portsRes = res
			alive = res.AliveHosts
			green.Printf("    Ports: %d, Alive: %d, TLS: %d\n\n", res.TotalPorts, len(alive), len(res.TLSInfo))
			r.out.SavePortResults(res)
		}
	} else if r.cfg.PassiveMode {
		yellow.Println("[Phase 3] Port Scanning... SKIPPED (passive mode)")
		fmt.Println()
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Screenshots (run early, right after we have live hosts and ports)
	// This runs in parallel with katana crawl for efficiency
	// ═══════════════════════════════════════════════════════════════════════
	var screenshotRes *screenshot.Result
	var screenshotWg sync.WaitGroup
	var screenshotMu sync.Mutex

	if r.cfg.EnableScreenshots && !r.cfg.PassiveMode && len(alive) > 0 {
		screenshotWg.Add(1)
		go func() {
			defer screenshotWg.Done()
			cyan.Println("[Visual Recon] Screenshots (parallel with crawl)")
			fmt.Println("───────────────────────────────────────────────────")
			sc := screenshot.NewCapturer(r.cfg, r.c)

			var res *screenshot.Result
			var err error

			// Use port-aware capture if we have portscan results
			if portsRes != nil && len(portsRes.OpenPorts) > 0 {
				res, err = sc.CaptureWithPorts(alive, portsRes.OpenPorts, r.cfg.OutputDir)
			} else {
				res, err = sc.CaptureWithResult(alive)
			}

			if err != nil {
				yellow.Printf("    ⚠ Screenshot capture failed: %v\n", err)
			} else if res != nil && !res.Skipped {
				green.Printf("    Captured: %d screenshots\n", res.TotalCaptures)
				if len(res.Clusters) > 0 {
					green.Printf("    Clusters: %d groups found\n", len(res.Clusters))
				}
				screenshotMu.Lock()
				screenshotRes = res
				screenshotMu.Unlock()
				r.out.SaveScreenshotResults(res)
			}
			fmt.Println()
		}()
	}

	// Run katana now that we have alive hosts (part of historic phase)
	if historicRes != nil && !r.cfg.PassiveMode && len(alive) > 0 {
		hc := historic.NewCollector(r.cfg, r.c)
		katanaURLs := hc.RunKatana(alive)
		if len(katanaURLs) > 0 {
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
			green.Printf("    Katana crawl: %d URLs (new: %d)\n\n", len(katanaURLs), newCount)
		}
		r.out.SaveHistoricResults(historicRes)
	} else if historicRes != nil {
		r.out.SaveHistoricResults(historicRes)
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 6/7: Tech Detection + Directory Bruteforce (parallel)
	// Both depend on alive hosts from port scanning
	// ═══════════════════════════════════════════════════════════════════════
	var techRes *techdetect.Result
	var dirRes *dirbrute.Result

	if !r.cfg.PassiveMode && len(alive) > 0 {
		cyan.Println("[Phase 6/7] Tech Detection + DirBrute (parallel)")
		fmt.Println("───────────────────────────────────────────────────")

		var wgB sync.WaitGroup
		var techMu, dirMu, graphqlMu sync.Mutex

		// GraphQL Detection (parallel)
		if r.cfg.EnableGraphQL && (r.cfg.ShouldRunPhase("graphql") || r.cfg.ShouldRunPhase("all")) {
			wgB.Add(1)
			go func() {
				defer wgB.Done()
				phaseStart := debug.LogPhaseStart("GraphQL Detection")
				gs := vulnscan.NewGraphQLScanner(r.cfg, r.c)
				if res, err := gs.ScanGraphQL(context.Background(), alive); err == nil {
					graphqlMu.Lock()
					graphqlRes = res
					graphqlMu.Unlock()
					// Save immediately
					res.SaveGraphQLResults(filepath.Join(outDir, "graphql"))
				}
				debug.LogPhaseEnd("GraphQL Detection", phaseStart)
			}()
		}

		// Tech Detection (parallel)
		if r.cfg.ShouldRunPhase("tech") || r.cfg.ShouldRunPhase("all") {
			wgB.Add(1)
			go func() {
				defer wgB.Done()
				phaseStart := debug.LogPhaseStart("Tech Detection")
				td := techdetect.NewDetector(r.cfg, r.c)
				if res, err := td.Detect(subs); err == nil {
					techMu.Lock()
					techRes = res
					techMu.Unlock()
				}
				debug.LogPhaseEnd("Tech Detection", phaseStart)
			}()
		}

		// Directory Bruteforce (parallel, only on non-WAF hosts)
		if !r.cfg.SkipDirBrute && (r.cfg.ShouldRunPhase("dirbrute") || r.cfg.ShouldRunPhase("all")) {
			wgB.Add(1)
			go func() {
				defer wgB.Done()
				phaseStart := debug.LogPhaseStart("Directory Bruteforce")

				// Filter out WAF/CDN protected hosts
				hostsToScan, skippedCount := filterNonWAFHosts(alive, directHosts)
				if skippedCount > 0 {
					yellow.Printf("        [!] Skipping %d WAF/CDN protected host(s)\n", skippedCount)
				}

				if len(hostsToScan) > 0 {
					ds := dirbrute.NewScanner(r.cfg, r.c)
					if res, err := ds.Scan(hostsToScan); err == nil {
						dirMu.Lock()
						dirRes = res
						dirMu.Unlock()
					}
				}
				debug.LogPhaseEnd("Directory Bruteforce", phaseStart)
			}()
		}

		// Wait for Group B to complete
		wgB.Wait()

		// Print Group B results
		if techRes != nil {
			green.Printf("    Tech:     %d hosts, %d unique technologies\n", techRes.Total, len(techRes.TechCount))
			r.out.SaveTechResults(techRes)
		}
		if dirRes != nil {
			green.Printf("    DirBrute: %d discoveries across %d hosts\n", len(dirRes.Discoveries), len(dirRes.ByHost))
			r.out.SaveDirBruteResults(dirRes)
		} else if r.cfg.SkipDirBrute {
			yellow.Println("    DirBrute: SKIPPED")
		}
		if graphqlRes != nil {
			green.Printf("    GraphQL:  %d endpoints (%d introspection enabled)\n", graphqlRes.TotalFound, graphqlRes.Introspectable)
		}
		fmt.Println()
	} else if r.cfg.PassiveMode {
		yellow.Println("[Phase 6/7] Tech + DirBrute... SKIPPED (passive mode)")
		fmt.Println()
	}

	// Categorize URLs from historic phase for targeted scanning
	var categorizedURLs *historic.CategorizedURLs
	if historicRes != nil && len(historicRes.URLs) > 0 {
		hc := historic.NewCollector(r.cfg, r.c)
		cat := hc.CategorizeURLs(historicRes.URLs)
		categorizedURLs = &cat
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 7b: JavaScript Deep Analysis (parallel-safe, uses categorized URLs)
	// ═══════════════════════════════════════════════════════════════════════
	var jsRes *jsanalysis.Result
	if !r.cfg.PassiveMode && categorizedURLs != nil && len(categorizedURLs.JSFiles) > 0 {
		cyan.Println("[Phase 7b] JavaScript Deep Analysis")
		fmt.Println("─────────────────────────────────────────────────")
		analyzer := jsanalysis.NewAnalyzer(r.cfg, r.c)
		if res, err := analyzer.Analyze(context.Background(), categorizedURLs.JSFiles); err == nil {
			jsRes = res
			green.Printf("    Endpoints: %d, DOM XSS Sinks: %d, Secrets: %d\n\n",
				len(res.Endpoints), len(res.DOMXSSSinks), len(res.Secrets))
			r.out.SaveJSAnalysisResults(res)
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 8: Vulnerability Scanning (needs all preceding data)
	// Dependencies: ports, tech, historic, dirbrute
	// ═══════════════════════════════════════════════════════════════════════
	var vulnRes *vulnscan.Result
	if !r.cfg.PassiveMode && !r.cfg.SkipVulnScan && (r.cfg.ShouldRunPhase("vulnscan") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		cyan.Println("[Phase 8] Vulnerability Scanning")
		fmt.Println("─────────────────────────────────────────────────")
		vs := vulnscan.NewScanner(r.cfg, r.c)

		// BB-10: Use CDN-aware scanning if port results contain CDN data
		if portsRes != nil && (len(portsRes.NonCDNHosts) > 0 || len(portsRes.CDNHosts) > 0) {
			cdnInput := &vulnscan.CDNInput{
				NonCDNHosts: portsRes.NonCDNHosts,
				CDNHosts:    portsRes.CDNHosts,
			}

			// Tech-aware input if available
			var techInput *vulnscan.TechInput
			if techRes != nil {
				techInput = &vulnscan.TechInput{
					TechByHost: techRes.TechByHost,
					TechCount:  techRes.TechCount,
				}
			}

			if res, err := vs.ScanWithCDNPriority(alive, categorizedURLs, techInput, cdnInput); err == nil {
				vulnRes = res
				green.Printf("    Vulnerabilities: %d (Critical: %d, High: %d)\n\n",
					len(res.Vulnerabilities), res.BySeverity["critical"], res.BySeverity["high"])
				r.out.SaveVulnResults(res)
			}
		} else {
			// Fallback to standard scanning if no CDN data
			if res, err := vs.Scan(alive, categorizedURLs); err == nil {
				vulnRes = res
				green.Printf("    Vulnerabilities: %d (Critical: %d, High: %d)\n\n",
					len(res.Vulnerabilities), res.BySeverity["critical"], res.BySeverity["high"])
				r.out.SaveVulnResults(res)
			}
		}
	} else if r.cfg.PassiveMode || r.cfg.SkipVulnScan {
		yellow.Println("[Phase 8] Vulnerability Scanning... SKIPPED")
		fmt.Println()
	}

	// Wait for screenshot capture to complete (started in parallel earlier)
	screenshotWg.Wait()

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 10: AI-Guided Scanning (final analysis phase)
	// ═══════════════════════════════════════════════════════════════════════
	var aiRes *aiguided.Result
	hasAIKeys := r.cfg.OpenAIKey != "" || r.cfg.ClaudeKey != "" || r.cfg.GeminiKey != ""
	if !r.cfg.PassiveMode && !r.cfg.SkipAIGuided && hasAIKeys && (r.cfg.ShouldRunPhase("aiguided") || r.cfg.ShouldRunPhase("all")) && len(alive) > 0 {
		cyan.Println("[Phase 10] AI-Guided Scanning")
		fmt.Println("───────────────────────────────────────────────────")

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
		yellow.Println("[Phase 10] AI-Guided Scanning... SKIPPED (no AI keys or disabled)")
		fmt.Println()
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Post-scan: Alerting (send notifications if enabled)
	// ═══════════════════════════════════════════════════════════════════════
	if r.cfg.EnableNotify && r.c.IsInstalled("notify") {
		cyan.Println("[Alerting] Sending Notifications")
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

	// Generate HTML Report
	if r.cfg.GenerateReport {
		reportData := &report.Data{
			Target:     target,
			Version:    version.Version,
			Date:       time.Now().Format(time.RFC1123),
			Duration:   time.Since(start).Round(time.Second).String(),
			Subdomain:  subRes,
			WAF:        wafRes,
			Ports:      portsRes,
			Takeover:   takeoverRes,
			Historic:   historicRes,
			Tech:       techRes,
			DirBrute:   dirRes,
			VulnScan:   vulnRes,
			AIGuided:   aiRes,
			OSINT:      osintRes,
			Screenshot: screenshotRes,
			JSAnalysis: jsRes,
		}

		if err := report.Generate(reportData, outDir); err != nil {
			yellow.Printf("⚠ Failed to generate report: %v\n", err)
		} else {
			green.Printf("    Report generated: report_%s.html\n", target)
		}
	}

	// Print timing summary
	green.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	green.Printf("  Target %s completed in %s\n", target, time.Since(start).Round(time.Second))
	green.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	r.out.SaveSummary(target)

	// Update scan status in SQLite if enabled
	if r.out.HasSQLite() {
		r.out.SQLiteDB().UpdateScanStatus(context.Background(), r.out.ScanID(), "completed")
	}

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

	// Initialize output manager (with SQLite if enabled)
	if r.cfg.EnableSQLite {
		var err error
		r.out, err = output.NewManagerWithSQLite(outDir)
		if err != nil {
			r.out = output.NewManager(outDir)
		}
	} else {
		r.out = output.NewManager(outDir)
	}
	defer r.out.Close()
	r.out.SetScanMeta(displayASN, version.Version)

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

	// Initialize output manager (with SQLite if enabled)
	if r.cfg.EnableSQLite {
		var err error
		r.out, err = output.NewManagerWithSQLite(outDir)
		if err != nil {
			r.out = output.NewManager(outDir)
		}
	} else {
		r.out = output.NewManager(outDir)
	}
	defer r.out.Close()
	r.out.SetScanMeta(target, version.Version)

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

	// Initialize output manager (with SQLite if enabled)
	var domainOut *output.Manager
	if r.cfg.EnableSQLite {
		var err error
		domainOut, err = output.NewManagerWithSQLite(domainDir)
		if err != nil {
			domainOut = output.NewManager(domainDir)
		}
	} else {
		domainOut = output.NewManager(domainDir)
	}
	defer domainOut.Close()

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
	return strings.ReplaceAll(s, "/", "_")
}

// mergeUnique merges two string slices and returns unique elements
func mergeUnique(existing, new []string) []string {
	seen := make(map[string]bool, len(existing)+len(new))
	result := make([]string, 0, len(existing)+len(new))

	for _, s := range existing {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range new {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
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

// extractHostFromURL extracts the hostname from a URL (strips scheme and port)
func extractHostFromURL(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	// Remove port if present
	if idx := strings.Index(urlStr, ":"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	// Remove path if present
	if idx := strings.Index(urlStr, "/"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	return urlStr
}

// filterNonWAFHosts filters alive URLs to only include hosts not behind WAF/CDN
func filterNonWAFHosts(aliveURLs []string, directHosts []string) (filtered []string, skipped int) {
	if len(directHosts) == 0 {
		// No WAF detection results, return all hosts
		return aliveURLs, 0
	}

	directSet := make(map[string]bool)
	for _, h := range directHosts {
		directSet[h] = true
	}

	for _, url := range aliveURLs {
		host := extractHostFromURL(url)
		if directSet[host] {
			filtered = append(filtered, url)
		} else {
			skipped++
		}
	}
	return filtered, skipped
}
