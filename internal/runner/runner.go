package runner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/output"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/tools"
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
	return nil
}

func (r *Runner) process(target string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	cyan.Printf("  Target: %s", target)
	if r.cfg.StealthMode {
		cyan.Printf(" [STEALTH]")
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

	// Phase 2: WAF/CDN Detection
	if (r.cfg.ShouldRunPhase("waf") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		cyan.Println("[Phase 2] WAF/CDN Detection")
		fmt.Println("─────────────────────────────────────────────────")
		d := waf.NewDetector(r.cfg, r.c)
		if res, err := d.Detect(subs); err == nil {
			directHosts = res.DirectHosts
			green.Printf("    CDN: %d, Direct: %d\n\n", len(res.CDNHosts), len(directHosts))
			r.out.SaveWAFResults(res)
		}
	}

	// Phase 3: Port Scanning + TLS
	if (r.cfg.ShouldRunPhase("ports") || r.cfg.ShouldRunPhase("all")) && len(subs) > 0 {
		cyan.Println("[Phase 3] Port Scanning + TLS")
		fmt.Println("─────────────────────────────────────────────────")

		scanTargets := subs
		if r.cfg.StealthMode && len(directHosts) > 0 {
			scanTargets = directHosts
			yellow.Printf("    [STEALTH] Scanning only %d non-WAF hosts\n", len(scanTargets))
		}

		s := portscan.NewScanner(r.cfg, r.c)
		if res, err := s.Scan(scanTargets); err == nil {
			alive = res.AliveHosts
			green.Printf("    Ports: %d, Alive: %d, TLS: %d\n\n", res.TotalPorts, len(alive), len(res.TLSInfo))
			r.out.SavePortResults(res)
		}
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
	if historicRes != nil {
		cyan.Println("[Phase 5] Historic URL Collection")
		fmt.Println("─────────────────────────────────────────────────")
		green.Printf("    ┌─ Summary ─────────────────────────────────\n")
		for source, count := range historicRes.Sources {
			green.Printf("    │ %-15s %d URLs\n", source+":", count)
		}
		green.Printf("    │ %-15s %d subdomains\n", "extracted:", len(historicRes.ExtractedSubdomains))
		green.Printf("    └─ Total: %d unique URLs\n\n", len(historicRes.URLs))
		r.out.SaveHistoricResults(historicRes)
	}

	r.out.SaveSummary(target)
	return nil
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
