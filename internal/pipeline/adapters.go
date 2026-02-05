package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/jsanalysis"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/trufflehog"
	"github.com/rootsploit/reconator/internal/vhost"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// RegisterAllAdapters registers all phase adapters with the executor
func RegisterAllAdapters(exec *Executor, cfg *config.Config, checker *tools.Checker) {
	exec.Register(NewIPRangeAdapter(cfg, checker))
	exec.Register(NewSubdomainAdapter(cfg, checker))
	exec.Register(NewWAFAdapter(cfg, checker))
	exec.Register(NewPortsAdapter(cfg, checker))
	exec.Register(NewVHostAdapter(cfg, checker))
	exec.Register(NewTakeoverAdapter(cfg, checker))
	exec.Register(NewHistoricAdapter(cfg, checker))
	exec.Register(NewTechAdapter(cfg, checker))
	exec.Register(NewJSAnalysisAdapter(cfg, checker))
	exec.Register(NewTruffleHogAdapter(cfg, checker))
	exec.Register(NewSecHeadersAdapter(cfg, checker))
	exec.Register(NewDirBruteAdapter(cfg, checker))
	exec.Register(NewVulnScanAdapter(cfg, checker))
	exec.Register(NewScreenshotAdapter(cfg, checker))
	exec.Register(NewAIGuidedAdapter(cfg, checker))
}

// SubdomainAdapter wraps subdomain.Enumerator as a PhaseExecutor
type SubdomainAdapter struct {
	enumerator *subdomain.Enumerator
	cfg        *config.Config
}

func NewSubdomainAdapter(cfg *config.Config, checker *tools.Checker) *SubdomainAdapter {
	return &SubdomainAdapter{
		enumerator: subdomain.NewEnumerator(cfg, checker),
		cfg:        cfg,
	}
}

func (a *SubdomainAdapter) Name() Phase { return PhaseSubdomain }

func (a *SubdomainAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseSubdomain,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Set up verbose step reporter if enabled
	if a.cfg.VerboseProgress {
		a.enumerator.SetReporter(subdomain.NewVerboseStepReporter())
	}

	// For ASN/IP targets, enumerate TLDs discovered by IPRange phase
	// instead of the raw target (which would fail - can't enumerate AS401405)
	if input.HasIPRangeData() && iprange.IsASN(input.Target) {
		return a.enumerateIPRangeTLDs(ctx, input, result, start)
	}

	res, err := a.enumerator.Enumerate(input.Target)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// enumerateIPRangeTLDs enumerates subdomains for TLDs discovered from ASN/IP targets
func (a *SubdomainAdapter) enumerateIPRangeTLDs(ctx context.Context, input *PhaseInput, result *PhaseResult, start time.Time) (*PhaseResult, error) {
	tlds := input.IPRangeBaseDomains
	if len(tlds) == 0 {
		// Extract TLDs from domains if base_domains is empty
		tlds = iprange.ExtractTLDs(input.IPRangeDomains)
	}

	if len(tlds) == 0 {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	fmt.Printf("    [*] Enumerating subdomains for %d TLDs from IP range discovery\n", len(tlds))

	// Aggregate results from all TLDs
	aggregated := &subdomain.Result{
		Domain:  input.Target,
		Sources: make(map[string]int),
	}

	for _, tld := range tlds {
		fmt.Printf("        [*] Enumerating: %s\n", tld)
		res, err := a.enumerator.Enumerate(tld)
		if err != nil {
			fmt.Printf("        [!] Error enumerating %s: %v\n", tld, err)
			continue
		}

		// Merge results
		aggregated.Subdomains = append(aggregated.Subdomains, res.Subdomains...)
		aggregated.AllSubdomains = append(aggregated.AllSubdomains, res.AllSubdomains...)
		for source, count := range res.Sources {
			aggregated.Sources[source] += count
		}
	}

	// Deduplicate
	aggregated.Subdomains = uniqueStrings(aggregated.Subdomains)
	aggregated.AllSubdomains = uniqueStrings(aggregated.AllSubdomains)

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)
	result.Status = StatusCompleted
	result.Data = aggregated
	return result, nil
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// WAFAdapter wraps waf.Detector as a PhaseExecutor
type WAFAdapter struct {
	detector *waf.Detector
}

func NewWAFAdapter(cfg *config.Config, checker *tools.Checker) *WAFAdapter {
	return &WAFAdapter{
		detector: waf.NewDetector(cfg, checker),
	}
}

func (a *WAFAdapter) Name() Phase { return PhaseWAF }

func (a *WAFAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseWAF,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Use httpx-validated AliveHosts for CDN/WAF detection
	// cdncheck works better with confirmed live hosts
	if !input.HasAliveHosts() {
		fmt.Printf("        [WAFAdapter] Skipping: no alive hosts (AliveHosts=%d)\n", len(input.AliveHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}
	fmt.Printf("        [WAFAdapter] Starting CDN/WAF detection with %d alive hosts\n", len(input.AliveHosts))

	res, err := a.detector.Detect(input.AliveHosts)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// PortsAdapter wraps portscan.Scanner as a PhaseExecutor
type PortsAdapter struct {
	scanner *portscan.Scanner
}

func NewPortsAdapter(cfg *config.Config, checker *tools.Checker) *PortsAdapter {
	return &PortsAdapter{
		scanner: portscan.NewScanner(cfg, checker),
	}
}

func (a *PortsAdapter) Name() Phase { return PhasePorts }

func (a *PortsAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhasePorts,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasSubdomains() {
		fmt.Printf("        [PortsAdapter] Skipping: no subdomains loaded (Subdomains=%d, AllSubdomains=%d)\n",
			len(input.Subdomains), len(input.AllSubdomains))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Log the subdomain sources
	fmt.Printf("        [PortsAdapter] Starting scan with %d subdomains", len(input.Subdomains))
	if len(input.ExtractedSubdomains) > 0 {
		fmt.Printf(" (includes %d historic-extracted)", len(input.ExtractedSubdomains))
	}
	fmt.Println()

	// Save the merged subdomains list to file for visibility and downstream use
	if input.Config != nil && len(input.ExtractedSubdomains) > 0 {
		mergedPath := filepath.Join(input.Config.OutputDir, input.Target, "1-subdomains", "merged_subdomains.txt")
		if f, err := os.Create(mergedPath); err == nil {
			for _, s := range input.Subdomains {
				f.WriteString(s + "\n")
			}
			f.Close()
			fmt.Printf("        [PortsAdapter] Saved merged subdomains to: %s\n", mergedPath)
		}
	}

	res, err := a.scanner.Scan(input.Subdomains)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// VHostAdapter wraps vhost.Discoverer as a PhaseExecutor
type VHostAdapter struct {
	discoverer *vhost.Discoverer
}

func NewVHostAdapter(cfg *config.Config, checker *tools.Checker) *VHostAdapter {
	return &VHostAdapter{
		discoverer: vhost.NewDiscoverer(cfg, checker),
	}
}

func (a *VHostAdapter) Name() Phase { return PhaseVHost }

func (a *VHostAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseVHost,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasAliveHosts() {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Use direct (non-CDN) hosts for VHost discovery - CDN hosts won't respond to vhost fuzzing
	hosts := input.GetHostsForScanning()
	if len(hosts) == 0 {
		fmt.Printf("        [VHostAdapter] Skipping: all hosts are CDN-protected (CDN=%d, Direct=%d)\n",
			len(input.CDNHosts), len(input.DirectHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	fmt.Printf("        [VHostAdapter] Using %d direct hosts (skipping %d CDN-protected)\n",
		len(hosts), len(input.CDNHosts))

	// Create a phase-level timeout context (VHost is prone to hanging)
	vhostTimeout := 10 * time.Minute // Default 10 minutes
	if input.Config != nil && input.Config.VHostTimeout > 0 {
		vhostTimeout = time.Duration(input.Config.VHostTimeout) * time.Minute
	}
	phaseCtx, cancel := context.WithTimeout(ctx, vhostTimeout)
	defer cancel()

	// Use context-aware discovery
	res, err := a.discoverer.DiscoverWithContext(phaseCtx, hosts, input.Target)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		// Check if it was a timeout/cancellation
		if phaseCtx.Err() == context.DeadlineExceeded {
			fmt.Printf("        [VHostAdapter] Phase timeout after %v\n", vhostTimeout)
			result.Status = StatusCompleted // Still mark as completed with partial results
			result.Data = res
			return result, nil
		}
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// TakeoverAdapter wraps takeover.Checker as a PhaseExecutor
type TakeoverAdapter struct {
	checker *takeover.Checker
}

func NewTakeoverAdapter(cfg *config.Config, checker *tools.Checker) *TakeoverAdapter {
	return &TakeoverAdapter{
		checker: takeover.NewChecker(cfg, checker),
	}
}

func (a *TakeoverAdapter) Name() Phase { return PhaseTakeover }

func (a *TakeoverAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseTakeover,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Use only dnsx-validated Subdomains for takeover check
	// AllSubdomains includes unvalidated permutations which waste time
	subs := input.Subdomains

	if len(subs) == 0 {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	res, err := a.checker.Check(subs)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// HistoricAdapter wraps historic.Collector as a PhaseExecutor
type HistoricAdapter struct {
	collector *historic.Collector
}

func NewHistoricAdapter(cfg *config.Config, checker *tools.Checker) *HistoricAdapter {
	return &HistoricAdapter{
		collector: historic.NewCollector(cfg, checker),
	}
}

func (a *HistoricAdapter) Name() Phase { return PhaseHistoric }

func (a *HistoricAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseHistoric,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Historic phase now runs at Level 0 (parallel with Subdomain enumeration)
	// Passive tools (gau, waybackurls, urlfinder, waymore) only need root domain
	// katana (active crawling) is skipped when aliveHosts is empty - that's expected
	// This saves 2-3 minutes by not waiting for subdomain enumeration

	// Use alive hosts if available (from Ports phase on re-runs), otherwise empty
	aliveHosts := input.AliveHosts
	if aliveHosts == nil {
		aliveHosts = []string{} // Passive tools only - katana will be skipped
	}

	res, err := a.collector.Collect(input.Target, aliveHosts)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// TechAdapter wraps techdetect.Detector as a PhaseExecutor
type TechAdapter struct {
	detector *techdetect.Detector
}

func NewTechAdapter(cfg *config.Config, checker *tools.Checker) *TechAdapter {
	return &TechAdapter{
		detector: techdetect.NewDetector(cfg, checker),
	}
}

func (a *TechAdapter) Name() Phase { return PhaseTech }

func (a *TechAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseTech,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasAliveHosts() {
		fmt.Printf("        [TechAdapter] Skipping: no alive hosts (AliveHosts=%d)\n", len(input.AliveHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}
	fmt.Printf("        [TechAdapter] Starting detection with %d alive hosts\n", len(input.AliveHosts))

	res, err := a.detector.Detect(input.AliveHosts)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// SecHeadersAdapter wraps secheaders.Checker as a PhaseExecutor
type SecHeadersAdapter struct {
	checker *secheaders.Checker
	cfg     *config.Config
}

func NewSecHeadersAdapter(cfg *config.Config, checker *tools.Checker) *SecHeadersAdapter {
	return &SecHeadersAdapter{
		checker: secheaders.NewChecker(cfg, checker),
		cfg:     cfg,
	}
}

func (a *SecHeadersAdapter) Name() Phase { return PhaseSecHeaders }

func (a *SecHeadersAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseSecHeaders,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasAliveHosts() {
		fmt.Printf("        [SecHeadersAdapter] Skipping: no alive hosts (AliveHosts=%d)\n", len(input.AliveHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}
	fmt.Printf("        [SecHeadersAdapter] Starting security header check with %d alive hosts\n", len(input.AliveHosts))

	res, err := a.checker.Check(input.Target, input.AliveHosts)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// VulnScanAdapter wraps vulnscan.Scanner as a PhaseExecutor
type VulnScanAdapter struct {
	scanner   *vulnscan.Scanner
	collector *historic.Collector // For running katana when alive hosts available
	cfg       *config.Config
	checker   *tools.Checker
}

func NewVulnScanAdapter(cfg *config.Config, checker *tools.Checker) *VulnScanAdapter {
	return &VulnScanAdapter{
		scanner:   vulnscan.NewScanner(cfg, checker),
		collector: historic.NewCollector(cfg, checker),
		cfg:       cfg,
		checker:   checker,
	}
}

func (a *VulnScanAdapter) Name() Phase { return PhaseVulnScan }

func (a *VulnScanAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseVulnScan,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasAliveHosts() {
		fmt.Printf("        [VulnScanAdapter] Skipping: no alive hosts (AliveHosts=%d)\n", len(input.AliveHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}
	fmt.Printf("        [VulnScanAdapter] Starting scan with %d alive hosts\n", len(input.AliveHosts))

	// CRITICAL FIX: Run katana active crawl now that alive hosts are available
	// Historic phase runs at Level 0 (parallel with Subdomain) so katana was skipped
	var allURLs []string
	if len(input.URLs) > 0 {
		allURLs = append(allURLs, input.URLs...)
	}

	// Run katana to actively crawl live hosts and discover fresh endpoints
	if !a.cfg.PassiveMode && a.checker.IsInstalled("katana") {
		fmt.Println("        [VulnScan] Running katana active crawl on alive hosts...")
		mergedURLs, mergedCategorized, _ := a.collector.RunKatanaAndMerge(input.AliveHosts, allURLs, input.Target)
		allURLs = mergedURLs
		fmt.Printf("        [VulnScan] Total URLs after katana merge: %d\n", len(allURLs))

		// Update categorized URLs with fresh data
		if input.CategorizedURLs == nil {
			input.CategorizedURLs = &CategorizedURLs{}
		}
		input.CategorizedURLs.XSS = mergedCategorized.XSS
		input.CategorizedURLs.SQLi = mergedCategorized.SQLi
		input.CategorizedURLs.SSRF = mergedCategorized.SSRF
		input.CategorizedURLs.LFI = mergedCategorized.LFI
		input.CategorizedURLs.RCE = mergedCategorized.RCE
		input.CategorizedURLs.SSTI = mergedCategorized.SSTI
		input.CategorizedURLs.Redirect = mergedCategorized.Redirect
		input.CategorizedURLs.Debug = mergedCategorized.Debug
		input.CategorizedURLs.JSFiles = mergedCategorized.JSFiles
		input.CategorizedURLs.APIFiles = mergedCategorized.APIFiles
		input.CategorizedURLs.Sensitive = mergedCategorized.Sensitive
	}

	// CRITICAL FIX: Extract ALL URLs with query parameters for XSS fuzzing
	// Don't rely only on XSS pattern matching - fuzz any URL with parameters
	allParamURLs := extractURLsWithParams(allURLs)
	fmt.Printf("        [VulnScan] URLs with parameters for fuzzing: %d\n", len(allParamURLs))

	// Convert pipeline.CategorizedURLs to historic.CategorizedURLs
	var categorized *historic.CategorizedURLs
	if input.CategorizedURLs != nil {
		// Merge all parameter URLs into XSS category for comprehensive fuzzing
		xssURLs := input.CategorizedURLs.XSS
		if len(allParamURLs) > 0 {
			// Add all param URLs to XSS for fuzzing (deduplicated)
			seen := make(map[string]bool)
			for _, u := range xssURLs {
				seen[u] = true
			}
			for _, u := range allParamURLs {
				if !seen[u] {
					xssURLs = append(xssURLs, u)
					seen[u] = true
				}
			}
		}
		categorized = &historic.CategorizedURLs{
			XSS:       xssURLs, // Now includes ALL parameter URLs
			SQLi:      input.CategorizedURLs.SQLi,
			SSRF:      input.CategorizedURLs.SSRF,
			LFI:       input.CategorizedURLs.LFI,
			RCE:       input.CategorizedURLs.RCE,
			SSTI:      input.CategorizedURLs.SSTI,
			Redirect:  input.CategorizedURLs.Redirect,
			Debug:     input.CategorizedURLs.Debug,
			JSFiles:   input.CategorizedURLs.JSFiles,
			APIFiles:  input.CategorizedURLs.APIFiles,
			Sensitive: input.CategorizedURLs.Sensitive,
		}
		fmt.Printf("        [VulnScan] XSS fuzzing targets: %d URLs\n", len(categorized.XSS))
	} else if len(allParamURLs) > 0 {
		// No categorized URLs from historic, but we have param URLs - create category
		categorized = &historic.CategorizedURLs{
			XSS: allParamURLs,
		}
		fmt.Printf("        [VulnScan] Created XSS category with %d param URLs\n", len(allParamURLs))
	}

	// Build tech input for tech-aware scanning
	var techInput *vulnscan.TechInput
	if input.HasTechStack() {
		techInput = &vulnscan.TechInput{
			TechByHost: input.TechByHost,
			TechCount:  input.TechCount,
		}
	}

	// Save XSS candidate URLs to file for manual testing
	// This allows security researchers to run their own tools on these URLs
	if categorized != nil && len(categorized.XSS) > 0 && input.Config != nil {
		xssDir := filepath.Join(input.Config.OutputDir, input.Target, "8-vulnscan", "xss-testing")
		if err := os.MkdirAll(xssDir, 0755); err == nil {
			// Save all XSS candidate URLs
			xssInputFile := filepath.Join(xssDir, "xss_candidate_urls.txt")
			if f, err := os.Create(xssInputFile); err == nil {
				for _, u := range categorized.XSS {
					f.WriteString(u + "\n")
				}
				f.Close()
				fmt.Printf("        [VulnScan] Saved %d XSS candidate URLs to: %s\n", len(categorized.XSS), xssInputFile)
			}
		}
	}

	// Use enhanced parallel scanning which includes:
	// - Tech-aware nuclei scanning
	// - DNSTake for DNS takeover detection
	// - CRLFuzz for CRLF injection
	// - Parallel nuclei scan types (SSRF, XXE, etc.)
	res, err := a.scanner.ScanWithParallel(
		input.AliveHosts,
		allURLs,
		input.Subdomains, // Pass subdomains for DNSTake
		categorized,
		techInput,
	)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	// Save XSS results to separate files by tool for manual verification
	if res != nil && input.Config != nil {
		xssDir := filepath.Join(input.Config.OutputDir, input.Target, "8-vulnscan", "xss-testing")
		if err := os.MkdirAll(xssDir, 0755); err == nil {
			// Separate vulnerabilities by tool
			dalfoxResults := []string{}
			sxssResults := []string{}
			quicktestResults := []string{}

			for _, v := range res.Vulnerabilities {
				if v.Type == "xss" || strings.Contains(strings.ToLower(v.Name), "xss") {
					switch v.Tool {
					case "dalfox":
						dalfoxResults = append(dalfoxResults, v.URL)
					case "sxss":
						sxssResults = append(sxssResults, v.URL)
					case "quicktest":
						quicktestResults = append(quicktestResults, v.URL)
					}
				}
			}

			// Save dalfox results
			if len(dalfoxResults) > 0 {
				f, _ := os.Create(filepath.Join(xssDir, "dalfox_vulnerable.txt"))
				if f != nil {
					for _, u := range dalfoxResults {
						f.WriteString(u + "\n")
					}
					f.Close()
					fmt.Printf("        [VulnScan] Saved %d dalfox XSS findings to: dalfox_vulnerable.txt\n", len(dalfoxResults))
				}
			}

			// Save sxss results
			if len(sxssResults) > 0 {
				f, _ := os.Create(filepath.Join(xssDir, "sxss_reflections.txt"))
				if f != nil {
					for _, u := range sxssResults {
						f.WriteString(u + "\n")
					}
					f.Close()
					fmt.Printf("        [VulnScan] Saved %d sxss reflection findings to: sxss_reflections.txt\n", len(sxssResults))
				}
			}

			// Save quicktest results
			if len(quicktestResults) > 0 {
				f, _ := os.Create(filepath.Join(xssDir, "quicktest_xss.txt"))
				if f != nil {
					for _, u := range quicktestResults {
						f.WriteString(u + "\n")
					}
					f.Close()
					fmt.Printf("        [VulnScan] Saved %d quicktest XSS findings to: quicktest_xss.txt\n", len(quicktestResults))
				}
			}
		}
	}

	// Quick Win #1: GraphQL Endpoint Discovery
	// Fast scan for GraphQL endpoints - doesn't require heavy processing
	fmt.Println("        [VulnScan] Running GraphQL endpoint discovery...")
	graphqlScanner := vulnscan.NewGraphQLScanner(a.cfg, a.checker)
	graphqlResult, err := graphqlScanner.ScanGraphQL(ctx, input.AliveHosts)
	if err == nil && graphqlResult != nil && graphqlResult.TotalFound > 0 {
		fmt.Printf("        [VulnScan] Found %d GraphQL endpoint(s)", graphqlResult.TotalFound)
		if graphqlResult.Introspectable > 0 {
			fmt.Printf(" (%d with introspection enabled - HIGH RISK)", graphqlResult.Introspectable)
		}
		fmt.Println()

		// Add GraphQL findings as vulnerabilities
		for _, endpoint := range graphqlResult.Endpoints {
			severity := "medium"
			vulnName := "GraphQL Endpoint Exposed"
			description := fmt.Sprintf("GraphQL endpoint discovered at %s", endpoint.URL)

			if endpoint.IntrospectionEnabled {
				severity = "high"
				vulnName = "GraphQL Introspection Enabled"
				description = fmt.Sprintf("GraphQL endpoint with introspection enabled at %s - full schema can be queried", endpoint.URL)
			}

			res.Vulnerabilities = append(res.Vulnerabilities, vulnscan.Vulnerability{
				Host:        endpoint.URL,
				URL:         endpoint.URL,
				TemplateID:  "graphql-" + endpoint.Type,
				Name:        vulnName,
				Severity:    severity,
				Type:        "graphql",
				Description: description,
				Tool:        "graphql-scanner",
			})
			res.BySeverity[severity]++
			res.ByType["graphql"]++
		}
	}

	// Quick Win #2: Admin Panel Detection
	// Fast scan for admin interfaces - easy to find, high impact
	fmt.Println("        [VulnScan] Running admin panel detection...")
	adminScanner := vulnscan.NewAdminPanelScanner(a.cfg)
	adminResult, err := adminScanner.ScanAdminPanels(ctx, input.AliveHosts)
	if err == nil && adminResult != nil && adminResult.Total > 0 {
		fmt.Printf("        [VulnScan] Found %d admin panel(s)\n", adminResult.Total)

		// Add admin panel findings as vulnerabilities
		for _, panel := range adminResult.Panels {
			severity := "medium"
			vulnName := "Admin Panel Exposed"
			description := fmt.Sprintf("Admin panel found at %s", panel.URL)

			if panel.HasLogin {
				// Login page is less severe than no auth
				severity = "low"
				vulnName = "Admin Login Page Exposed"
				description = fmt.Sprintf("Admin login page (%s auth) at %s", panel.AuthType, panel.URL)
			} else {
				// No login requirement = critical
				severity = "high"
				vulnName = "Admin Panel Without Authentication"
				description = fmt.Sprintf("Admin panel accessible without authentication at %s", panel.URL)
			}

			if panel.Title != "" {
				description += fmt.Sprintf(" (Title: %s)", panel.Title)
			}

			res.Vulnerabilities = append(res.Vulnerabilities, vulnscan.Vulnerability{
				Host:        panel.URL,
				URL:         panel.URL,
				TemplateID:  "admin-panel-exposed",
				Name:        vulnName,
				Severity:    severity,
				Type:        "exposure",
				Description: description,
				Tool:        "admin-scanner",
			})
			res.BySeverity[severity]++
			res.ByType["exposure"]++
		}
	}

	// Quick Win #3: Cloud Storage Misconfiguration Detection
	// Scan for exposed S3/GCS/Azure buckets - critical finding if found
	fmt.Println("        [VulnScan] Running cloud storage misconfiguration scan...")
	cloudScanner := vulnscan.NewCloudStorageScanner(a.cfg)
	cloudResult, err := cloudScanner.ScanCloudStorage(ctx, input.Target, input.Subdomains)
	if err == nil && cloudResult != nil && len(cloudResult.Buckets) > 0 {
		fmt.Printf("        [VulnScan] Found %d cloud bucket(s): ", len(cloudResult.Buckets))
		if cloudResult.ByStatus["open"] > 0 {
			fmt.Printf("%d OPEN (CRITICAL)", cloudResult.ByStatus["open"])
		}
		if cloudResult.ByStatus["listable"] > 0 {
			if cloudResult.ByStatus["open"] > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%d listable", cloudResult.ByStatus["listable"])
		}
		fmt.Println()

		// Add cloud bucket findings as vulnerabilities
		for _, bucket := range cloudResult.Buckets {
			severity := "medium"
			vulnName := fmt.Sprintf("%s Bucket Exposed", strings.ToUpper(bucket.Provider))
			description := fmt.Sprintf("%s bucket '%s' discovered at %s", strings.ToUpper(bucket.Provider), bucket.Name, bucket.URL)

			// Determine severity based on status
			switch bucket.Status {
			case "open":
				if bucket.Writable {
					severity = "critical"
					vulnName = fmt.Sprintf("%s Bucket Publicly Writable", strings.ToUpper(bucket.Provider))
					description += " - PUBLICLY WRITABLE (can upload files)"
				} else if bucket.Listable {
					severity = "critical"
					vulnName = fmt.Sprintf("%s Bucket Publicly Readable", strings.ToUpper(bucket.Provider))
					description += " - PUBLICLY READABLE (all files exposed)"
				} else {
					severity = "high"
					description += " - publicly accessible"
				}
			case "listable":
				severity = "high"
				vulnName = fmt.Sprintf("%s Bucket Listable", strings.ToUpper(bucket.Provider))
				description += " - directory listing enabled"
			case "authenticated":
				severity = "low"
				description += " - requires authentication"
			}

			if bucket.FileCount > 0 {
				description += fmt.Sprintf(" (%d files found)", bucket.FileCount)
			}

			res.Vulnerabilities = append(res.Vulnerabilities, vulnscan.Vulnerability{
				Host:        bucket.URL,
				URL:         bucket.URL,
				TemplateID:  fmt.Sprintf("cloud-bucket-%s", bucket.Status),
				Name:        vulnName,
				Severity:    severity,
				Type:        "cloud-misconfig",
				Description: description,
				Tool:        "cloud-scanner",
			})
			res.BySeverity[severity]++
			res.ByType["cloud-misconfig"]++
		}
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// extractURLsWithParams extracts all URLs that have query parameters
// These are candidates for XSS, SQLi, and other injection testing
func extractURLsWithParams(urls []string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, u := range urls {
		// URL has parameters if it contains "?" followed by "="
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			if !seen[u] {
				seen[u] = true
				result = append(result, u)
			}
		}
	}
	return result
}

// ScreenshotAdapter wraps screenshot.Capturer as a PhaseExecutor
type ScreenshotAdapter struct {
	capturer *screenshot.Capturer
}

func NewScreenshotAdapter(cfg *config.Config, checker *tools.Checker) *ScreenshotAdapter {
	return &ScreenshotAdapter{
		capturer: screenshot.NewCapturer(cfg, checker),
	}
}

func (a *ScreenshotAdapter) Name() Phase { return PhaseScreenshot }

func (a *ScreenshotAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseScreenshot,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Use httpx results (confirmed HTTP services) instead of raw port scan results
	targets := input.GetScreenshotTargets()
	if len(targets) == 0 {
		fmt.Printf("        [ScreenshotAdapter] Skipping: no targets (httpx_urls=%d, tech_hosts=%d, alive=%d)\n",
			len(input.HttpxURLs), len(input.TechByHost), len(input.AliveHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	source := "httpx_urls"
	if len(input.HttpxURLs) == 0 {
		if len(input.TechByHost) > 0 {
			source = "tech_hosts"
		} else {
			source = "port_scan"
		}
	}
	fmt.Printf("        [ScreenshotAdapter] Starting capture with %d URLs (source: %s)\n", len(targets), source)

	// Use target-specific output directory for screenshots
	outputDir := filepath.Join(input.Config.OutputDir, input.Target)

	// Capture screenshots and cluster them
	res, err := a.capturer.CaptureWithResultInDir(targets, outputDir)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		fmt.Printf("        [ScreenshotAdapter] Error: %v\n", err)
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	// Check if screenshots were skipped (e.g., gowitness not installed)
	if res != nil && res.Skipped {
		fmt.Printf("        [ScreenshotAdapter] Skipped: %s\n", res.SkipReason)
		result.Status = StatusSkipped
		result.Data = res
		return result, nil
	}

	fmt.Printf("        [ScreenshotAdapter] Completed: %d captures, %d clusters\n",
		res.TotalCaptures, len(res.Clusters))
	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// IPRangeAdapter wraps iprange.Discoverer as a PhaseExecutor
type IPRangeAdapter struct {
	discoverer *iprange.Discoverer
}

func NewIPRangeAdapter(cfg *config.Config, checker *tools.Checker) *IPRangeAdapter {
	return &IPRangeAdapter{
		discoverer: iprange.NewDiscoverer(cfg, checker),
	}
}

func (a *IPRangeAdapter) Name() Phase { return PhaseIPRange }

func (a *IPRangeAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseIPRange,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Check if target is IP/CIDR/ASN
	target := input.Target
	if !iprange.IsIPTarget(target) && !iprange.IsASN(target) {
		// Not an IP-based target, skip this phase
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	var res *iprange.Result
	var err error

	if iprange.IsASN(target) {
		res, err = a.discoverer.DiscoverFromASN(target)
	} else {
		res, err = a.discoverer.Discover(target)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// DirBruteAdapter wraps dirbrute.Scanner as a PhaseExecutor
type DirBruteAdapter struct {
	scanner *dirbrute.Scanner
}

func NewDirBruteAdapter(cfg *config.Config, checker *tools.Checker) *DirBruteAdapter {
	return &DirBruteAdapter{
		scanner: dirbrute.NewScanner(cfg, checker),
	}
}

func (a *DirBruteAdapter) Name() Phase { return PhaseDirBrute }

func (a *DirBruteAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseDirBrute,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasAliveHosts() {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Use direct hosts (non-WAF) if available - skip CDN hosts as brute-forcing is ineffective
	hosts := input.GetHostsForScanning()
	if len(hosts) == 0 {
		fmt.Printf("        [DirBruteAdapter] Skipping: all hosts are CDN-protected (CDN=%d, Direct=%d)\n",
			len(input.CDNHosts), len(input.DirectHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	fmt.Printf("        [DirBruteAdapter] Using %d direct hosts (skipping %d CDN-protected)\n",
		len(hosts), len(input.CDNHosts))

	// Create a phase-level timeout context (DirBrute can take a long time)
	dirbruteTimeout := 15 * time.Minute // Default 15 minutes
	if input.Config != nil && input.Config.PhaseTimeout > 0 {
		dirbruteTimeout = time.Duration(input.Config.PhaseTimeout) * time.Minute
	}
	phaseCtx, cancel := context.WithTimeout(ctx, dirbruteTimeout)
	defer cancel()

	// Use context-aware scanning
	res, err := a.scanner.ScanWithContext(phaseCtx, hosts)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		// Check if it was a timeout/cancellation
		if phaseCtx.Err() == context.DeadlineExceeded {
			fmt.Printf("        [DirBruteAdapter] Phase timeout after %v\n", dirbruteTimeout)
			result.Status = StatusCompleted // Still mark as completed with partial results
			result.Data = res
			return result, nil
		}
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// AIGuidedAdapter wraps aiguided.Scanner as a PhaseExecutor
type AIGuidedAdapter struct {
	scanner *aiguided.Scanner
}

func NewAIGuidedAdapter(cfg *config.Config, checker *tools.Checker) *AIGuidedAdapter {
	return &AIGuidedAdapter{
		scanner: aiguided.NewScanner(cfg, checker),
	}
}

func (a *AIGuidedAdapter) Name() Phase { return PhaseAIGuided }

func (a *AIGuidedAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseAIGuided,
		Status:    StatusRunning,
		StartTime: start,
	}

	if !input.HasAliveHosts() {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Build target context from previous phases
	targetCtx := &aiguided.TargetContext{
		Domain:               input.Target,
		Technologies:         []string{},
		Endpoints:            input.URLs,
		JSFiles:              []string{},
		APIEndpoints:         []string{},
		Services:             []string{},
		WAFDetected:          len(input.CDNHosts) > 0,
		CDNHosts:             len(input.CDNHosts),
		SecurityHeaderIssues: input.SecurityHeaderIssues,
	}

	// Extract technologies from TechByHost
	if input.TechByHost != nil {
		techSet := make(map[string]bool)
		for _, techs := range input.TechByHost {
			for _, tech := range techs {
				techSet[tech] = true
			}
		}
		for tech := range techSet {
			targetCtx.Technologies = append(targetCtx.Technologies, tech)
		}
	}

	// Extract JS files and API endpoints from categorized URLs
	if input.CategorizedURLs != nil {
		targetCtx.JSFiles = input.CategorizedURLs.JSFiles
		targetCtx.APIEndpoints = input.CategorizedURLs.APIFiles
	}

	res, err := a.scanner.Scan(input.AliveHosts, targetCtx)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// JSAnalysisAdapter wraps jsanalysis.Analyzer as a PhaseExecutor
type JSAnalysisAdapter struct {
	analyzer *jsanalysis.Analyzer
	cfg      *config.Config
}

func NewJSAnalysisAdapter(cfg *config.Config, checker *tools.Checker) *JSAnalysisAdapter {
	return &JSAnalysisAdapter{
		analyzer: jsanalysis.NewAnalyzer(cfg, checker),
		cfg:      cfg,
	}
}

func (a *JSAnalysisAdapter) Name() Phase { return PhaseJSAnalysis }

func (a *JSAnalysisAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseJSAnalysis,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Check if we have JS files from historic phase
	var jsURLs []string
	if input.CategorizedURLs != nil && len(input.CategorizedURLs.JSFiles) > 0 {
		jsURLs = input.CategorizedURLs.JSFiles
	}

	if len(jsURLs) == 0 {
		fmt.Printf("        [JSAnalysisAdapter] Skipping: no JS files found in historic URLs\n")
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	fmt.Printf("        [JSAnalysisAdapter] Analyzing %d JavaScript files\n", len(jsURLs))

	// Run JS analysis
	res, err := a.analyzer.Analyze(ctx, jsURLs)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}

// TruffleHogAdapter wraps trufflehog.Scanner as a PhaseExecutor
// Scans JS files from both historic (passive) and JSAnalysis (active) phases for secrets
type TruffleHogAdapter struct {
	scanner *trufflehog.Scanner
	cfg     *config.Config
	checker *tools.Checker
}

func NewTruffleHogAdapter(cfg *config.Config, checker *tools.Checker) *TruffleHogAdapter {
	return &TruffleHogAdapter{
		scanner: trufflehog.NewScanner(checker),
		cfg:     cfg,
		checker: checker,
	}
}

func (a *TruffleHogAdapter) Name() Phase { return PhaseTruffleHog }

func (a *TruffleHogAdapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseTruffleHog,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Check if trufflehog is installed
	if !a.checker.IsInstalled("trufflehog") {
		fmt.Printf("        [TruffleHogAdapter] Skipping: trufflehog not installed\n")
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Collect JS files from historic phase
	// Historic phase includes both passive (waybackurls, gau, urlfinder, waymore)
	// and active (katana) JS file discovery
	var jsURLs []string
	if input.CategorizedURLs != nil && len(input.CategorizedURLs.JSFiles) > 0 {
		jsURLs = input.CategorizedURLs.JSFiles
		fmt.Printf("        [TruffleHogAdapter] Found %d JS files from historic scan\n", len(jsURLs))
	}

	// Get target URL from alive hosts for main page HTML scanning
	var targetURL string
	if len(input.AliveHosts) > 0 {
		// Use first alive host as target for main page scan
		targetURL = input.AliveHosts[0]
		fmt.Printf("        [TruffleHogAdapter] Target URL for main page scan: %s\n", targetURL)
	} else if input.Target != "" {
		// Fallback to target domain
		targetURL = "https://" + input.Target
		fmt.Printf("        [TruffleHogAdapter] Target URL (fallback): %s\n", targetURL)
	}

	if len(jsURLs) == 0 && targetURL == "" {
		fmt.Printf("        [TruffleHogAdapter] Skipping: no JS files or target URL found\n")
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	fmt.Printf("        [TruffleHogAdapter] Scanning %d unique JS files + main page for secrets\n", len(jsURLs))

	// Run TruffleHog scan
	res, err := a.scanner.ScanWebTarget(ctx, targetURL, jsURLs)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result, err
	}

	result.Status = StatusCompleted
	result.Data = res
	return result, nil
}
