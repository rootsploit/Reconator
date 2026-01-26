package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
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
	exec.Register(NewSecHeadersAdapter(cfg, checker))
	exec.Register(NewDirBruteAdapter(cfg, checker))
	exec.Register(NewVulnScanAdapter(cfg, checker))
	exec.Register(NewScreenshotAdapter(cfg, checker))
	exec.Register(NewAIGuidedAdapter(cfg, checker))
}

// SubdomainAdapter wraps subdomain.Enumerator as a PhaseExecutor
type SubdomainAdapter struct {
	enumerator *subdomain.Enumerator
}

func NewSubdomainAdapter(cfg *config.Config, checker *tools.Checker) *SubdomainAdapter {
	return &SubdomainAdapter{
		enumerator: subdomain.NewEnumerator(cfg, checker),
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
	fmt.Printf("        [PortsAdapter] Starting scan with %d subdomains\n", len(input.Subdomains))

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
	scanner *vulnscan.Scanner
}

func NewVulnScanAdapter(cfg *config.Config, checker *tools.Checker) *VulnScanAdapter {
	return &VulnScanAdapter{
		scanner: vulnscan.NewScanner(cfg, checker),
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

	// Convert pipeline.CategorizedURLs to historic.CategorizedURLs
	var categorized *historic.CategorizedURLs
	if input.CategorizedURLs != nil {
		categorized = &historic.CategorizedURLs{
			XSS:       input.CategorizedURLs.XSS,
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
	}

	// Build tech input for tech-aware scanning
	var techInput *vulnscan.TechInput
	if input.HasTechStack() {
		techInput = &vulnscan.TechInput{
			TechByHost: input.TechByHost,
			TechCount:  input.TechCount,
		}
	}

	// Use tech-aware scanning when tech data is available
	res, err := a.scanner.ScanWithTech(input.AliveHosts, categorized, techInput)
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

	if !input.HasAliveHosts() {
		fmt.Printf("        [ScreenshotAdapter] Skipping: no alive hosts (AliveHosts=%d)\n", len(input.AliveHosts))
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}
	fmt.Printf("        [ScreenshotAdapter] Starting capture with %d alive hosts\n", len(input.AliveHosts))

	// Use target-specific output directory for screenshots
	outputDir := filepath.Join(input.Config.OutputDir, input.Target)

	// Capture screenshots and cluster them
	res, err := a.capturer.CaptureWithResultInDir(input.AliveHosts, outputDir)
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
