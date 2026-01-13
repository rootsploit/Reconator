package pipeline

import (
	"context"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// RegisterAllAdapters registers all phase adapters with the executor
func RegisterAllAdapters(exec *Executor, cfg *config.Config, checker *tools.Checker) {
	exec.Register(NewSubdomainAdapter(cfg, checker))
	exec.Register(NewWAFAdapter(cfg, checker))
	exec.Register(NewPortsAdapter(cfg, checker))
	exec.Register(NewTakeoverAdapter(cfg, checker))
	exec.Register(NewHistoricAdapter(cfg, checker))
	exec.Register(NewTechAdapter(cfg, checker))
	exec.Register(NewVulnScanAdapter(cfg, checker))
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

	if !input.HasSubdomains() {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	res, err := a.detector.Detect(input.Subdomains)
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
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
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

	// Use AllSubdomains for takeover check (includes unvalidated)
	subs := input.AllSubdomains
	if len(subs) == 0 {
		subs = input.Subdomains
	}

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

	// Collect historic URLs for the target domain
	res, err := a.collector.Collect(input.Target, input.Subdomains)
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
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

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
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

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

	res, err := a.scanner.Scan(input.AliveHosts, categorized)
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
