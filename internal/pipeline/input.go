package pipeline

import (
	"github.com/rootsploit/reconator/internal/config"
)

// PhaseInput aggregates data from previous phases for use by current phase
// This struct is populated by reading outputs from dependency phases
// Zero allocation when fields are unused (nil slices don't allocate)
type PhaseInput struct {
	// Scan context
	Target string
	ScanID string
	Config *config.Config

	// From subdomain phase
	Subdomains    []string // Validated, alive subdomains
	AllSubdomains []string // All discovered (including unvalidated)

	// From waf phase
	DirectHosts []string // Non-WAF/CDN protected hosts
	CDNHosts    []string // WAF/CDN protected hosts

	// From ports phase
	AliveHosts []string         // Hosts with HTTP(S) services
	OpenPorts  map[string][]int // host -> [ports]
	// TLSInfo is not used by downstream phases - it's parsed directly from JSON for reports

	// From historic phase
	URLs              []string
	CategorizedURLs   *CategorizedURLs
	ExtractedSubdomains []string

	// From tech phase
	TechByHost map[string][]string // host -> [technologies]
	TechCount  map[string]int      // technology -> count
	HttpxURLs  []string            // Full URLs with protocol that responded to httpx (for screenshots)

	// From vulnscan phase
	Vulnerabilities []Vulnerability

	// From takeover phase
	TakeoverVulns []TakeoverVuln

	// From dirbrute phase
	Discoveries []Discovery

	// From secheaders phase
	SecurityHeaderIssues int // Count of hosts with missing security headers

	// From iprange phase (ASN/IP targets)
	IPRangeIPs         []string // Discovered IPs
	IPRangeDomains     []string // Domains found via reverse DNS/certs
	IPRangeBaseDomains []string // Unique TLDs extracted from domains
}

// CategorizedURLs groups URLs by vulnerability type for targeted scanning
type CategorizedURLs struct {
	XSS      []string
	SQLi     []string
	SSRF     []string
	LFI      []string
	RCE      []string
	SSTI     []string
	Redirect []string
	Debug    []string
	JSFiles  []string
	APIFiles []string
	Sensitive []string
}

// Vulnerability represents a discovered vulnerability
type Vulnerability struct {
	Host        string `json:"host"`
	URL         string `json:"url,omitempty"`
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Tool        string `json:"tool"`
}

// TakeoverVuln represents a subdomain takeover vulnerability
type TakeoverVuln struct {
	Subdomain string `json:"subdomain"`
	Service   string `json:"service"`
	Severity  string `json:"severity"`
	Tool      string `json:"tool"`
}

// Discovery represents a directory bruteforce finding
type Discovery struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Tool       string `json:"tool"`
}

// NewPhaseInput creates a new PhaseInput with scan context
func NewPhaseInput(target, scanID string, cfg *config.Config) *PhaseInput {
	return &PhaseInput{
		Target: target,
		ScanID: scanID,
		Config: cfg,
	}
}

// HasSubdomains returns true if subdomain data is available
func (p *PhaseInput) HasSubdomains() bool {
	return len(p.Subdomains) > 0
}

// HasAliveHosts returns true if alive hosts data is available
func (p *PhaseInput) HasAliveHosts() bool {
	return len(p.AliveHosts) > 0
}

// HasURLs returns true if historic URLs are available
func (p *PhaseInput) HasURLs() bool {
	return len(p.URLs) > 0
}

// HasTechStack returns true if technology detection data is available
func (p *PhaseInput) HasTechStack() bool {
	return len(p.TechByHost) > 0
}

// GetHttpxHosts returns hosts that responded to httpx probing (from tech phase)
// These are confirmed HTTP services, unlike AliveHosts which are raw port scan results
func (p *PhaseInput) GetHttpxHosts() []string {
	if len(p.TechByHost) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(p.TechByHost))
	for host := range p.TechByHost {
		hosts = append(hosts, host)
	}
	return hosts
}

// GetScreenshotTargets returns the best URLs for screenshots
// Prefers HttpxURLs (full URLs with protocol), falls back to hostnames
func (p *PhaseInput) GetScreenshotTargets() []string {
	// Best: httpx URLs with protocol (no duplicates)
	if len(p.HttpxURLs) > 0 {
		return p.HttpxURLs
	}
	// Fallback: generate URLs from TechByHost hostnames (prepend https://)
	if httpxHosts := p.GetHttpxHosts(); len(httpxHosts) > 0 {
		urls := make([]string, 0, len(httpxHosts))
		for _, host := range httpxHosts {
			urls = append(urls, "https://"+host)
		}
		return urls
	}
	// Last resort: AliveHosts from port scan
	return p.AliveHosts
}

// HasIPRangeData returns true if IP range discovery data is available
func (p *PhaseInput) HasIPRangeData() bool {
	return len(p.IPRangeBaseDomains) > 0 || len(p.IPRangeDomains) > 0
}

// GetHostsForScanning returns the appropriate host list for scanning
// Prefers DirectHosts (non-WAF) if available, falls back to all alive hosts
func (p *PhaseInput) GetHostsForScanning() []string {
	if len(p.DirectHosts) > 0 {
		return p.DirectHosts
	}
	return p.AliveHosts
}

// FilterNonWAFHosts filters alive hosts to only include non-WAF protected ones
func (p *PhaseInput) FilterNonWAFHosts(hosts []string) []string {
	if len(p.DirectHosts) == 0 {
		return hosts // No WAF info, return all
	}

	directSet := make(map[string]bool, len(p.DirectHosts))
	for _, h := range p.DirectHosts {
		directSet[h] = true
	}

	filtered := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if directSet[h] {
			filtered = append(filtered, h)
		}
	}
	return filtered
}
