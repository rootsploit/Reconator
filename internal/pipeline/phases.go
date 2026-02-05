package pipeline

import "fmt"

// Phase represents a scan phase identifier
type Phase string

const (
	PhaseIPRange    Phase = "iprange"    // Phase 0
	PhaseSubdomain  Phase = "subdomain"  // Phase 1
	PhaseWAF        Phase = "waf"        // Phase 2
	PhasePorts      Phase = "ports"      // Phase 3
	PhaseVHost      Phase = "vhost"      // Phase 4 (VHost Discovery)
	PhaseTakeover   Phase = "takeover"   // Phase 5
	PhaseHistoric   Phase = "historic"   // Phase 6
	PhaseTech       Phase = "tech"       // Phase 7
	PhaseJSAnalysis Phase = "jsanalysis" // Phase 7b (JavaScript Deep Analysis)
	PhaseTruffleHog Phase = "trufflehog" // Phase 7c (Secret Scanning with TruffleHog)
	PhaseSecHeaders Phase = "secheaders" // Phase 8 (Security Headers Check)
	PhaseDirBrute   Phase = "dirbrute"   // Phase 9
	PhaseVulnScan   Phase = "vulnscan"   // Phase 10
	PhaseScreenshot Phase = "screenshot" // Phase 11 (Visual Recon)
	PhaseAIGuided   Phase = "aiguided"   // Phase 12
)

// PhaseNumber maps phases to their display number (Phase 0-12)
var PhaseNumber = map[Phase]int{
	PhaseIPRange:    0,
	PhaseSubdomain:  1,
	PhaseWAF:        2,
	PhasePorts:      3,
	PhaseVHost:      4,
	PhaseTakeover:   5,
	PhaseHistoric:   6,
	PhaseTech:       7,
	PhaseJSAnalysis: 7, // 7b - runs parallel with Tech
	PhaseTruffleHog: 7, // 7c - runs after Historic/JSAnalysis
	PhaseSecHeaders: 8,
	PhaseDirBrute:   9,
	PhaseVulnScan:   10,
	PhaseScreenshot: 11,
	PhaseAIGuided:   12,
}

// PhaseName maps phases to their display name
var PhaseName = map[Phase]string{
	PhaseIPRange:    "IP Range Discovery",
	PhaseSubdomain:  "Subdomain Enumeration",
	PhaseWAF:        "WAF/CDN Detection",
	PhasePorts:      "Port Scanning + TLS",
	PhaseVHost:      "VHost Discovery",
	PhaseTakeover:   "Subdomain Takeover Check",
	PhaseHistoric:   "Historic URL Collection",
	PhaseTech:       "Technology Detection",
	PhaseJSAnalysis: "JavaScript Deep Analysis",
	PhaseTruffleHog: "Secret Scanning (TruffleHog)",
	PhaseSecHeaders: "Security Headers Check",
	PhaseDirBrute:   "Directory Bruteforce",
	PhaseVulnScan:   "Vulnerability Scanning",
	PhaseScreenshot: "Visual Recon (Screenshots)",
	PhaseAIGuided:   "AI-Guided Scanning",
}

// PhaseDependencies defines what each phase requires from previous phases
// Key: phase that needs input, Value: phases it depends on
// Note: These are soft dependencies - phase can run with partial data
var PhaseDependencies = map[Phase][]Phase{
	PhaseIPRange:    {}, // No dependencies - entry point for IP/ASN targets
	PhaseSubdomain:  {PhaseIPRange}, // Soft dep: loads TLDs from IPRange for ASN targets
	PhaseWAF:        {PhasePorts},     // WAF needs alive hosts from ports for CDN detection
	PhasePorts:      {PhaseSubdomain, PhaseHistoric}, // Ports needs subdomains + historic extracted subdomains (MERGED)
	PhaseVHost:      {PhasePorts},     // Needs alive hosts for VHost fuzzing
	PhaseTakeover:   {PhaseSubdomain, PhaseHistoric}, // Check both subdomain and historic-extracted subs for takeover
	PhaseHistoric:   {}, // NO DEPENDENCY - runs parallel with Subdomain! Only needs root domain for gau/waybackurls/urlfinder
	PhaseTech:       {PhasePorts},
	PhaseJSAnalysis: {PhaseHistoric}, // Needs JS files list from historic URLs
	PhaseTruffleHog: {PhaseHistoric, PhaseJSAnalysis}, // Scans JS from both historic (passive) and JSAnalysis (active)
	PhaseSecHeaders: {PhasePorts}, // Needs alive hosts for header checking
	PhaseDirBrute:   {PhasePorts}, // WAF is optional (used for filtering)
	PhaseVulnScan:   {PhasePorts, PhaseHistoric, PhaseTech}, // Tech enables tech-aware scanning
	PhaseScreenshot: {PhasePorts, PhaseTech},                 // Uses httpx results for HTTP-responding hosts
	PhaseAIGuided:   {PhasePorts, PhaseTech, PhaseVulnScan, PhaseSecHeaders}, // SecHeaders for summary
}

// PhaseProduces defines what data each phase produces
var PhaseProduces = map[Phase][]string{
	PhaseIPRange:    {"ips", "domains", "base_domains"},
	PhaseSubdomain:  {"subdomains", "validated_subdomains", "all_subdomains"},
	PhaseWAF:        {"direct_hosts", "cdn_hosts", "waf_info"},
	PhasePorts:      {"alive_hosts", "open_ports", "tls_info"},
	PhaseVHost:      {"vhosts", "cert_sans", "reverse_dns"},
	PhaseTakeover:   {"vulnerable_subs"},
	PhaseHistoric:   {"urls", "categorized_urls", "extracted_subdomains"},
	PhaseTech:       {"tech_by_host", "tech_count"},
	PhaseJSAnalysis: {"endpoints", "dom_xss_sinks", "secrets", "js_files_analyzed"},
	PhaseTruffleHog: {"secrets", "verified_secrets", "secret_detections"},
	PhaseSecHeaders: {"header_findings", "email_security", "misconfig_vulns"},
	PhaseDirBrute:   {"discoveries"},
	PhaseVulnScan:   {"vulnerabilities"},
	PhaseScreenshot: {"screenshots", "clusters", "cluster_summary"},
	PhaseAIGuided:   {"ai_recommendations", "ai_vulnerabilities"},
}

// GetDependencies returns the phases that must complete before the given phase
func GetDependencies(phase Phase) []Phase {
	return PhaseDependencies[phase]
}

// GetAllPhases returns all phases in execution order
func GetAllPhases() []Phase {
	return []Phase{
		PhaseIPRange,
		PhaseSubdomain,
		PhaseWAF,
		PhasePorts,
		PhaseVHost,
		PhaseTakeover,
		PhaseHistoric,
		PhaseTech,
		PhaseJSAnalysis,
		PhaseTruffleHog,
		PhaseSecHeaders,
		PhaseDirBrute,
		PhaseVulnScan,
		PhaseScreenshot,
		PhaseAIGuided,
	}
}

// GetPhaseDisplayName returns "Phase N: Name" for CLI output
func GetPhaseDisplayName(phase Phase) string {
	num := PhaseNumber[phase]
	name := PhaseName[phase]
	return fmt.Sprintf("[Phase %d] %s", num, name)
}

// CanRunInParallel returns phases that can run concurrently given completed phases
func CanRunInParallel(completed map[Phase]bool) []Phase {
	var runnable []Phase

	for _, phase := range GetAllPhases() {
		if completed[phase] {
			continue // Already done
		}

		// Check if all dependencies are met
		deps := GetDependencies(phase)
		allMet := true
		for _, dep := range deps {
			if !completed[dep] {
				allMet = false
				break
			}
		}

		if allMet {
			runnable = append(runnable, phase)
		}
	}

	return runnable
}
