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
	PhaseDirBrute   Phase = "dirbrute"   // Phase 8
	PhaseVulnScan   Phase = "vulnscan"   // Phase 9
	PhaseScreenshot Phase = "screenshot" // Phase 10 (Visual Recon)
	PhaseAIGuided   Phase = "aiguided"   // Phase 11
)

// PhaseNumber maps phases to their display number (Phase 0-11)
var PhaseNumber = map[Phase]int{
	PhaseIPRange:    0,
	PhaseSubdomain:  1,
	PhaseWAF:        2,
	PhasePorts:      3,
	PhaseVHost:      4,
	PhaseTakeover:   5,
	PhaseHistoric:   6,
	PhaseTech:       7,
	PhaseDirBrute:   8,
	PhaseVulnScan:   9,
	PhaseScreenshot: 10,
	PhaseAIGuided:   11,
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
	PhaseDirBrute:   "Directory Bruteforce",
	PhaseVulnScan:   "Vulnerability Scanning",
	PhaseScreenshot: "Visual Recon (Screenshots)",
	PhaseAIGuided:   "AI-Guided Scanning",
}

// PhaseDependencies defines what each phase requires from previous phases
// Key: phase that needs input, Value: phases it depends on
var PhaseDependencies = map[Phase][]Phase{
	PhaseIPRange:    {}, // No dependencies - entry point for IP/ASN targets
	PhaseSubdomain:  {}, // No dependencies - entry point for domain targets
	PhaseWAF:        {PhaseSubdomain},
	PhasePorts:      {PhaseSubdomain}, // WAF is optional (used for filtering)
	PhaseVHost:      {PhasePorts},     // Needs alive hosts for VHost fuzzing
	PhaseTakeover:   {PhaseSubdomain},
	PhaseHistoric:   {PhaseSubdomain},
	PhaseTech:       {PhasePorts},
	PhaseDirBrute:   {PhasePorts}, // WAF is optional (used for filtering)
	PhaseVulnScan:   {PhasePorts, PhaseHistoric, PhaseTech}, // Tech enables tech-aware scanning
	PhaseScreenshot: {PhasePorts},                           // Needs alive hosts for screenshot URLs
	PhaseAIGuided:   {PhasePorts, PhaseTech, PhaseVulnScan},
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
