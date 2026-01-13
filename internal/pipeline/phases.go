package pipeline

// Phase represents a scan phase identifier
type Phase string

const (
	PhaseIPRange  Phase = "iprange"
	PhaseSubdomain Phase = "subdomain"
	PhaseWAF      Phase = "waf"
	PhasePorts    Phase = "ports"
	PhaseTakeover Phase = "takeover"
	PhaseHistoric Phase = "historic"
	PhaseTech     Phase = "tech"
	PhaseDirBrute Phase = "dirbrute"
	PhaseVulnScan Phase = "vulnscan"
	PhaseAIGuided Phase = "aiguided"
)

// PhaseDependencies defines what each phase requires from previous phases
// Key: phase that needs input, Value: phases it depends on
var PhaseDependencies = map[Phase][]Phase{
	PhaseIPRange:  {}, // No dependencies - entry point for IP/ASN targets
	PhaseSubdomain: {}, // No dependencies - entry point for domain targets
	PhaseWAF:      {PhaseSubdomain},
	PhasePorts:    {PhaseSubdomain}, // WAF is optional (used for filtering)
	PhaseTakeover: {PhaseSubdomain},
	PhaseHistoric: {PhaseSubdomain},
	PhaseTech:     {PhasePorts},
	PhaseDirBrute: {PhasePorts}, // WAF is optional (used for filtering)
	PhaseVulnScan: {PhasePorts, PhaseHistoric},
	PhaseAIGuided: {PhasePorts, PhaseTech, PhaseVulnScan},
}

// PhaseProduces defines what data each phase produces
var PhaseProduces = map[Phase][]string{
	PhaseIPRange:   {"ips", "domains", "base_domains"},
	PhaseSubdomain: {"subdomains", "validated_subdomains", "all_subdomains"},
	PhaseWAF:       {"direct_hosts", "cdn_hosts", "waf_info"},
	PhasePorts:     {"alive_hosts", "open_ports", "tls_info"},
	PhaseTakeover:  {"vulnerable_subs"},
	PhaseHistoric:  {"urls", "categorized_urls", "extracted_subdomains"},
	PhaseTech:      {"tech_by_host", "tech_count"},
	PhaseDirBrute:  {"discoveries"},
	PhaseVulnScan:  {"vulnerabilities"},
	PhaseAIGuided:  {"ai_recommendations", "ai_vulnerabilities"},
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
		PhaseTakeover,
		PhaseHistoric,
		PhaseTech,
		PhaseDirBrute,
		PhaseVulnScan,
		PhaseAIGuided,
	}
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
