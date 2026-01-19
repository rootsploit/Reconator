package aiguided

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// VulnChain represents a chain of vulnerabilities that can be exploited together
type VulnChain struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Vulns       []ChainedVuln `json:"vulnerabilities"`
	Impact      string        `json:"impact"`
	Severity    string        `json:"severity"` // Overall chain severity
	Likelihood  string        `json:"likelihood"`
	Steps       []string      `json:"exploitation_steps"`
	Mitigations []string      `json:"mitigations"`
}

// ChainedVuln is a vulnerability that's part of a chain
type ChainedVuln struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Severity   string `json:"severity"`
	Role       string `json:"role"` // "entry_point", "pivot", "escalation", "target"
	Order      int    `json:"order"`
}

// ChainAnalysis contains the full vulnerability chain analysis
type ChainAnalysis struct {
	Chains           []VulnChain       `json:"chains"`
	PrioritizedVulns []PrioritizedVuln `json:"prioritized_vulns"`
	Summary          string            `json:"summary"`
	Provider         string            `json:"provider"`
}

// PrioritizedVuln is a vulnerability with priority scoring
type PrioritizedVuln struct {
	TemplateID   string `json:"template_id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Severity     string `json:"severity"`
	Priority     int    `json:"priority"`    // 1-10, higher is more critical
	ChainCount   int    `json:"chain_count"` // How many chains include this vuln
	Exploitable  bool   `json:"exploitable"`
	HasPublicPOC bool   `json:"has_public_poc"`
	Reasoning    string `json:"reasoning"`
}

// VulnChainer analyzes vulnerabilities and identifies attack chains
type VulnChainer struct {
	provider *ProviderManager
}

// NewVulnChainer creates a new vulnerability chainer
func NewVulnChainer() *VulnChainer {
	pm := NewProviderManager()
	pm.LoadFromEnv()
	configPath := GetDefaultConfigPath()
	pm.LoadFromFile(configPath)

	return &VulnChainer{provider: pm}
}

// AnalyzeChains analyzes vulnerabilities to find attack chains
func (vc *VulnChainer) AnalyzeChains(vulns []Vulnerability, context *TargetContext) (*ChainAnalysis, error) {
	providers := vc.provider.GetAvailableProviders()
	if len(providers) == 0 {
		// Return rule-based analysis if no AI available
		return vc.ruleBasedAnalysis(vulns), nil
	}

	// Prepare vulnerability summary for AI
	prompt := vc.buildChainPrompt(vulns, context)

	// Query AI for chain analysis
	response, provider, err := vc.provider.QueryRaw(prompt)
	if err != nil {
		fmt.Printf("        [AI Chain] AI analysis failed: %v, using rule-based\n", err)
		return vc.ruleBasedAnalysis(vulns), nil
	}

	// Parse AI response
	analysis, err := vc.parseChainResponse(response)
	if err != nil {
		fmt.Printf("        [AI Chain] Parse failed: %v, using rule-based\n", err)
		return vc.ruleBasedAnalysis(vulns), nil
	}

	analysis.Provider = string(provider)
	return analysis, nil
}

func (vc *VulnChainer) buildChainPrompt(vulns []Vulnerability, ctx *TargetContext) string {
	// Build vulnerability list grouped by severity
	var criticalVulns, highVulns, mediumVulns strings.Builder
	critCount, highCount, medCount := 0, 0, 0

	for _, v := range vulns {
		entry := fmt.Sprintf("    <vuln id=\"%s\" host=\"%s\">%s</vuln>\n", v.TemplateID, v.Host, v.Name)
		switch strings.ToLower(v.Severity) {
		case "critical":
			if critCount < 15 {
				criticalVulns.WriteString(entry)
				critCount++
			}
		case "high":
			if highCount < 15 {
				highVulns.WriteString(entry)
				highCount++
			}
		case "medium":
			if medCount < 10 {
				mediumVulns.WriteString(entry)
				medCount++
			}
		}
	}

	// Build tech stack string
	techStack := "Unknown"
	if len(ctx.Technologies) > 0 {
		techStack = strings.Join(ctx.Technologies, ", ")
	}

	wafStatus := "Not Detected"
	if ctx.WAFDetected {
		wafStatus = "ACTIVE"
	}

	return fmt.Sprintf(`<agent_core>
  <role>You are a Red Team Attack Graph Analyst. Your task is to identify exploitable vulnerability chains.</role>
  <methodology>Graph-of-Thought: Model vulnerabilities as NODES, exploitation paths as EDGES, and goals as TERMINAL STATES.</methodology>
</agent_core>

<target_context>
  <domain>%s</domain>
  <tech_stack>%s</tech_stack>
  <waf_status>%s</waf_status>
  <total_vulns>%d</total_vulns>
</target_context>

<vulnerability_inventory>
  <critical_severity>
%s  </critical_severity>
  <high_severity>
%s  </high_severity>
  <medium_severity>
%s  </medium_severity>
</vulnerability_inventory>

<graph_construction_rules>
  <node_types>
    - ENTRY: Externally accessible vulns (XSS, SQLi, SSRF, Default Creds, Exposed Panels)
    - PIVOT: Internal access vulns (LFI, IDOR, API Abuse, Session Fixation)
    - ESCALATION: Privilege gain vulns (Auth Bypass, Role Manipulation, Kernel Exploits)
    - TERMINAL: Goal achievement (RCE, Data Exfil, Cloud Keys, Domain Admin)
  </node_types>
  <edge_weights>
    - Direct exploit = 1.0 (single step)
    - Requires info from previous = 0.7 (needs data leak first)
    - Probabilistic success = 0.5 (depends on config)
    - Theoretical only = 0.2 (requires assumptions)
  </edge_weights>
</graph_construction_rules>

<known_attack_patterns>
  <!-- Cloud Compromise Paths -->
  SSRF -> IMDSv1 -> IAM Credentials -> Cloud Takeover
  Exposed .env -> AWS Keys -> S3 Bucket Access -> Data Breach

  <!-- Web Application Paths -->
  SQLi -> DB Dump -> Password Hashes -> Credential Stuffing -> Admin Access
  XSS -> Session Theft -> Admin Impersonation -> Config Change -> RCE
  LFI -> /etc/passwd -> User Enum -> SSH Bruteforce -> Server Access

  <!-- DevOps/CI Paths -->
  Git Exposure -> Source Code -> Hardcoded Secrets -> Internal Systems
  Jenkins Default Creds -> Script Console -> Groovy RCE -> Server Compromise
  Exposed Docker API -> Container Escape -> Host Compromise
</known_attack_patterns>

<metacognition_checklist>
  Before finalizing, verify each chain:
  [ ] Is this chain ACTUALLY exploitable with the vulns listed?
  [ ] Are the vulns on the SAME host or can they cross hosts?
  [ ] What's the REALISTIC likelihood (not theoretical)?
  [ ] Am I inferring vulns that DON'T EXIST in the inventory?
</metacognition_checklist>

<output_instructions>
  1. First, in <reasoning> tags, list each vuln and classify it as ENTRY/PIVOT/ESCALATION/TERMINAL
  2. Then identify which vulns can connect (same host or logical data flow)
  3. Finally output JSON with ONLY chains that use ACTUAL vulnerabilities from the inventory
</output_instructions>

<output_schema>
{
  "chains": [
    {
      "id": "chain-N",
      "name": "Short descriptive name",
      "description": "How this chain works end-to-end",
      "vulnerabilities": [
        {"template_id": "from-inventory", "name": "Actual Name", "host": "actual.host", "severity": "high", "role": "entry_point|pivot|escalation|target", "order": 1}
      ],
      "impact": "Business impact if exploited",
      "severity": "critical|high|medium",
      "likelihood": "high|medium|low",
      "exploitation_steps": ["Step 1", "Step 2", "..."],
      "mitigations": ["Fix 1", "Fix 2"]
    }
  ],
  "prioritized_vulns": [
    {
      "template_id": "from-inventory",
      "name": "Name",
      "host": "host",
      "severity": "severity",
      "priority": 1-10,
      "chain_count": N,
      "exploitable": true|false,
      "has_public_poc": true|false,
      "reasoning": "Why this priority"
    }
  ],
  "summary": "Found N chains. Highest risk: [description]. Immediate action: [recommendation]."
}
</output_schema>`,
		ctx.Domain,
		techStack,
		wafStatus,
		len(vulns),
		criticalVulns.String(),
		highVulns.String(),
		mediumVulns.String(),
	)
}

func (vc *VulnChainer) parseChainResponse(response string) (*ChainAnalysis, error) {
	// Remove <reasoning> tags (Graph-of-Thought output)
	if idx := strings.Index(response, "</reasoning>"); idx != -1 {
		response = response[idx+len("</reasoning>"):]
	}
	// Also handle case where reasoning tag is at the start
	if idx := strings.Index(response, "<reasoning>"); idx != -1 {
		if endIdx := strings.Index(response, "</reasoning>"); endIdx != -1 {
			response = response[:idx] + response[endIdx+len("</reasoning>"):]
		}
	}

	response = strings.TrimSpace(response)

	// Find JSON in response
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]
	var analysis ChainAnalysis
	if err := json.Unmarshal([]byte(jsonStr), &analysis); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	return &analysis, nil
}

// ruleBasedAnalysis provides chain analysis without AI
func (vc *VulnChainer) ruleBasedAnalysis(vulns []Vulnerability) *ChainAnalysis {
	analysis := &ChainAnalysis{
		Chains:           []VulnChain{},
		PrioritizedVulns: []PrioritizedVuln{},
		Provider:         "rule-based",
	}

	// Group vulnerabilities by type for chaining
	vulnsByType := make(map[string][]Vulnerability)
	for _, v := range vulns {
		vulnType := categorizeVuln(v)
		vulnsByType[vulnType] = append(vulnsByType[vulnType], v)
	}

	// Find common chains
	chains := vc.findRuleBasedChains(vulnsByType)
	analysis.Chains = chains

	// Prioritize vulnerabilities
	analysis.PrioritizedVulns = vc.prioritizeVulns(vulns, chains)

	// Generate summary
	chainTypes := make([]string, 0, len(chains))
	for _, c := range chains {
		chainTypes = append(chainTypes, c.Name)
	}
	if len(chains) > 0 {
		analysis.Summary = fmt.Sprintf("Found %d potential attack chains: %s", len(chains), strings.Join(chainTypes, ", "))
	} else {
		analysis.Summary = "No obvious attack chains identified. Individual vulnerabilities should still be addressed."
	}

	return analysis
}

func categorizeVuln(v Vulnerability) string {
	name := strings.ToLower(v.Name)
	templateID := strings.ToLower(v.TemplateID)
	combined := name + " " + templateID

	switch {
	case strings.Contains(combined, "ssrf"):
		return "ssrf"
	case strings.Contains(combined, "sqli") || strings.Contains(combined, "sql injection"):
		return "sqli"
	case strings.Contains(combined, "xss"):
		return "xss"
	case strings.Contains(combined, "csrf"):
		return "csrf"
	case strings.Contains(combined, "lfi") || strings.Contains(combined, "local file"):
		return "lfi"
	case strings.Contains(combined, "rfi") || strings.Contains(combined, "remote file"):
		return "rfi"
	case strings.Contains(combined, "rce") || strings.Contains(combined, "command injection") || strings.Contains(combined, "code execution"):
		return "rce"
	case strings.Contains(combined, "upload"):
		return "upload"
	case strings.Contains(combined, "auth") || strings.Contains(combined, "bypass"):
		return "auth_bypass"
	case strings.Contains(combined, "default") || strings.Contains(combined, "credential"):
		return "default_creds"
	case strings.Contains(combined, "exposure") || strings.Contains(combined, "disclosure"):
		return "info_disclosure"
	case strings.Contains(combined, "cloud") || strings.Contains(combined, "metadata") || strings.Contains(combined, "aws") || strings.Contains(combined, "gcp"):
		return "cloud"
	case strings.Contains(combined, "admin") || strings.Contains(combined, "panel"):
		return "admin_panel"
	case strings.Contains(combined, "api"):
		return "api"
	default:
		return "other"
	}
}

func (vc *VulnChainer) findRuleBasedChains(vulnsByType map[string][]Vulnerability) []VulnChain {
	var chains []VulnChain
	chainID := 1

	// SSRF + Cloud = Credential Theft
	if ssrfs, ok := vulnsByType["ssrf"]; ok && len(ssrfs) > 0 {
		chain := VulnChain{
			ID:          fmt.Sprintf("chain-%d", chainID),
			Name:        "SSRF to Cloud Metadata",
			Description: "Server-Side Request Forgery can be used to access cloud metadata endpoints and steal credentials",
			Impact:      "Cloud credential theft, lateral movement",
			Severity:    "critical",
			Likelihood:  "high",
			Steps: []string{
				"Identify SSRF vulnerability endpoint",
				"Craft request to cloud metadata endpoint (169.254.169.254)",
				"Extract IAM credentials from metadata response",
				"Use credentials for lateral movement or data exfiltration",
			},
			Mitigations: []string{
				"Block requests to metadata endpoints",
				"Use IMDSv2 on AWS",
				"Implement egress filtering",
			},
		}
		for i, v := range ssrfs {
			chain.Vulns = append(chain.Vulns, ChainedVuln{
				TemplateID: v.TemplateID,
				Name:       v.Name,
				Host:       v.Host,
				Severity:   v.Severity,
				Role:       "entry_point",
				Order:      i + 1,
			})
		}
		chains = append(chains, chain)
		chainID++
	}

	// SQLi + Info Disclosure = Data Breach
	if sqlis, ok := vulnsByType["sqli"]; ok && len(sqlis) > 0 {
		chain := VulnChain{
			ID:          fmt.Sprintf("chain-%d", chainID),
			Name:        "SQL Injection to Data Breach",
			Description: "SQL Injection can be exploited to extract sensitive data from the database",
			Impact:      "Complete database compromise, sensitive data exposure",
			Severity:    "critical",
			Likelihood:  "high",
			Steps: []string{
				"Identify SQL injection point",
				"Enumerate database schema",
				"Extract user credentials and sensitive data",
				"Attempt privilege escalation via database",
			},
			Mitigations: []string{
				"Use parameterized queries",
				"Implement input validation",
				"Apply principle of least privilege to database accounts",
			},
		}
		for i, v := range sqlis {
			chain.Vulns = append(chain.Vulns, ChainedVuln{
				TemplateID: v.TemplateID,
				Name:       v.Name,
				Host:       v.Host,
				Severity:   v.Severity,
				Role:       "entry_point",
				Order:      i + 1,
			})
		}
		chains = append(chains, chain)
		chainID++
	}

	// Default Creds + Admin Panel = Full Compromise
	if defaultCreds, hasDefault := vulnsByType["default_creds"]; hasDefault && len(defaultCreds) > 0 {
		if adminPanels, hasAdmin := vulnsByType["admin_panel"]; hasAdmin && len(adminPanels) > 0 {
			chain := VulnChain{
				ID:          fmt.Sprintf("chain-%d", chainID),
				Name:        "Default Credentials to Admin Access",
				Description: "Default credentials on exposed admin panels lead to full administrative access",
				Impact:      "Full application compromise, potential RCE",
				Severity:    "critical",
				Likelihood:  "high",
				Steps: []string{
					"Access exposed admin panel",
					"Authenticate with default credentials",
					"Gain administrative access",
					"Execute arbitrary commands or modify application",
				},
				Mitigations: []string{
					"Change default credentials immediately",
					"Implement MFA for admin access",
					"Restrict admin panel to internal networks",
				},
			}
			for i, v := range defaultCreds {
				chain.Vulns = append(chain.Vulns, ChainedVuln{
					TemplateID: v.TemplateID,
					Name:       v.Name,
					Host:       v.Host,
					Severity:   v.Severity,
					Role:       "entry_point",
					Order:      i + 1,
				})
			}
			for i, v := range adminPanels {
				chain.Vulns = append(chain.Vulns, ChainedVuln{
					TemplateID: v.TemplateID,
					Name:       v.Name,
					Host:       v.Host,
					Severity:   v.Severity,
					Role:       "target",
					Order:      len(defaultCreds) + i + 1,
				})
			}
			chains = append(chains, chain)
			chainID++
		}
	}

	// XSS + CSRF = Session Hijacking
	if xss, hasXSS := vulnsByType["xss"]; hasXSS && len(xss) > 0 {
		chain := VulnChain{
			ID:          fmt.Sprintf("chain-%d", chainID),
			Name:        "XSS to Account Takeover",
			Description: "Cross-Site Scripting can be chained to steal sessions or perform actions as victims",
			Impact:      "Account takeover, data theft",
			Severity:    "high",
			Likelihood:  "medium",
			Steps: []string{
				"Inject malicious JavaScript via XSS",
				"Capture session tokens or cookies",
				"Hijack victim sessions",
				"Perform actions as authenticated users",
			},
			Mitigations: []string{
				"Implement CSP headers",
				"Use HttpOnly cookies",
				"Sanitize user input",
			},
		}
		for i, v := range xss {
			chain.Vulns = append(chain.Vulns, ChainedVuln{
				TemplateID: v.TemplateID,
				Name:       v.Name,
				Host:       v.Host,
				Severity:   v.Severity,
				Role:       "entry_point",
				Order:      i + 1,
			})
		}
		chains = append(chains, chain)
		chainID++
	}

	// LFI/RFI to RCE
	if lfi, hasLFI := vulnsByType["lfi"]; hasLFI && len(lfi) > 0 {
		chain := VulnChain{
			ID:          fmt.Sprintf("chain-%d", chainID),
			Name:        "LFI to Remote Code Execution",
			Description: "Local File Inclusion can be escalated to remote code execution",
			Impact:      "Full server compromise",
			Severity:    "critical",
			Likelihood:  "medium",
			Steps: []string{
				"Identify LFI vulnerability",
				"Enumerate sensitive files (/etc/passwd, config files)",
				"Attempt log poisoning or wrapper techniques",
				"Achieve code execution via PHP wrappers or log injection",
			},
			Mitigations: []string{
				"Validate and sanitize file paths",
				"Use allowlists for file inclusion",
				"Disable dangerous PHP wrappers",
			},
		}
		for i, v := range lfi {
			chain.Vulns = append(chain.Vulns, ChainedVuln{
				TemplateID: v.TemplateID,
				Name:       v.Name,
				Host:       v.Host,
				Severity:   v.Severity,
				Role:       "entry_point",
				Order:      i + 1,
			})
		}
		chains = append(chains, chain)
		chainID++
	}

	// Auth Bypass + API = Data Exfiltration
	if authBypass, hasAuth := vulnsByType["auth_bypass"]; hasAuth && len(authBypass) > 0 {
		if api, hasAPI := vulnsByType["api"]; hasAPI && len(api) > 0 {
			chain := VulnChain{
				ID:          fmt.Sprintf("chain-%d", chainID),
				Name:        "Auth Bypass to API Data Theft",
				Description: "Authentication bypass combined with API access leads to unauthorized data access",
				Impact:      "Mass data exfiltration",
				Severity:    "critical",
				Likelihood:  "high",
				Steps: []string{
					"Bypass authentication mechanism",
					"Access internal API endpoints",
					"Enumerate available data",
					"Extract sensitive information",
				},
				Mitigations: []string{
					"Fix authentication vulnerabilities",
					"Implement proper access controls",
					"Add rate limiting to APIs",
				},
			}
			for i, v := range authBypass {
				chain.Vulns = append(chain.Vulns, ChainedVuln{
					TemplateID: v.TemplateID,
					Name:       v.Name,
					Host:       v.Host,
					Severity:   v.Severity,
					Role:       "entry_point",
					Order:      i + 1,
				})
			}
			for i, v := range api {
				chain.Vulns = append(chain.Vulns, ChainedVuln{
					TemplateID: v.TemplateID,
					Name:       v.Name,
					Host:       v.Host,
					Severity:   v.Severity,
					Role:       "target",
					Order:      len(authBypass) + i + 1,
				})
			}
			chains = append(chains, chain)
		}
	}

	return chains
}

func (vc *VulnChainer) prioritizeVulns(vulns []Vulnerability, chains []VulnChain) []PrioritizedVuln {
	// Count chain participation
	chainCount := make(map[string]int)
	for _, chain := range chains {
		for _, v := range chain.Vulns {
			chainCount[v.TemplateID]++
		}
	}

	// Calculate priority for each vuln
	var prioritized []PrioritizedVuln
	for _, v := range vulns {
		priority := calculatePriority(v, chainCount[v.TemplateID])
		prioritized = append(prioritized, PrioritizedVuln{
			TemplateID:   v.TemplateID,
			Name:         v.Name,
			Host:         v.Host,
			Severity:     v.Severity,
			Priority:     priority,
			ChainCount:   chainCount[v.TemplateID],
			Exploitable:  isLikelyExploitable(v),
			HasPublicPOC: hasPublicPOC(v),
			Reasoning:    generatePriorityReasoning(v, priority, chainCount[v.TemplateID]),
		})
	}

	// Sort by priority (descending)
	sort.Slice(prioritized, func(i, j int) bool {
		return prioritized[i].Priority > prioritized[j].Priority
	})

	return prioritized
}

func calculatePriority(v Vulnerability, chainCount int) int {
	priority := 0

	// Base severity score
	switch strings.ToLower(v.Severity) {
	case "critical":
		priority += 4
	case "high":
		priority += 3
	case "medium":
		priority += 2
	case "low":
		priority += 1
	}

	// Chain participation bonus
	priority += chainCount * 2

	// Exploitability bonus
	if isLikelyExploitable(v) {
		priority += 2
	}

	// Public POC bonus
	if hasPublicPOC(v) {
		priority += 1
	}

	// Cap at 10
	if priority > 10 {
		priority = 10
	}

	return priority
}

func isLikelyExploitable(v Vulnerability) bool {
	exploitablePatterns := []string{
		"rce", "sqli", "sql injection", "ssrf", "command injection",
		"default", "credential", "upload", "deserialization",
		"auth bypass", "idor", "lfi", "rfi",
	}

	combined := strings.ToLower(v.Name + " " + v.TemplateID)
	for _, pattern := range exploitablePatterns {
		if strings.Contains(combined, pattern) {
			return true
		}
	}
	return false
}

func hasPublicPOC(v Vulnerability) bool {
	// CVEs typically have POCs
	if strings.HasPrefix(strings.ToLower(v.TemplateID), "cve-") {
		return true
	}
	// Well-known vulnerability classes
	pocPatterns := []string{"wordpress", "jenkins", "grafana", "jira", "gitlab"}
	combined := strings.ToLower(v.Name + " " + v.TemplateID)
	for _, pattern := range pocPatterns {
		if strings.Contains(combined, pattern) {
			return true
		}
	}
	return false
}

func generatePriorityReasoning(v Vulnerability, priority int, chainCount int) string {
	var reasons []string

	switch strings.ToLower(v.Severity) {
	case "critical":
		reasons = append(reasons, "Critical severity")
	case "high":
		reasons = append(reasons, "High severity")
	}

	if chainCount > 0 {
		reasons = append(reasons, fmt.Sprintf("Part of %d attack chain(s)", chainCount))
	}

	if isLikelyExploitable(v) {
		reasons = append(reasons, "Likely exploitable")
	}

	if hasPublicPOC(v) {
		reasons = append(reasons, "Public POC available")
	}

	if len(reasons) == 0 {
		return "Standard priority"
	}

	return strings.Join(reasons, "; ")
}
