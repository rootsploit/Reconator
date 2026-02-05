package aiguided

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AssetSummary provides comprehensive analysis of the attack surface
type AssetSummary struct {
	Domain           string            `json:"domain"`
	AttackSurface    AttackSurface     `json:"attack_surface"`
	ManualChecks     []ManualCheck     `json:"manual_checks"`
	InterestingFinds []InterestingFind `json:"interesting_finds"`
	Priorities       []Priority        `json:"priorities"`
	RiskScore        int               `json:"risk_score"` // 0-100
}

// AttackSurface summarizes the discovered attack surface
type AttackSurface struct {
	TotalHosts            int      `json:"total_hosts"`
	TotalEndpoints        int      `json:"total_endpoints"`
	TotalParameters       int      `json:"total_parameters"`
	TotalJSFiles          int      `json:"total_js_files"`
	TotalAPIs             int      `json:"total_apis"`
	Technologies          []string `json:"technologies"`
	ExposedServices       []string `json:"exposed_services"`
	DirectHosts           int      `json:"direct_hosts"`  // Non-WAF protected
	CDNProtected          int      `json:"cdn_protected"` // WAF protected
	SecurityHeaderIssues  int      `json:"security_header_issues"`  // Hosts with missing security headers
}

// ManualCheck suggests areas that need manual security review
type ManualCheck struct {
	Category    string   `json:"category"` // SQLi, XSS, SSRF, Auth, etc.
	Confidence  string   `json:"confidence"` // high, medium, low
	Reason      string   `json:"reason"`
	Evidence    []string `json:"evidence"`
	SuggestedTests []string `json:"suggested_tests"`
}

// InterestingFind highlights notable discoveries
type InterestingFind struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Impact      string `json:"impact"`
}

// Priority ranks areas to focus on
type Priority struct {
	Rank        int    `json:"rank"`
	Area        string `json:"area"`
	Reason      string `json:"reason"`
	Effort      string `json:"effort"` // low, medium, high
	Impact      string `json:"impact"` // low, medium, high, critical
}

// GenerateAssetSummary creates a comprehensive summary for manual review
func GenerateAssetSummary(ctx *TargetContext, categorizedURLs map[string][]string, vulns []Vulnerability) *AssetSummary {
	summary := &AssetSummary{
		Domain: ctx.Domain,
		AttackSurface: AttackSurface{
			TotalEndpoints:  len(ctx.Endpoints),
			TotalJSFiles:    len(ctx.JSFiles),
			TotalAPIs:       len(ctx.APIEndpoints),
			Technologies:    ctx.Technologies,
			CDNProtected:    ctx.CDNHosts,
		},
		ManualChecks:     []ManualCheck{},
		InterestingFinds: []InterestingFind{},
		Priorities:       []Priority{},
	}

	// Count parameters
	paramCount := 0
	for _, endpoint := range ctx.Endpoints {
		paramCount += strings.Count(endpoint, "=")
	}
	summary.AttackSurface.TotalParameters = paramCount

	// Analyze for potential SQLi
	if sqliURLs, ok := categorizedURLs["sqli"]; ok && len(sqliURLs) > 0 {
		summary.ManualChecks = append(summary.ManualChecks, ManualCheck{
			Category:   "SQL Injection",
			Confidence: determineConfidence(len(sqliURLs), paramCount),
			Reason:     fmt.Sprintf("Found %d URLs with SQL-injectable parameters", len(sqliURLs)),
			Evidence:   truncateList(sqliURLs, 5),
			SuggestedTests: []string{
				"Test with sqlmap: sqlmap -u 'URL' --batch --dbs",
				"Manual testing with: ' OR '1'='1' -- ",
				"Error-based: ' AND 1=CONVERT(int,@@version)--",
				"Time-based: ' AND SLEEP(5)--",
			},
		})
	} else if paramCount > 10 {
		summary.ManualChecks = append(summary.ManualChecks, ManualCheck{
			Category:   "SQL Injection",
			Confidence: "low",
			Reason:     fmt.Sprintf("No obvious SQLi patterns but %d parameters found - worth manual testing", paramCount),
			Evidence:   []string{fmt.Sprintf("%d total parameters across endpoints", paramCount)},
			SuggestedTests: []string{
				"Identify numeric ID parameters",
				"Test search/filter functionality",
				"Check API endpoints with query params",
			},
		})
	}

	// Analyze for potential XSS
	if xssURLs, ok := categorizedURLs["xss"]; ok && len(xssURLs) > 0 {
		summary.ManualChecks = append(summary.ManualChecks, ManualCheck{
			Category:   "Cross-Site Scripting (XSS)",
			Confidence: determineConfidence(len(xssURLs), paramCount),
			Reason:     fmt.Sprintf("Found %d URLs with XSS-prone parameters", len(xssURLs)),
			Evidence:   truncateList(xssURLs, 5),
			SuggestedTests: []string{
				"Test with dalfox: dalfox url 'URL' --skip-bav",
				"Manual: <script>alert(1)</script>",
				"Event handlers: \" onmouseover=\"alert(1)",
				"DOM XSS: Check JS files for document.write, innerHTML, eval",
			},
		})
	}

	// Analyze for SSRF
	if ssrfURLs, ok := categorizedURLs["ssrf"]; ok && len(ssrfURLs) > 0 {
		summary.ManualChecks = append(summary.ManualChecks, ManualCheck{
			Category:   "Server-Side Request Forgery (SSRF)",
			Confidence: determineConfidence(len(ssrfURLs), len(ctx.Endpoints)),
			Reason:     fmt.Sprintf("Found %d URLs with URL/redirect parameters", len(ssrfURLs)),
			Evidence:   truncateList(ssrfURLs, 5),
			SuggestedTests: []string{
				"Test with Burp Collaborator or webhook.site",
				"AWS metadata: http://169.254.169.254/latest/meta-data/",
				"Internal scan: http://127.0.0.1:PORT",
				"DNS rebinding techniques",
			},
		})
	}

	// Analyze for LFI
	if lfiURLs, ok := categorizedURLs["lfi"]; ok && len(lfiURLs) > 0 {
		summary.ManualChecks = append(summary.ManualChecks, ManualCheck{
			Category:   "Local File Inclusion (LFI)",
			Confidence: determineConfidence(len(lfiURLs), len(ctx.Endpoints)),
			Reason:     fmt.Sprintf("Found %d URLs with file/path parameters", len(lfiURLs)),
			Evidence:   truncateList(lfiURLs, 5),
			SuggestedTests: []string{
				"Path traversal: ../../etc/passwd",
				"Null byte: /etc/passwd%00.jpg",
				"Wrapper: php://filter/convert.base64-encode/resource=",
				"Log poisoning if error logs accessible",
			},
		})
	}

	// Check for authentication issues
	if sensitiveURLs, ok := categorizedURLs["sensitive"]; ok && len(sensitiveURLs) > 0 {
		summary.ManualChecks = append(summary.ManualChecks, ManualCheck{
			Category:   "Authentication & Authorization",
			Confidence: "medium",
			Reason:     fmt.Sprintf("Found %d admin/auth endpoints", len(sensitiveURLs)),
			Evidence:   truncateList(sensitiveURLs, 5),
			SuggestedTests: []string{
				"Test for default credentials",
				"Check for IDOR vulnerabilities",
				"Test session handling",
				"Verify 2FA enforcement",
			},
		})
	}

	// JS Files analysis
	if len(ctx.JSFiles) > 0 {
		summary.InterestingFinds = append(summary.InterestingFinds, InterestingFind{
			Type:        "JavaScript Files",
			Description: fmt.Sprintf("%d JavaScript files discovered - potential for secrets/endpoints", len(ctx.JSFiles)),
			Location:    strings.Join(truncateList(ctx.JSFiles, 3), ", "),
			Impact:      "May contain API keys, internal endpoints, business logic",
		})
	}

	// API analysis
	if len(ctx.APIEndpoints) > 0 {
		summary.InterestingFinds = append(summary.InterestingFinds, InterestingFind{
			Type:        "API Endpoints",
			Description: fmt.Sprintf("%d API endpoints discovered", len(ctx.APIEndpoints)),
			Location:    strings.Join(truncateList(ctx.APIEndpoints, 3), ", "),
			Impact:      "Check for broken access control, rate limiting, data exposure",
		})
	}

	// Technology-specific findings
	for _, tech := range ctx.Technologies {
		techLower := strings.ToLower(tech)
		switch {
		case strings.Contains(techLower, "wordpress"):
			summary.InterestingFinds = append(summary.InterestingFinds, InterestingFind{
				Type:        "CMS Detection",
				Description: "WordPress detected - check for vulnerable plugins",
				Location:    ctx.Domain,
				Impact:      "Many plugins have known vulnerabilities",
			})
		case strings.Contains(techLower, "jenkins"):
			summary.InterestingFinds = append(summary.InterestingFinds, InterestingFind{
				Type:        "CI/CD System",
				Description: "Jenkins detected - high-value target",
				Location:    ctx.Domain,
				Impact:      "Script console access = RCE",
			})
		case strings.Contains(techLower, "gitlab"):
			summary.InterestingFinds = append(summary.InterestingFinds, InterestingFind{
				Type:        "Code Repository",
				Description: "GitLab detected - check for public repos/tokens",
				Location:    ctx.Domain,
				Impact:      "Source code exposure, CI/CD secrets",
			})
		}
	}

	// Generate priorities
	summary.Priorities = generatePriorities(summary)

	// Calculate risk score
	summary.RiskScore = calculateRiskScore(summary)

	return summary
}

// SetSecurityHeaderIssues sets the count of hosts with security header issues
func (s *AssetSummary) SetSecurityHeaderIssues(count int) {
	s.AttackSurface.SecurityHeaderIssues = count
}

func determineConfidence(matches, total int) string {
	if total == 0 {
		return "low"
	}
	ratio := float64(matches) / float64(total)
	if ratio > 0.3 || matches > 20 {
		return "high"
	} else if ratio > 0.1 || matches > 5 {
		return "medium"
	}
	return "low"
}

func truncateList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func generatePriorities(summary *AssetSummary) []Priority {
	var priorities []Priority
	rank := 1

	// High confidence findings first
	for _, check := range summary.ManualChecks {
		if check.Confidence == "high" {
			priorities = append(priorities, Priority{
				Rank:   rank,
				Area:   check.Category,
				Reason: check.Reason,
				Effort: "low",
				Impact: "high",
			})
			rank++
		}
	}

	// Medium confidence
	for _, check := range summary.ManualChecks {
		if check.Confidence == "medium" {
			priorities = append(priorities, Priority{
				Rank:   rank,
				Area:   check.Category,
				Reason: check.Reason,
				Effort: "medium",
				Impact: "medium",
			})
			rank++
		}
	}

	// Interesting findings
	for _, find := range summary.InterestingFinds {
		priorities = append(priorities, Priority{
			Rank:   rank,
			Area:   find.Type,
			Reason: find.Description,
			Effort: "medium",
			Impact: "medium",
		})
		rank++
	}

	return priorities
}

func calculateRiskScore(summary *AssetSummary) int {
	score := 0

	// Attack surface
	if summary.AttackSurface.TotalParameters > 50 {
		score += 10
	}
	if summary.AttackSurface.TotalAPIs > 10 {
		score += 10
	}
	if summary.AttackSurface.DirectHosts > 0 {
		score += 15 // Direct access without WAF
	}

	// Manual checks
	for _, check := range summary.ManualChecks {
		switch check.Confidence {
		case "high":
			score += 20
		case "medium":
			score += 10
		case "low":
			score += 5
		}
	}

	// Interesting findings
	score += len(summary.InterestingFinds) * 5

	if score > 100 {
		score = 100
	}
	return score
}

// SaveAssetSummary saves the summary to JSON and human-readable format
func (s *AssetSummary) SaveAssetSummary(dir string) error {
	os.MkdirAll(dir, 0755)

	// Save JSON
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(filepath.Join(dir, "asset_summary.json"), data, 0644)

	// Save human-readable report
	f, err := os.Create(filepath.Join(dir, "attack_surface_report.txt"))
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "ASSET SUMMARY REPORT - %s\n", s.Domain)
	fmt.Fprintf(f, "Risk Score: %d/100\n", s.RiskScore)
	fmt.Fprintf(f, "%s\n\n", strings.Repeat("=", 60))

	fmt.Fprintf(f, "ATTACK SURFACE\n")
	fmt.Fprintf(f, "--------------\n")
	fmt.Fprintf(f, "Endpoints: %d | Parameters: %d | JS Files: %d | APIs: %d\n",
		s.AttackSurface.TotalEndpoints, s.AttackSurface.TotalParameters,
		s.AttackSurface.TotalJSFiles, s.AttackSurface.TotalAPIs)
	fmt.Fprintf(f, "Technologies: %s\n\n", strings.Join(s.AttackSurface.Technologies, ", "))

	fmt.Fprintf(f, "MANUAL CHECKS RECOMMENDED\n")
	fmt.Fprintf(f, "-------------------------\n")
	for _, check := range s.ManualChecks {
		fmt.Fprintf(f, "[%s] %s (Confidence: %s)\n", check.Category, check.Reason, check.Confidence)
		fmt.Fprintf(f, "  Evidence: %s\n", strings.Join(check.Evidence, ", "))
		fmt.Fprintf(f, "  Tests:\n")
		for _, test := range check.SuggestedTests {
			fmt.Fprintf(f, "    - %s\n", test)
		}
		fmt.Fprintf(f, "\n")
	}

	fmt.Fprintf(f, "INTERESTING FINDINGS\n")
	fmt.Fprintf(f, "--------------------\n")
	for _, find := range s.InterestingFinds {
		fmt.Fprintf(f, "[%s] %s\n  Location: %s\n  Impact: %s\n\n",
			find.Type, find.Description, find.Location, find.Impact)
	}

	fmt.Fprintf(f, "PRIORITIES\n")
	fmt.Fprintf(f, "----------\n")
	for _, p := range s.Priorities {
		fmt.Fprintf(f, "%d. %s (Effort: %s, Impact: %s)\n   %s\n\n",
			p.Rank, p.Area, p.Effort, p.Impact, p.Reason)
	}

	return nil
}

// ExecutiveSummary represents an AI-generated executive summary
type ExecutiveSummary struct {
	OneLiner           string   `json:"one_liner"`
	KeyFindings        []string `json:"key_findings"`
	ImmediateActions   []string `json:"immediate_actions"`
	RiskAssessment     string   `json:"risk_assessment"`
	BusinessImpact     string   `json:"business_impact"`
	RecommendedNextSteps []string `json:"recommended_next_steps"`
	Provider           string   `json:"provider"`
}

// SummaryGenerator generates AI-powered executive summaries
type SummaryGenerator struct {
	provider *ProviderManager
}

// NewSummaryGenerator creates a new AI summary generator
func NewSummaryGenerator() *SummaryGenerator {
	pm := NewProviderManager()
	pm.LoadFromEnv()
	configPath := GetDefaultConfigPath()
	pm.LoadFromFile(configPath)

	return &SummaryGenerator{provider: pm}
}

// GenerateExecutiveSummary creates an AI-powered executive summary
func (sg *SummaryGenerator) GenerateExecutiveSummary(summary *AssetSummary, vulns []Vulnerability, chainAnalysis *ChainAnalysis) (*ExecutiveSummary, error) {
	providers := sg.provider.GetAvailableProviders()
	if len(providers) == 0 {
		// Return rule-based summary if no AI available
		return sg.generateRuleBasedSummary(summary, vulns), nil
	}

	prompt := sg.buildSummaryPrompt(summary, vulns, chainAnalysis)

	response, provider, err := sg.provider.QueryRaw(prompt)
	if err != nil {
		fmt.Printf("        [AI Summary] AI generation failed: %v, using rule-based\n", err)
		return sg.generateRuleBasedSummary(summary, vulns), nil
	}

	execSummary, err := sg.parseSummaryResponse(response)
	if err != nil {
		fmt.Printf("        [AI Summary] Parse failed: %v, using rule-based\n", err)
		return sg.generateRuleBasedSummary(summary, vulns), nil
	}

	execSummary.Provider = string(provider)
	return execSummary, nil
}

func (sg *SummaryGenerator) buildSummaryPrompt(summary *AssetSummary, vulns []Vulnerability, chainAnalysis *ChainAnalysis) string {
	// Count vulnerabilities by severity
	critCount, highCount, medCount, lowCount := 0, 0, 0, 0
	var criticalVulns, highVulns []string
	for _, v := range vulns {
		entry := fmt.Sprintf("%s: %s (%s)", v.TemplateID, v.Name, v.Host)
		switch strings.ToLower(v.Severity) {
		case "critical":
			critCount++
			if len(criticalVulns) < 5 {
				criticalVulns = append(criticalVulns, entry)
			}
		case "high":
			highCount++
			if len(highVulns) < 5 {
				highVulns = append(highVulns, entry)
			}
		case "medium":
			medCount++
		case "low":
			lowCount++
		}
	}

	// Build chain summary
	chainSummary := "No attack chains identified"
	if chainAnalysis != nil && len(chainAnalysis.Chains) > 0 {
		var chains []string
		for _, c := range chainAnalysis.Chains {
			if len(chains) < 3 {
				chains = append(chains, fmt.Sprintf("%s (%s)", c.Name, c.Severity))
			}
		}
		chainSummary = strings.Join(chains, "; ")
	}

	// Build manual checks summary
	var highConfChecks []string
	for _, check := range summary.ManualChecks {
		if check.Confidence == "high" && len(highConfChecks) < 3 {
			highConfChecks = append(highConfChecks, check.Category)
		}
	}

	return fmt.Sprintf(`<agent_core>
  <role>You are a Senior Security Consultant writing an Executive Briefing for a CISO.</role>
  <methodology>Pyramid Principle: Lead with the conclusion, then support with key findings.</methodology>
  <constraint>Be concise, actionable, and business-focused. No technical jargon in the one-liner.</constraint>
</agent_core>

<co_star_context>
  <context>Security reconnaissance completed on %s</context>
  <objective>Provide actionable executive summary for security leadership</objective>
  <style>Professional, concise, risk-focused</style>
  <tone>Authoritative but not alarmist</tone>
  <audience>CISO, Security Director, Engineering Leadership</audience>
  <response>Structured JSON with clear action items</response>
</co_star_context>

<critical_rules>
  IMPORTANT: Follow these rules strictly:
  1. NEVER claim "strong security posture" or "robust security" if there are ANY issues (including low severity or info findings)
  2. Security header issues ARE security issues - they must be mentioned in findings
  3. Always list the actual issues found by severity (critical, high, medium, low)
  4. If only low/info issues exist, still highlight them as "areas for improvement"
  5. Only say "no issues found" if vulnerabilities AND security_headers.hosts_with_issues are both 0
</critical_rules>

<scan_results>
  <target>%s</target>
  <risk_score>%d/100</risk_score>
  <attack_surface>
    <endpoints>%d</endpoints>
    <parameters>%d</parameters>
    <js_files>%d</js_files>
    <api_endpoints>%d</api_endpoints>
    <technologies>%s</technologies>
    <waf_protected>%d hosts</waf_protected>
    <direct_access>%d hosts (no WAF)</direct_access>
  </attack_surface>
  <vulnerabilities>
    <total>%d</total>
    <by_severity>
      <critical_count>%d</critical_count>
      <high_count>%d</high_count>
      <medium_count>%d</medium_count>
      <low_count>%d</low_count>
    </by_severity>
    <critical_examples>%s</critical_examples>
    <high_examples>%s</high_examples>
  </vulnerabilities>
  <security_headers>
    <hosts_with_issues>%d</hosts_with_issues>
    <severity>low</severity>
    <note>Missing headers like CSP, HSTS, X-Frame-Options are LOW severity issues that should be addressed</note>
  </security_headers>
  <attack_chains>%s</attack_chains>
  <high_confidence_issues>%s</high_confidence_issues>
</scan_results>

<output_requirements>
  <pyramid_structure>
    1. ONE-LINER: Single sentence describing what was found (NOT claiming strong security if issues exist)
    2. KEY FINDINGS: 3-5 bullet points - MUST include security header issues if hosts_with_issues > 0
    3. IMMEDIATE ACTIONS: 2-3 things to do THIS WEEK
    4. RISK ASSESSMENT: Overall risk level with brief justification
    5. BUSINESS IMPACT: Base this on actual severity counts - if critical_count > 0 OR high_count > 0, impact should be HIGH/CRITICAL
    6. NEXT STEPS: Recommended follow-up activities
  </pyramid_structure>
  <business_impact_rules>
    - If critical_count > 0: Impact = CRITICAL (data breach, RCE, full system compromise)
    - If high_count > 0: Impact = HIGH (unauthorized access, data exposure, service disruption)
    - If medium_count > 50: Impact = MEDIUM (multiple moderate vulnerabilities increase attack surface)
    - If only low_count OR security_header issues: Impact = LOW (address during maintenance)
    - Never downplay the impact if critical or high vulnerabilities exist
  </business_impact_rules>
</output_requirements>

<output_format>
First, in <thinking> tags, analyze the data and determine the most critical issues.
Then output JSON:
{
  "one_liner": "Single sentence describing findings (not claiming strong security if any issues exist)",
  "key_findings": [
    "Finding 1 - most critical",
    "Finding 2",
    "Finding 3 - include security header issues if any"
  ],
  "immediate_actions": [
    "Action 1 - highest priority",
    "Action 2"
  ],
  "risk_assessment": "HIGH/MEDIUM/LOW - Brief justification",
  "business_impact": "What could happen if these issues are not addressed",
  "recommended_next_steps": [
    "Next step 1",
    "Next step 2"
  ]
}
</output_format>`,
		summary.Domain,
		summary.Domain,
		summary.RiskScore,
		summary.AttackSurface.TotalEndpoints,
		summary.AttackSurface.TotalParameters,
		summary.AttackSurface.TotalJSFiles,
		summary.AttackSurface.TotalAPIs,
		strings.Join(summary.AttackSurface.Technologies, ", "),
		summary.AttackSurface.CDNProtected,
		summary.AttackSurface.DirectHosts,
		len(vulns),
		critCount,
		highCount,
		medCount,
		lowCount,
		strings.Join(criticalVulns, "; "),
		strings.Join(highVulns, "; "),
		summary.AttackSurface.SecurityHeaderIssues,
		chainSummary,
		strings.Join(highConfChecks, ", "),
	)
}

func (sg *SummaryGenerator) parseSummaryResponse(response string) (*ExecutiveSummary, error) {
	// Remove <thinking> tags
	if idx := strings.Index(response, "</thinking>"); idx != -1 {
		response = response[idx+len("</thinking>"):]
	}
	if idx := strings.Index(response, "<thinking>"); idx != -1 {
		if endIdx := strings.Index(response, "</thinking>"); endIdx != -1 {
			response = response[:idx] + response[endIdx+len("</thinking>"):]
		}
	}

	response = strings.TrimSpace(response)

	// Strip markdown code blocks
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
	}
	if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
	}
	response = strings.TrimSuffix(response, "```")
	response = strings.TrimSpace(response)

	// Find JSON
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]
	var summary ExecutiveSummary
	if err := json.Unmarshal([]byte(jsonStr), &summary); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	return &summary, nil
}

func (sg *SummaryGenerator) generateRuleBasedSummary(summary *AssetSummary, vulns []Vulnerability) *ExecutiveSummary {
	// Count vulnerabilities by severity (including low and info)
	critCount, highCount, medCount, lowCount, infoCount := 0, 0, 0, 0, 0
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		case "info":
			infoCount++
		}
	}

	// Count total issues (security headers are low severity issues)
	totalIssues := len(vulns) + summary.AttackSurface.SecurityHeaderIssues
	hasSecurityHeaderIssues := summary.AttackSurface.SecurityHeaderIssues > 0

	// Determine risk level - never claim "strong security" if there are ANY issues
	riskLevel := "LOW"
	if summary.RiskScore >= 70 || critCount > 0 {
		riskLevel = "HIGH"
	} else if summary.RiskScore >= 40 || highCount > 2 || medCount > 5 {
		riskLevel = "MEDIUM"
	}

	// Build one-liner - be explicit about issues found
	var oneLiner string
	if totalIssues == 0 && !hasSecurityHeaderIssues {
		oneLiner = fmt.Sprintf("%s scan completed with no vulnerabilities identified across %d endpoints.",
			summary.Domain, summary.AttackSurface.TotalEndpoints)
	} else if critCount > 0 || highCount > 0 {
		oneLiner = fmt.Sprintf("%s requires attention: %d critical, %d high, %d medium, %d low severity issues identified.",
			summary.Domain, critCount, highCount, medCount, lowCount)
	} else if hasSecurityHeaderIssues {
		oneLiner = fmt.Sprintf("%s has %d security header issues across %d hosts that should be addressed.",
			summary.Domain, summary.AttackSurface.SecurityHeaderIssues, summary.AttackSurface.TotalHosts)
	} else {
		oneLiner = fmt.Sprintf("%s has %d low severity issues to review across %d endpoints.",
			summary.Domain, lowCount+infoCount, summary.AttackSurface.TotalEndpoints)
	}

	// Build key findings - always highlight issues found
	var findings []string
	if critCount > 0 {
		findings = append(findings, fmt.Sprintf("%d critical vulnerabilities require immediate attention", critCount))
	}
	if highCount > 0 {
		findings = append(findings, fmt.Sprintf("%d high severity issues detected", highCount))
	}
	if medCount > 0 {
		findings = append(findings, fmt.Sprintf("%d medium severity issues detected", medCount))
	}
	if lowCount > 0 {
		findings = append(findings, fmt.Sprintf("%d low severity issues detected", lowCount))
	}
	if hasSecurityHeaderIssues {
		findings = append(findings, fmt.Sprintf("%d hosts with missing security headers (CSP, HSTS, X-Frame-Options) - low severity", summary.AttackSurface.SecurityHeaderIssues))
	}
	if summary.AttackSurface.DirectHosts > 0 {
		findings = append(findings, fmt.Sprintf("%d hosts directly accessible without WAF protection", summary.AttackSurface.DirectHosts))
	}
	if len(summary.AttackSurface.Technologies) > 0 && len(findings) < 5 {
		findings = append(findings, fmt.Sprintf("Technology stack includes: %s", strings.Join(truncateList(summary.AttackSurface.Technologies, 5), ", ")))
	}
	for _, check := range summary.ManualChecks {
		if check.Confidence == "high" && len(findings) < 6 {
			findings = append(findings, fmt.Sprintf("High confidence %s indicators detected", check.Category))
		}
	}
	// If no findings at all, say so explicitly
	if len(findings) == 0 {
		findings = append(findings, "No significant security issues detected in automated scan")
		findings = append(findings, "Manual testing recommended for business logic vulnerabilities")
	}

	// Build immediate actions
	var actions []string
	if critCount > 0 {
		actions = append(actions, "Remediate critical vulnerabilities within 24-48 hours")
	}
	if highCount > 0 {
		actions = append(actions, "Address high severity issues within 1 week")
	}
	if summary.AttackSurface.DirectHosts > 0 {
		actions = append(actions, "Enable WAF/CDN protection for exposed hosts")
	}
	if hasSecurityHeaderIssues {
		actions = append(actions, "Deploy missing security headers (CSP, HSTS, X-Frame-Options)")
	}
	for _, check := range summary.ManualChecks {
		if check.Confidence == "high" && len(actions) < 4 {
			actions = append(actions, fmt.Sprintf("Investigate %s findings with manual testing", check.Category))
		}
	}
	if len(actions) == 0 {
		actions = append(actions, "Continue regular security monitoring")
		actions = append(actions, "Schedule periodic penetration testing")
	}

	// Build business impact - be realistic about issues
	var businessImpact string
	if riskLevel == "HIGH" {
		businessImpact = "Critical vulnerabilities could lead to data breach, service disruption, or unauthorized access. Immediate remediation required."
	} else if riskLevel == "MEDIUM" {
		businessImpact = "Identified issues present moderate risk of exploitation. Remediation should be prioritized within the next sprint cycle."
	} else if hasSecurityHeaderIssues || lowCount > 0 {
		businessImpact = "Low severity issues identified. While not immediately exploitable, missing security headers can enable certain attack vectors (clickjacking, MIME sniffing). Address during regular maintenance."
	} else {
		businessImpact = "No significant vulnerabilities found in automated scanning. Manual testing recommended to identify business logic issues."
	}

	// Build next steps
	var nextSteps []string
	if critCount > 0 || highCount > 0 {
		nextSteps = append(nextSteps, "Schedule immediate vulnerability remediation sprint")
	}
	if hasSecurityHeaderIssues {
		nextSteps = append(nextSteps, "Implement security headers across all web servers")
	}
	nextSteps = append(nextSteps, "Conduct manual penetration testing for business logic vulnerabilities")
	nextSteps = append(nextSteps, "Review and update security monitoring for identified attack vectors")

	return &ExecutiveSummary{
		OneLiner:           oneLiner,
		KeyFindings:        findings,
		ImmediateActions:   actions,
		RiskAssessment:     fmt.Sprintf("%s - Risk score %d/100 based on attack surface and vulnerability analysis", riskLevel, summary.RiskScore),
		BusinessImpact:     businessImpact,
		RecommendedNextSteps: nextSteps,
		Provider:           "rule-based",
	}
}

// SaveExecutiveSummary saves the executive summary to a file
func (es *ExecutiveSummary) SaveExecutiveSummary(dir string) error {
	os.MkdirAll(dir, 0755)

	// Save JSON
	data, _ := json.MarshalIndent(es, "", "  ")
	os.WriteFile(filepath.Join(dir, "executive_summary.json"), data, 0644)

	// Save human-readable report
	f, err := os.Create(filepath.Join(dir, "executive_summary.txt"))
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "EXECUTIVE SECURITY SUMMARY\n")
	fmt.Fprintf(f, "%s\n\n", strings.Repeat("=", 60))

	fmt.Fprintf(f, "BOTTOM LINE\n")
	fmt.Fprintf(f, "-----------\n")
	fmt.Fprintf(f, "%s\n\n", es.OneLiner)

	fmt.Fprintf(f, "KEY FINDINGS\n")
	fmt.Fprintf(f, "------------\n")
	for i, finding := range es.KeyFindings {
		fmt.Fprintf(f, "%d. %s\n", i+1, finding)
	}
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "IMMEDIATE ACTIONS REQUIRED\n")
	fmt.Fprintf(f, "--------------------------\n")
	for i, action := range es.ImmediateActions {
		fmt.Fprintf(f, "%d. %s\n", i+1, action)
	}
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "RISK ASSESSMENT\n")
	fmt.Fprintf(f, "---------------\n")
	fmt.Fprintf(f, "%s\n\n", es.RiskAssessment)

	fmt.Fprintf(f, "BUSINESS IMPACT\n")
	fmt.Fprintf(f, "---------------\n")
	fmt.Fprintf(f, "%s\n\n", es.BusinessImpact)

	fmt.Fprintf(f, "RECOMMENDED NEXT STEPS\n")
	fmt.Fprintf(f, "----------------------\n")
	for i, step := range es.RecommendedNextSteps {
		fmt.Fprintf(f, "%d. %s\n", i+1, step)
	}

	fmt.Fprintf(f, "\n[Generated by AI: %s]\n", es.Provider)

	return nil
}
