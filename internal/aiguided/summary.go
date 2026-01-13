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
	TotalHosts       int      `json:"total_hosts"`
	TotalEndpoints   int      `json:"total_endpoints"`
	TotalParameters  int      `json:"total_parameters"`
	TotalJSFiles     int      `json:"total_js_files"`
	TotalAPIs        int      `json:"total_apis"`
	Technologies     []string `json:"technologies"`
	ExposedServices  []string `json:"exposed_services"`
	DirectHosts      int      `json:"direct_hosts"`  // Non-WAF protected
	CDNProtected     int      `json:"cdn_protected"` // WAF protected
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
	f, _ := os.Create(filepath.Join(dir, "attack_surface_report.txt"))
	defer f.Close()

	fmt.Fprintf(f, "ASSET SUMMARY REPORT - %s\n", s.Domain)
	fmt.Fprintf(f, "Risk Score: %d/100\n", s.RiskScore)
	fmt.Fprintf(f, strings.Repeat("=", 60)+"\n\n")

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
