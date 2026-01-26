package secheaders

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// Result holds all security header findings
type Result struct {
	Domain         string              `json:"domain"`
	TotalScanned   int                 `json:"total_scanned"`
	HeaderFindings []HeaderFinding     `json:"header_findings"`
	EmailSecurity  *EmailSecurityCheck `json:"email_security,omitempty"`
	MisconfigVulns []MisconfigVuln     `json:"misconfig_vulns,omitempty"`
	Duration       time.Duration       `json:"duration"`
	// Summary counts
	MissingHeaders   int `json:"missing_headers"`
	WeakHeaders      int `json:"weak_headers"`
	EmailIssues      int `json:"email_issues"`
	MisconfigCount   int `json:"misconfig_count"`
}

// HeaderFinding represents a security header finding for a host
type HeaderFinding struct {
	Host     string               `json:"host"`
	URL      string               `json:"url"`
	Missing  []HeaderIssue        `json:"missing"`
	Weak     []HeaderIssue        `json:"weak"`
	Present  []string             `json:"present"`
	Headers  map[string]string    `json:"headers,omitempty"`
	Score    int                  `json:"score"` // 0-100 security score
}

// HeaderIssue describes a specific header issue
type HeaderIssue struct {
	Header      string `json:"header"`
	Severity    string `json:"severity"` // info, low, medium, high
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// EmailSecurityCheck holds email security findings for the domain
type EmailSecurityCheck struct {
	Domain   string      `json:"domain"`
	SPF      *SPFRecord  `json:"spf"`
	DKIM     *DKIMRecord `json:"dkim"`
	DMARC    *DMARCRecord`json:"dmarc"`
	Score    int         `json:"score"` // 0-100 email security score
}

// SPFRecord holds SPF record analysis
type SPFRecord struct {
	Found       bool   `json:"found"`
	Record      string `json:"record,omitempty"`
	Valid       bool   `json:"valid"`
	Issues      []string `json:"issues,omitempty"`
	Severity    string `json:"severity"` // info, low, medium, high
}

// DKIMRecord holds DKIM record analysis
type DKIMRecord struct {
	Found    bool     `json:"found"`
	Selectors []string `json:"selectors,omitempty"`
	Issues   []string `json:"issues,omitempty"`
	Severity string   `json:"severity"`
}

// DMARCRecord holds DMARC record analysis
type DMARCRecord struct {
	Found    bool   `json:"found"`
	Record   string `json:"record,omitempty"`
	Policy   string `json:"policy,omitempty"` // none, quarantine, reject
	Valid    bool   `json:"valid"`
	Issues   []string `json:"issues,omitempty"`
	Severity string `json:"severity"`
}

// MisconfigVuln represents a misconfiguration vulnerability from nuclei
type MisconfigVuln struct {
	Host       string `json:"host"`
	URL        string `json:"url,omitempty"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Type       string `json:"type"`
	Description string `json:"description,omitempty"`
}

// Checker performs security header checks
type Checker struct {
	cfg *config.Config
	c   *tools.Checker
}

// NewChecker creates a new security header checker
func NewChecker(cfg *config.Config, checker *tools.Checker) *Checker {
	return &Checker{cfg: cfg, c: checker}
}

// Check performs security header and email security checks
func (c *Checker) Check(domain string, hosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Domain:         domain,
		TotalScanned:   len(hosts),
		HeaderFindings: []HeaderFinding{},
		MisconfigVulns: []MisconfigVuln{},
	}

	if len(hosts) == 0 {
		return result, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Phase 1: Check HTTP security headers using httpx
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("        Checking HTTP security headers...")
		findings := c.checkHTTPHeaders(hosts)
		mu.Lock()
		result.HeaderFindings = findings
		for _, f := range findings {
			result.MissingHeaders += len(f.Missing)
			result.WeakHeaders += len(f.Weak)
		}
		mu.Unlock()
		fmt.Printf("        HTTP headers: %d hosts scanned, %d missing, %d weak\n",
			len(findings), result.MissingHeaders, result.WeakHeaders)
	}()

	// Phase 2: Check email security (SPF/DKIM/DMARC) via DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("        Checking email security (SPF/DKIM/DMARC)...")
		emailCheck := c.checkEmailSecurity(domain)
		mu.Lock()
		result.EmailSecurity = emailCheck
		if emailCheck != nil {
			if emailCheck.SPF != nil && !emailCheck.SPF.Found {
				result.EmailIssues++
			}
			if emailCheck.DMARC != nil && !emailCheck.DMARC.Found {
				result.EmailIssues++
			}
			if emailCheck.DMARC != nil && emailCheck.DMARC.Policy == "none" {
				result.EmailIssues++
			}
		}
		mu.Unlock()
		if emailCheck != nil {
			fmt.Printf("        Email security: SPF=%v, DKIM=%v, DMARC=%v (score: %d/100)\n",
				emailCheck.SPF.Found, emailCheck.DKIM.Found, emailCheck.DMARC.Found, emailCheck.Score)
		}
	}()

	// Phase 3: Run nuclei security-misconfiguration templates
	if c.c.IsInstalled("nuclei") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running nuclei misconfig templates...")
			vulns := c.nucleiMisconfigScan(hosts)
			mu.Lock()
			result.MisconfigVulns = vulns
			result.MisconfigCount = len(vulns)
			mu.Unlock()
			fmt.Printf("        nuclei misconfig: %d findings\n", len(vulns))
		}()
	}

	wg.Wait()
	result.Duration = time.Since(start)

	return result, nil
}

// checkHTTPHeaders checks security headers for each host using httpx
func (c *Checker) checkHTTPHeaders(hosts []string) []HeaderFinding {
	var findings []HeaderFinding

	if !c.c.IsInstalled("httpx") {
		return findings
	}

	// Create temp file with hosts
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-secheaders.txt")
	if err != nil {
		return findings
	}
	defer cleanup()

	// httpx with response headers in JSON
	args := []string{
		"-l", tmpFile,
		"-silent",
		"-json",
		"-include-response-header",
		"-timeout", "10",
	}
	if c.cfg.Threads > 0 {
		threads := c.cfg.Threads
		if threads > 25 {
			threads = 25
		}
		args = append(args, "-threads", fmt.Sprintf("%d", threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return findings
	}

	// Parse results and check headers
	seenHosts := make(map[string]bool)
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}

		var entry struct {
			URL           string            `json:"url"`
			Host          string            `json:"host"`
			ResponseHeaders map[string]string `json:"header,omitempty"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		host := entry.Host
		if host == "" {
			continue
		}
		// Deduplicate by host
		if seenHosts[host] {
			continue
		}
		seenHosts[host] = true

		finding := c.analyzeHeaders(host, entry.URL, entry.ResponseHeaders)
		findings = append(findings, finding)
	}

	return findings
}

// analyzeHeaders analyzes response headers for security issues
func (c *Checker) analyzeHeaders(host, url string, headers map[string]string) HeaderFinding {
	finding := HeaderFinding{
		Host:    host,
		URL:     url,
		Headers: headers,
		Present: []string{},
		Missing: []HeaderIssue{},
		Weak:    []HeaderIssue{},
		Score:   100,
	}

	// Normalize header names to lowercase for comparison
	normalizedHeaders := make(map[string]string)
	for k, v := range headers {
		normalizedHeaders[strings.ToLower(k)] = v
	}

	// Security headers to check
	// NOTE: All security headers are classified as "low" severity to avoid confusion
	// Missing security headers are important to fix but not critical vulnerabilities
	securityHeaders := []struct {
		Name        string
		Severity    string
		Required    bool
		Description string
		Remediation string
		Validator   func(string) (bool, string) // Returns (valid, issue)
	}{
		{
			Name:        "X-Frame-Options",
			Severity:    "low",
			Required:    true,
			Description: "Prevents clickjacking attacks by controlling frame embedding",
			Remediation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
			Validator: func(v string) (bool, string) {
				v = strings.ToUpper(v)
				if v == "DENY" || v == "SAMEORIGIN" {
					return true, ""
				}
				if strings.HasPrefix(v, "ALLOW-FROM") {
					return true, "ALLOW-FROM is deprecated and not supported in modern browsers"
				}
				return false, "Invalid X-Frame-Options value"
			},
		},
		{
			Name:        "Content-Security-Policy",
			Severity:    "low",
			Required:    true,
			Description: "Prevents XSS and data injection attacks",
			Remediation: "Add Content-Security-Policy header with appropriate directives",
			Validator: func(v string) (bool, string) {
				if strings.Contains(v, "unsafe-inline") && !strings.Contains(v, "nonce-") {
					return true, "Contains unsafe-inline without nonce (XSS risk)"
				}
				if strings.Contains(v, "unsafe-eval") {
					return true, "Contains unsafe-eval (potential XSS risk)"
				}
				if strings.Contains(v, "*") && !strings.Contains(v, "*.") {
					return true, "Contains wildcard source (overly permissive)"
				}
				return true, ""
			},
		},
		{
			Name:        "X-Content-Type-Options",
			Severity:    "low",
			Required:    true,
			Description: "Prevents MIME type sniffing attacks",
			Remediation: "Add 'X-Content-Type-Options: nosniff'",
			Validator: func(v string) (bool, string) {
				if strings.ToLower(v) == "nosniff" {
					return true, ""
				}
				return false, "Should be 'nosniff'"
			},
		},
		{
			Name:        "X-XSS-Protection",
			Severity:    "info",
			Required:    false, // Deprecated but still checked
			Description: "Legacy XSS filter (deprecated in modern browsers)",
			Remediation: "Consider removing or set to '0' as CSP is preferred",
			Validator: func(v string) (bool, string) {
				// X-XSS-Protection is deprecated; CSP is preferred
				// "1; mode=block" was the old recommendation
				// "0" is now recommended if CSP is in place
				return true, ""
			},
		},
		{
			Name:        "Strict-Transport-Security",
			Severity:    "low",
			Required:    true,
			Description: "Enforces HTTPS connections - prevents downgrade attacks",
			Remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
			Validator: func(v string) (bool, string) {
				if !strings.Contains(v, "max-age=") {
					return false, "Missing max-age directive"
				}
				// Check for weak max-age
				if strings.Contains(v, "max-age=0") {
					return false, "max-age=0 disables HSTS"
				}
				return true, ""
			},
		},
		{
			Name:        "Referrer-Policy",
			Severity:    "low",
			Required:    false,
			Description: "Controls referrer information sent with requests",
			Remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'",
			Validator: func(v string) (bool, string) {
				safe := []string{"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
				v = strings.ToLower(v)
				for _, s := range safe {
					if v == s {
						return true, ""
					}
				}
				if v == "unsafe-url" {
					return true, "unsafe-url leaks full URL in referrer"
				}
				return true, ""
			},
		},
		{
			Name:        "Permissions-Policy",
			Severity:    "low",
			Required:    false,
			Description: "Controls browser features and APIs",
			Remediation: "Add Permissions-Policy to restrict unnecessary browser features",
			Validator: func(v string) (bool, string) {
				return true, ""
			},
		},
	}

	// Check each security header
	for _, sh := range securityHeaders {
		headerKey := strings.ToLower(sh.Name)
		value, exists := normalizedHeaders[headerKey]

		if !exists {
			if sh.Required {
				finding.Missing = append(finding.Missing, HeaderIssue{
					Header:      sh.Name,
					Severity:    sh.Severity,
					Description: sh.Description,
					Remediation: sh.Remediation,
				})
				finding.Score -= c.severityScore(sh.Severity)
			}
		} else {
			finding.Present = append(finding.Present, sh.Name)
			if sh.Validator != nil {
				valid, issue := sh.Validator(value)
				if !valid || issue != "" {
					finding.Weak = append(finding.Weak, HeaderIssue{
						Header:      sh.Name,
						Severity:    sh.Severity,
						Description: issue,
						Remediation: sh.Remediation,
					})
					if !valid {
						finding.Score -= c.severityScore(sh.Severity) / 2
					}
				}
			}
		}
	}

	if finding.Score < 0 {
		finding.Score = 0
	}

	return finding
}

// severityScore returns point deduction for each severity level
func (c *Checker) severityScore(severity string) int {
	switch severity {
	case "high":
		return 25
	case "medium":
		return 15
	case "low":
		return 10
	case "info":
		return 5
	default:
		return 5
	}
}

// checkEmailSecurity checks SPF, DKIM, and DMARC records
func (c *Checker) checkEmailSecurity(domain string) *EmailSecurityCheck {
	result := &EmailSecurityCheck{
		Domain: domain,
		Score:  100,
	}

	// Check SPF
	result.SPF = c.checkSPF(domain)
	if !result.SPF.Found {
		result.Score -= 30
	} else if !result.SPF.Valid {
		result.Score -= 15
	}

	// Check DKIM (common selectors)
	result.DKIM = c.checkDKIM(domain)
	if !result.DKIM.Found {
		result.Score -= 20
	}

	// Check DMARC
	result.DMARC = c.checkDMARC(domain)
	if !result.DMARC.Found {
		result.Score -= 30
	} else if result.DMARC.Policy == "none" {
		result.Score -= 15
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}

// checkSPF checks the SPF record for a domain
func (c *Checker) checkSPF(domain string) *SPFRecord {
	result := &SPFRecord{
		Found:    false,
		Valid:    false,
		Severity: "high",
	}

	// Query TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		result.Issues = append(result.Issues, "Failed to query TXT records")
		return result
	}

	// Find SPF record
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			result.Found = true
			result.Record = txt
			break
		}
	}

	if !result.Found {
		result.Issues = append(result.Issues, "No SPF record found - emails can be spoofed")
		return result
	}

	// Validate SPF record
	result.Valid = true
	record := strings.ToLower(result.Record)

	// Check for overly permissive SPF
	if strings.Contains(record, "+all") {
		result.Issues = append(result.Issues, "SPF uses +all (allows all senders) - highly insecure")
		result.Valid = false
		result.Severity = "high"
	} else if strings.Contains(record, "?all") {
		result.Issues = append(result.Issues, "SPF uses ?all (neutral) - provides no protection")
		result.Severity = "medium"
	} else if strings.Contains(record, "~all") {
		result.Issues = append(result.Issues, "SPF uses ~all (softfail) - consider using -all for strict enforcement")
		result.Severity = "low"
	} else if strings.Contains(record, "-all") {
		result.Severity = "info" // Good configuration
	}

	// Check for too many DNS lookups (SPF limit is 10)
	lookups := strings.Count(record, "include:") + strings.Count(record, "a:") +
		strings.Count(record, "mx") + strings.Count(record, "redirect=")
	if lookups > 10 {
		result.Issues = append(result.Issues, fmt.Sprintf("SPF has %d DNS lookups (limit is 10)", lookups))
	}

	return result
}

// checkDKIM checks for DKIM selectors
func (c *Checker) checkDKIM(domain string) *DKIMRecord {
	result := &DKIMRecord{
		Found:    false,
		Severity: "medium",
	}

	// Common DKIM selectors to check
	selectors := []string{
		"default", "google", "selector1", "selector2", // Microsoft 365
		"k1", "k2", "s1", "s2", "dkim", "mail", "email",
		"google", "googlemail", // Google
		"mandrill", "mailchimp", "sendgrid", "amazonses", // Email services
	}

	for _, sel := range selectors {
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		txtRecords, err := net.LookupTXT(dkimDomain)
		if err != nil {
			continue
		}
		for _, txt := range txtRecords {
			if strings.Contains(strings.ToLower(txt), "v=dkim1") {
				result.Found = true
				result.Selectors = append(result.Selectors, sel)
			}
		}
	}

	if !result.Found {
		result.Issues = append(result.Issues, "No DKIM records found for common selectors")
		result.Severity = "medium"
	} else {
		result.Severity = "info"
	}

	return result
}

// checkDMARC checks the DMARC record
func (c *Checker) checkDMARC(domain string) *DMARCRecord {
	result := &DMARCRecord{
		Found:    false,
		Valid:    false,
		Severity: "high",
	}

	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		result.Issues = append(result.Issues, "Failed to query DMARC record")
		return result
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			result.Found = true
			result.Record = txt
			break
		}
	}

	if !result.Found {
		result.Issues = append(result.Issues, "No DMARC record found - email spoofing not prevented")
		return result
	}

	result.Valid = true
	record := strings.ToLower(result.Record)

	// Extract policy
	if strings.Contains(record, "p=reject") {
		result.Policy = "reject"
		result.Severity = "info"
	} else if strings.Contains(record, "p=quarantine") {
		result.Policy = "quarantine"
		result.Severity = "low"
	} else if strings.Contains(record, "p=none") {
		result.Policy = "none"
		result.Issues = append(result.Issues, "DMARC policy is 'none' - provides monitoring but no enforcement")
		result.Severity = "medium"
	}

	// Check for reporting
	if !strings.Contains(record, "rua=") {
		result.Issues = append(result.Issues, "No aggregate reporting (rua) configured")
	}

	return result
}

// nucleiMisconfigScan runs nuclei with security misconfiguration templates
func (c *Checker) nucleiMisconfigScan(hosts []string) []MisconfigVuln {
	var vulns []MisconfigVuln

	if len(hosts) == 0 {
		return vulns
	}

	// Create temp file with hosts
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-misconfig.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	// Run nuclei with security misconfiguration tags
	// Focus on quick, high-value checks
	args := []string{
		"-l", tmpFile,
		"-tags", "misconfig,security-misconfiguration,exposure,cors,crlf,header",
		"-severity", "low,medium,high,critical",
		"-jsonl",
		"-exclude-tags", "dos,fuzz",
		"-timeout", "5",
		"-duc", // Disable update check
		"-silent",
	}

	if c.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", c.cfg.Threads))
	} else {
		args = append(args, "-c", "25")
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return vulns
	}

	// Parse nuclei output
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}

		var entry struct {
			Host       string `json:"host"`
			MatchedAt  string `json:"matched-at"`
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string   `json:"name"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				Tags        []string `json:"tags"`
			} `json:"info"`
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}

		if entry.Host == "" && entry.MatchedAt == "" {
			continue
		}

		vulnType := entry.Type
		if vulnType == "" && len(entry.Info.Tags) > 0 {
			vulnType = entry.Info.Tags[0]
		}

		vulns = append(vulns, MisconfigVuln{
			Host:        entry.Host,
			URL:         entry.MatchedAt,
			TemplateID:  entry.TemplateID,
			Name:        entry.Info.Name,
			Severity:    entry.Info.Severity,
			Type:        vulnType,
			Description: entry.Info.Description,
		})
	}

	return vulns
}
