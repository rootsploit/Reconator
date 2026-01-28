package vulnscan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/tools"
)

// BB-8: Modular Quick Test Framework
// Easily add new vulnerability tests by adding entries to quickTests slice

// QuickTest defines a single vulnerability test case
// To add a new test, just append to quickTests slice below
type QuickTest struct {
	Name           string   // Test name (e.g., "SSTI")
	GFPattern      string   // gf pattern to filter URLs (e.g., "ssti")
	Payloads       []string // Payloads to inject via qsreplace
	Matchers       []string // Strings to match in response (indicates vulnerability)
	Severity       string   // Severity level: critical, high, medium, low
	Description    string   // Human-readable description
	RequireValidation bool  // If true, requires secondary validation to reduce FPs
}

// quickTests defines all quick vulnerability tests
// ADD NEW TESTS HERE - just append a new QuickTest struct
// NOTE: Tests with RequireValidation=true will be validated with HTTP requests to reduce false positives
var quickTests = []QuickTest{
	{
		Name:        "SSTI",
		GFPattern:   "ssti",
		Payloads:    []string{"{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}"},
		Matchers:    []string{"49"}, // SSTI is reliable - 49 only appears if evaluated
		Severity:    "high",
		Description: "Server-Side Template Injection",
		RequireValidation: false,
	},
	{
		Name:        "SQLi-Error",
		GFPattern:   "sqli",
		Payloads:    []string{"'", "\"", "1'\""},
		// More specific SQL error patterns to reduce false positives
		Matchers:    []string{"SQL syntax", "mysql_", "ORA-0", "PG::SyntaxError", "sqlite3.OperationalError", "SQLSTATE[", "ODBC Driver"},
		Severity:    "high",
		Description: "SQL Injection (Error-Based)",
		RequireValidation: false,
	},
	// XSS-Reflection DISABLED - too many false positives
	// Simple reflection detection doesn't confirm XSS - the payload might be HTML-encoded
	// Use dalfox or nuclei for proper XSS scanning instead
	// {
	// 	Name:        "XSS-Reflection",
	// 	...
	// },
	{
		Name:        "LFI",
		GFPattern:   "lfi",
		Payloads: []string{
			"....//....//....//etc/passwd",
			"..%2f..%2f..%2fetc/passwd",
			"..%252f..%252f..%252fetc/passwd",
		},
		// Very specific LFI indicators - actual file content, not generic strings
		Matchers:    []string{"root:x:0:0:", "daemon:x:1:1:", "nobody:x:"},
		Severity:    "high",
		Description: "Local File Inclusion / Path Traversal",
		RequireValidation: true, // Validate to confirm actual file read
	},
	// SSRF DISABLED for QuickTest - too many false positives
	// Pattern matching for "meta-data", "instance-id" etc. triggers on normal page content
	// Use nuclei SSRF templates with OAST/Burp Collaborator for proper SSRF testing
	// {
	// 	Name:        "SSRF",
	// 	...
	// },
	{
		Name:        "OpenRedirect",
		GFPattern:   "redirect",
		Payloads: []string{
			"//evil.com",
			"https://evil.com",
			"/\\evil.com",
		},
		// Check for actual redirect in Location header
		Matchers:    []string{"Location: //evil.com", "Location: https://evil.com", "Location: http://evil.com"},
		Severity:    "medium",
		Description: "Open Redirect",
		RequireValidation: true, // Validate redirect actually happens
	},
	// RFI DISABLED - extremely high false positive rate
	// Pattern matching for "shell", "test", "<?php" matches normal page content
	// Use nuclei RFI templates for proper RFI testing
	// {
	// 	Name:        "RFI",
	// 	...
	// },
	{
		Name:        "CRLF",
		GFPattern:   "redirect",
		Payloads: []string{
			"%0d%0aSet-Cookie:crlf=injection",
			"%0aSet-Cookie:crlf=injection",
		},
		// CRLF is reliable - these patterns only appear if header injection works
		Matchers:    []string{"Set-Cookie: crlf=injection", "Set-Cookie:crlf=injection"},
		Severity:    "medium",
		Description: "CRLF Injection (HTTP Response Splitting)",
		RequireValidation: true, // Validate header actually injected
	},
}

// QuickTestResult holds results from quick testing
type QuickTestResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	TestsRun        int             `json:"tests_run"`
	Duration        time.Duration   `json:"duration"`
}

// QuickTester performs rapid vulnerability testing using gf + qsreplace + httpx
type QuickTester struct {
	checker *tools.Checker
	threads int
}

// NewQuickTester creates a new quick tester
func NewQuickTester(checker *tools.Checker, threads int) *QuickTester {
	return &QuickTester{checker: checker, threads: threads}
}

// RunQuickTests executes all quick tests on categorized URLs
func (qt *QuickTester) RunQuickTests(categorized *historic.CategorizedURLs) *QuickTestResult {
	start := time.Now()
	result := &QuickTestResult{}

	// Check required tools
	if !qt.checker.IsInstalled("qsreplace") {
		fmt.Println("        [QuickTest] qsreplace not installed, skipping quick tests")
		return result
	}
	if !qt.checker.IsInstalled("httpx") {
		fmt.Println("        [QuickTest] httpx not installed, skipping quick tests")
		return result
	}

	// Map gf pattern to categorized URLs
	urlsByPattern := map[string][]string{
		"ssti":     categorized.SSTI,
		"sqli":     categorized.SQLi,
		"xss":      categorized.XSS,
		"lfi":      categorized.LFI,
		"ssrf":     categorized.SSRF,
		"redirect": categorized.Redirect,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allVulns []Vulnerability

	// Run tests in parallel (one goroutine per test type)
	for _, test := range quickTests {
		urls := urlsByPattern[test.GFPattern]
		if len(urls) == 0 {
			continue
		}

		wg.Add(1)
		go func(t QuickTest, testURLs []string) {
			defer wg.Done()

			vulns := qt.runSingleTest(t, testURLs)
			if len(vulns) > 0 {
				mu.Lock()
				allVulns = append(allVulns, vulns...)
				result.TestsRun++
				mu.Unlock()
				fmt.Printf("        [QuickTest] %s: %d potential vulnerabilities\n", t.Name, len(vulns))
			}
		}(test, urls)
	}

	wg.Wait()
	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)

	return result
}

// runSingleTest executes a single quick test
func (qt *QuickTester) runSingleTest(test QuickTest, urls []string) []Vulnerability {
	var vulns []Vulnerability

	// Limit URLs to prevent overwhelming
	maxURLs := 100
	if len(urls) > maxURLs {
		urls = urls[:maxURLs]
	}

	// Create temp file with URLs
	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-quicktest.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	// Test each payload
	for _, payload := range test.Payloads {
		// Build matcher string for httpx
		matcherArg := strings.Join(test.Matchers, "|")

		// Pipeline: cat urls | qsreplace <payload> | httpx -match-string <matchers>
		cmd := fmt.Sprintf(
			"cat %s | qsreplace '%s' | httpx -silent -mc 200,301,302 -mr '%s' 2>/dev/null",
			tmp, payload, matcherArg,
		)

		r := exec.Run("sh", []string{"-c", cmd}, &exec.Options{Timeout: 2 * time.Minute})
		if r.Error != nil {
			continue
		}

		// Parse results
		for _, line := range exec.Lines(r.Stdout) {
			if line == "" {
				continue
			}

			potentialVuln := Vulnerability{
				URL:         line,
				TemplateID:  fmt.Sprintf("quicktest-%s", strings.ToLower(test.Name)),
				Name:        fmt.Sprintf("%s Detected", test.Name),
				Severity:    test.Severity,
				Type:        strings.ToLower(test.Name),
				Description: fmt.Sprintf("%s: Payload '%s' matched response pattern", test.Description, payload),
				Tool:        "quicktest",
			}

			// Validate vulnerability if required to reduce false positives
			if test.RequireValidation {
				if validateVulnerability(potentialVuln, test) {
					potentialVuln.Description = fmt.Sprintf("%s (Validated): Payload '%s' confirmed", test.Description, payload)
					vulns = append(vulns, potentialVuln)
				}
				// If validation fails, skip this potential vulnerability (false positive)
			} else {
				vulns = append(vulns, potentialVuln)
			}
		}
	}

	return vulns
}

// GetAvailableTests returns list of all configured quick tests (for documentation)
func GetAvailableTests() []QuickTest {
	return quickTests
}

// AddCustomTest allows adding custom tests at runtime
// Example: AddCustomTest(QuickTest{Name: "Custom", GFPattern: "custom", ...})
func AddCustomTest(test QuickTest) {
	quickTests = append(quickTests, test)
}

// validateVulnerability performs secondary validation to reduce false positives
// Returns true if the vulnerability is confirmed, false if it's a false positive
func validateVulnerability(vuln Vulnerability, test QuickTest) bool {
	if !test.RequireValidation {
		return true // No validation required
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - we want to see the redirect response
			return http.ErrUseLastResponse
		},
	}

	// Make request to validate
	resp, err := client.Get(vuln.URL)
	if err != nil {
		return false // Can't validate - treat as false positive
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false
	}
	bodyStr := string(body)

	// Validation based on test type
	switch test.Name {
	case "LFI":
		// For LFI, check if actual /etc/passwd content is present
		// Must have multiple passwd-like entries to confirm
		passwdIndicators := 0
		if strings.Contains(bodyStr, "root:x:0:0:") {
			passwdIndicators++
		}
		if strings.Contains(bodyStr, "daemon:x:1:1:") {
			passwdIndicators++
		}
		if strings.Contains(bodyStr, "nobody:x:") {
			passwdIndicators++
		}
		if strings.Contains(bodyStr, "/bin/bash") || strings.Contains(bodyStr, "/bin/sh") {
			passwdIndicators++
		}
		// Require at least 2 indicators to confirm LFI
		return passwdIndicators >= 2

	case "OpenRedirect":
		// For redirect, check Location header
		location := resp.Header.Get("Location")
		if location != "" {
			locationLower := strings.ToLower(location)
			if strings.Contains(locationLower, "evil.com") {
				return true
			}
		}
		return false

	case "CRLF":
		// For CRLF, check if our injected cookie is in response headers
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "crlf" && cookie.Value == "injection" {
				return true
			}
		}
		// Also check raw Set-Cookie header
		setCookie := resp.Header.Get("Set-Cookie")
		if strings.Contains(setCookie, "crlf=injection") {
			return true
		}
		return false

	default:
		return true // Unknown test type - don't filter
	}
}
