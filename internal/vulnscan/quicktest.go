package vulnscan

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
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
		Matchers:    []string{"49"}, // Requires validation to avoid FPs (49 appears in many pages)
		Severity:    "high",
		Description: "Server-Side Template Injection",
		RequireValidation: true, // Validate to reduce false positives
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
			// Basic traversal
			"....//....//....//etc/passwd",
			"..%2f..%2f..%2fetc/passwd",
			// Double URL encoding
			"..%252f..%252f..%252fetc/passwd",
			"..%255c..%255c..%255cetc/passwd",
			// Null byte (older PHP)
			"....//....//etc/passwd%00",
			"..%2f..%2f..%2fetc/passwd%00.jpg",
			// Windows paths
			"....\\....\\....\\windows\\win.ini",
			"..%5c..%5c..%5cwindows%5cwin.ini",
			// Path truncation
			"....//....//....//etc/passwd" + strings.Repeat("/.", 50),
			// Filter bypass
			"....//..//..//..//etc/passwd",
			"....%252f....%252f....%252fetc/passwd",
			// Wrapper-based (PHP)
			"php://filter/convert.base64-encode/resource=../../../etc/passwd",
			"php://filter/read=string.rot13/resource=../../../etc/passwd",
		},
		// Very specific LFI indicators - actual file content, not generic strings
		Matchers:    []string{"root:x:0:0:", "daemon:x:1:1:", "nobody:x:", "[fonts]", "[extensions]", "cm9vdDp4"},
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
			// Basic redirects
			"//evil.com",
			"https://evil.com",
			"http://evil.com",
			// Backslash tricks
			"/\\evil.com",
			"\\/evil.com",
			"//evil.com/",
			// Protocol-relative with encoding
			"//evil%2ecom",
			"%2f%2fevil.com",
			// Domain confusion
			"https:evil.com",
			"///evil.com",
			"////evil.com",
			// @ trick (http://legit.com@evil.com)
			"https://legit.com@evil.com",
			"//legit.com@evil.com",
			// Unicode bypass
			"//evil。com",      // Fullwidth dot
			"//evil%E3%80%82com", // URL-encoded fullwidth
			// JavaScript scheme
			"javascript:alert(document.domain)//",
			"javascript://evil.com%0aalert(1)",
			// Data URL
			"data:text/html,<script>alert(1)</script>",
			// Null byte
			"//evil.com%00.legit.com",
			// Tab/newline bypass
			"//evil.com%09",
			"//evil.com%0d%0a",
		},
		// Check for actual redirect in Location header
		Matchers:    []string{"Location: //evil", "Location: https://evil", "Location: http://evil", "evil.com", "evil%2ecom"},
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

// HostHeaderTest represents a host header injection test case
type HostHeaderTest struct {
	Name        string
	Header      string   // Header to inject (Host, X-Forwarded-Host, etc.)
	Values      []string // Values to inject
	Matchers    []string // What to look for in response body
	Severity    string
	Description string
}

// hostHeaderTests defines all host header injection tests
var hostHeaderTests = []HostHeaderTest{
	{
		Name:   "Host-Header-Injection",
		Header: "Host",
		Values: []string{
			"evil.com",
			"localhost",
			"127.0.0.1",
		},
		// Look for injected host in response (password reset, cache poisoning indicators)
		Matchers:    []string{"evil.com", "://evil.com", "href=\"http://evil.com", "href='http://evil.com"},
		Severity:    "high",
		Description: "Host Header Injection - Host header reflected in response",
	},
	{
		Name:   "X-Forwarded-Host-Injection",
		Header: "X-Forwarded-Host",
		Values: []string{
			"evil.com",
		},
		Matchers:    []string{"evil.com", "://evil.com"},
		Severity:    "high",
		Description: "X-Forwarded-Host Injection - Header reflected in response",
	},
	{
		Name:   "X-Host-Injection",
		Header: "X-Host",
		Values: []string{
			"evil.com",
		},
		Matchers:    []string{"evil.com", "://evil.com"},
		Severity:    "medium",
		Description: "X-Host Injection - Header reflected in response",
	},
	{
		Name:   "X-Original-URL",
		Header: "X-Original-URL",
		Values: []string{
			"/admin",
			"/admin/",
		},
		Matchers:    []string{"admin", "dashboard", "settings", "configuration"},
		Severity:    "high",
		Description: "X-Original-URL Bypass - Access control bypass via header",
	},
	{
		Name:   "X-Rewrite-URL",
		Header: "X-Rewrite-URL",
		Values: []string{
			"/admin",
			"/admin/",
		},
		Matchers:    []string{"admin", "dashboard", "settings", "configuration"},
		Severity:    "high",
		Description: "X-Rewrite-URL Bypass - Access control bypass via header",
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
		// For LFI, require STRICT validation - actual /etc/passwd content format
		// The response must contain actual passwd file lines, not just keywords

		// Check for Linux /etc/passwd format: username:x:uid:gid:gecos:home:shell
		// Must have at least 2 valid passwd lines to confirm (reduces FPs from error messages)
		passwdLinePattern := regexp.MustCompile(`^[a-z_][a-z0-9_-]*:x?:\d+:\d+:[^:]*:[^:]+:[^:]*$`)
		lines := strings.Split(bodyStr, "\n")
		validPasswdLines := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if passwdLinePattern.MatchString(line) {
				validPasswdLines++
			}
		}
		if validPasswdLines >= 3 {
			return true // Confirmed: found 3+ valid passwd lines
		}

		// Also check for specific well-known entries that must appear together
		hasRoot := strings.Contains(bodyStr, "root:x:0:0:") || strings.Contains(bodyStr, "root::0:0:")
		hasBin := strings.Contains(bodyStr, "bin:x:1:1:") || strings.Contains(bodyStr, "bin:x:2:2:")
		hasDaemon := strings.Contains(bodyStr, "daemon:x:1:1:") || strings.Contains(bodyStr, "daemon:x:2:2:")
		hasNobody := strings.Contains(bodyStr, "nobody:x:")

		// Require root + at least 2 other standard accounts
		knownAccounts := 0
		if hasRoot {
			knownAccounts++
		}
		if hasBin {
			knownAccounts++
		}
		if hasDaemon {
			knownAccounts++
		}
		if hasNobody {
			knownAccounts++
		}
		if hasRoot && knownAccounts >= 3 {
			return true
		}

		// Check for base64-encoded /etc/passwd (php://filter output)
		// "root:x:0:0:" in base64 is "cm9vdDp4OjA6MDo="
		if strings.Contains(bodyStr, "cm9vdDp4OjA6MDo") {
			return true
		}

		// Check for Windows win.ini - require multiple sections
		winIndicators := 0
		if strings.Contains(bodyStr, "[fonts]") {
			winIndicators++
		}
		if strings.Contains(bodyStr, "[extensions]") {
			winIndicators++
		}
		if strings.Contains(bodyStr, "[mci extensions]") {
			winIndicators++
		}
		if strings.Contains(bodyStr, "[Mail]") {
			winIndicators++
		}
		// Require at least 2 win.ini sections
		return winIndicators >= 2

	case "OpenRedirect":
		// For redirect, MUST have redirect status code AND Location header pointing to evil.com
		// Status codes: 301, 302, 303, 307, 308
		isRedirectStatus := resp.StatusCode == 301 || resp.StatusCode == 302 ||
			resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308

		if !isRedirectStatus {
			return false // Not a redirect response
		}

		location := resp.Header.Get("Location")
		if location != "" {
			locationLower := strings.ToLower(location)
			// Must redirect to our evil.com domain
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

	case "SSTI":
		// For SSTI, verify "49" doesn't appear in baseline response
		// This catches false positives where "49" exists in normal page content

		// Get baseline URL by removing SSTI payloads from query params
		baselineURL := removeSSSTIPayloads(vuln.URL)

		// Fetch baseline response
		baselineResp, err := client.Get(baselineURL)
		if err == nil {
			defer baselineResp.Body.Close()
			baselineBody, _ := io.ReadAll(io.LimitReader(baselineResp.Body, 1024*1024))

			// If "49" appears in baseline, it's a false positive
			if strings.Contains(string(baselineBody), "49") {
				return false
			}
		}

		// Verify "49" appears in the payload response
		return strings.Contains(bodyStr, "49")

	default:
		return true // Unknown test type - don't filter
	}
}

// RunHostHeaderTests runs all host header injection tests on alive hosts
// This is separate from URL-based quick tests as it tests HTTP headers
func (qt *QuickTester) RunHostHeaderTests(aliveHosts []string) []Vulnerability {
	if len(aliveHosts) == 0 {
		return nil
	}

	// Limit hosts to prevent overwhelming
	maxHosts := 50
	if len(aliveHosts) > maxHosts {
		aliveHosts = aliveHosts[:maxHosts]
	}

	var allVulns []Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	fmt.Printf("        [HostHeader] Testing %d hosts for header injection...\n", len(aliveHosts))

	// Run each host header test type in parallel
	for _, test := range hostHeaderTests {
		wg.Add(1)
		go func(t HostHeaderTest) {
			defer wg.Done()
			vulns := qt.runSingleHostHeaderTest(t, aliveHosts)
			if len(vulns) > 0 {
				mu.Lock()
				allVulns = append(allVulns, vulns...)
				mu.Unlock()
				fmt.Printf("        [HostHeader] %s: %d potential vulnerabilities\n", t.Name, len(vulns))
			}
		}(test)
	}

	wg.Wait()
	return allVulns
}

// runSingleHostHeaderTest runs a single host header injection test
func (qt *QuickTester) runSingleHostHeaderTest(test HostHeaderTest, hosts []string) []Vulnerability {
	var vulns []Vulnerability

	// Create HTTP client for custom header testing
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	for _, host := range hosts {
		// Normalize host URL
		targetURL := host
		if !strings.HasPrefix(targetURL, "http") {
			targetURL = "https://" + targetURL
		}

		for _, value := range test.Values {
			// Create request with injected header
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				continue
			}

			// Inject the test header
			if test.Header == "Host" {
				// For Host header, we need special handling
				// Store original host and set evil host
				req.Host = value
			} else {
				req.Header.Set(test.Header, value)
			}

			// Make request
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// Read response body
			body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB limit
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := strings.ToLower(string(body))

			// Check for matchers in response
			for _, matcher := range test.Matchers {
				if strings.Contains(bodyStr, strings.ToLower(matcher)) {
					// Validate it's not a false positive
					if qt.validateHostHeaderVuln(test, client, targetURL, value, matcher, bodyStr) {
						vulns = append(vulns, Vulnerability{
							URL:         targetURL,
							TemplateID:  fmt.Sprintf("quicktest-%s", strings.ToLower(strings.ReplaceAll(test.Name, " ", "-"))),
							Name:        test.Name,
							Severity:    test.Severity,
							Type:        "host-header-injection",
							Description: fmt.Sprintf("%s: %s header with value '%s' reflected in response", test.Description, test.Header, value),
							Tool:        "quicktest",
						})
						break // One match per host is enough
					}
				}
			}
		}
	}

	return vulns
}

// validateHostHeaderVuln validates host header injection to reduce false positives
func (qt *QuickTester) validateHostHeaderVuln(test HostHeaderTest, client *http.Client, targetURL, injectedValue, matcher, bodyWithPayload string) bool {
	// Get baseline response without the injected header
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	if err != nil {
		return false
	}
	baselineBody := strings.ToLower(string(body))

	// If the matcher already exists in baseline response, it's a false positive
	if strings.Contains(baselineBody, strings.ToLower(matcher)) {
		return false
	}

	// Special case for X-Original-URL and X-Rewrite-URL bypass tests
	// The matcher might be generic (like "admin"), so we need stricter validation
	if test.Header == "X-Original-URL" || test.Header == "X-Rewrite-URL" {
		// Check if response code changed significantly (e.g., 403 -> 200)
		return true // Already passed baseline check, consider it valid
	}

	return true
}

// removeSSSTIPayloads removes common SSTI payloads from URL query parameters
// to get a baseline URL for comparison
func removeSSSTIPayloads(urlStr string) string {
	// Common SSTI payloads to remove
	payloads := []string{
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"#{7*7}",
		"${{7*7}}",
		"%7B%7B7*7%7D%7D",      // URL-encoded {{7*7}}
		"%24%7B7*7%7D",         // URL-encoded ${7*7}
		"%24%7B7%2A7%7D",       // URL-encoded ${7*7} with encoded *
	}

	result := urlStr
	for _, payload := range payloads {
		result = strings.ReplaceAll(result, payload, "test")
	}
	return result
}
