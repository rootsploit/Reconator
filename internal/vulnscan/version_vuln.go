package vulnscan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// VersionVulnerability represents a known vulnerability for a specific version
type VersionVulnerability struct {
	Product      string   // e.g., "PHP", "IIS", "jQuery"
	AffectedRange string  // e.g., "< 5.6.41", ">= 7.0 < 7.1.27"
	CVEs         []string // List of CVE IDs
	Severity     string   // critical, high, medium, low
	Description  string   // Human readable description
	References   []string // Links to CVE details
}

// KnownVulnerableVersions contains mappings of products to their known vulnerabilities
// This is a curated list of high-impact vulnerabilities for common technologies
var KnownVulnerableVersions = []VersionVulnerability{
	// PHP vulnerabilities
	{
		Product:       "PHP",
		AffectedRange: "< 5.6.41",
		CVEs:          []string{"CVE-2014-9427", "CVE-2014-8142", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-6831"},
		Severity:      "high",
		Description:   "PHP < 5.6.41 has multiple critical vulnerabilities including deserialization flaws and memory corruption",
		References:    []string{"https://www.php.net/ChangeLog-5.php"},
	},
	{
		Product:       "PHP",
		AffectedRange: ">= 7.0.0 < 7.1.33",
		CVEs:          []string{"CVE-2019-11036", "CVE-2019-11038", "CVE-2019-11039", "CVE-2019-11040"},
		Severity:      "high",
		Description:   "PHP 7.0.x-7.1.x has multiple security vulnerabilities including buffer overflows",
		References:    []string{"https://www.php.net/ChangeLog-7.php"},
	},
	{
		Product:       "PHP",
		AffectedRange: ">= 7.2.0 < 7.2.34",
		CVEs:          []string{"CVE-2020-7068", "CVE-2020-7069", "CVE-2020-7070"},
		Severity:      "medium",
		Description:   "PHP 7.2.x < 7.2.34 has security vulnerabilities",
		References:    []string{"https://www.php.net/ChangeLog-7.php"},
	},
	{
		Product:       "PHP",
		AffectedRange: ">= 8.0.0 < 8.0.30",
		CVEs:          []string{"CVE-2023-3823", "CVE-2023-3824"},
		Severity:      "high",
		Description:   "PHP 8.0.x < 8.0.30 has XML parsing and phar vulnerabilities",
		References:    []string{"https://www.php.net/ChangeLog-8.php"},
	},
	// IIS vulnerabilities
	{
		Product:       "IIS",
		AffectedRange: "<= 8.5",
		CVEs:          []string{"CVE-2014-4078", "CVE-2017-7269"},
		Severity:      "medium",
		Description:   "Microsoft IIS 8.5 and earlier has known security issues including WebDAV buffer overflow (CVE-2017-7269)",
		References:    []string{"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-7269"},
	},
	{
		Product:       "IIS",
		AffectedRange: ">= 6.0 <= 7.5",
		CVEs:          []string{"CVE-2017-7269"},
		Severity:      "critical",
		Description:   "IIS 6.0-7.5 WebDAV buffer overflow allowing RCE (actively exploited)",
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7269"},
	},
	// jQuery vulnerabilities
	{
		Product:       "jQuery",
		AffectedRange: "< 1.9.2",
		CVEs:          []string{"CVE-2012-6708", "CVE-2015-9251"},
		Severity:      "medium",
		Description:   "jQuery < 1.9.2 has XSS vulnerabilities in selector parsing",
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2015-9251"},
	},
	{
		Product:       "jQuery",
		AffectedRange: "< 3.0.0",
		CVEs:          []string{"CVE-2015-9251", "CVE-2019-11358"},
		Severity:      "medium",
		Description:   "jQuery < 3.0.0 has prototype pollution and XSS vulnerabilities",
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-11358"},
	},
	{
		Product:       "jQuery",
		AffectedRange: "< 3.5.0",
		CVEs:          []string{"CVE-2020-11022", "CVE-2020-11023"},
		Severity:      "medium",
		Description:   "jQuery < 3.5.0 has XSS vulnerabilities in htmlPrefilter",
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-11022"},
	},
	// Apache HTTP Server
	{
		Product:       "Apache HTTP Server",
		AffectedRange: "< 2.4.50",
		CVEs:          []string{"CVE-2021-41773", "CVE-2021-42013"},
		Severity:      "critical",
		Description:   "Apache < 2.4.50 has path traversal and RCE vulnerabilities",
		References:    []string{"https://httpd.apache.org/security/vulnerabilities_24.html"},
	},
	{
		Product:       "Apache",
		AffectedRange: "<= 2.4.25",
		CVEs:          []string{"CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679"},
		Severity:      "high",
		Description:   "Apache <= 2.4.25 has multiple authentication bypass and buffer overflow vulnerabilities",
		References:    []string{"https://httpd.apache.org/security/vulnerabilities_24.html"},
	},
	// Nginx
	{
		Product:       "Nginx",
		AffectedRange: "< 1.20.1",
		CVEs:          []string{"CVE-2021-23017"},
		Severity:      "high",
		Description:   "Nginx < 1.20.1 has DNS resolver vulnerability allowing memory disclosure",
		References:    []string{"https://nginx.org/en/CHANGES"},
	},
	// Bootstrap
	{
		Product:       "Bootstrap",
		AffectedRange: "< 3.4.0",
		CVEs:          []string{"CVE-2018-14041", "CVE-2018-14042", "CVE-2019-8331"},
		Severity:      "medium",
		Description:   "Bootstrap < 3.4.0 has multiple XSS vulnerabilities in tooltip/popover",
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-8331"},
	},
	// AngularJS (legacy, unmaintained)
	{
		Product:       "AngularJS",
		AffectedRange: "< 1.8.0",
		CVEs:          []string{"CVE-2019-10768", "CVE-2020-7676"},
		Severity:      "medium",
		Description:   "AngularJS < 1.8.0 has prototype pollution vulnerabilities (note: AngularJS is EOL)",
		References:    []string{"https://docs.angularjs.org/guide/security"},
	},
	// ASP.NET
	{
		Product:       "Microsoft ASP.NET",
		AffectedRange: "<= 2.0.50727",
		CVEs:          []string{"CVE-2008-5100", "CVE-2011-3416", "CVE-2012-0163"},
		Severity:      "high",
		Description:   "ASP.NET 2.0 has multiple security vulnerabilities and is end-of-life",
		References:    []string{"https://docs.microsoft.com/en-us/lifecycle/products/microsoft-net-framework"},
	},
}

// OutdatedSoftwareWarning represents a warning about outdated/EOL software
type OutdatedSoftwareWarning struct {
	Product     string
	Version     string
	EOLDate     string // When support ended
	Reason      string // Why it's outdated
	Severity    string // low, medium, high for risk level
	Replacement string // Recommended replacement
}

// OutdatedSoftwareList contains known EOL/outdated software
var OutdatedSoftwareList = []OutdatedSoftwareWarning{
	{Product: "PHP", Version: "5.6", EOLDate: "2018-12-31", Reason: "PHP 5.6 reached end of life", Severity: "high", Replacement: "PHP 8.x"},
	{Product: "PHP", Version: "7.0", EOLDate: "2019-01-10", Reason: "PHP 7.0 reached end of life", Severity: "high", Replacement: "PHP 8.x"},
	{Product: "PHP", Version: "7.1", EOLDate: "2019-12-01", Reason: "PHP 7.1 reached end of life", Severity: "high", Replacement: "PHP 8.x"},
	{Product: "PHP", Version: "7.2", EOLDate: "2020-11-30", Reason: "PHP 7.2 reached end of life", Severity: "medium", Replacement: "PHP 8.x"},
	{Product: "PHP", Version: "7.3", EOLDate: "2021-12-06", Reason: "PHP 7.3 reached end of life", Severity: "medium", Replacement: "PHP 8.x"},
	{Product: "PHP", Version: "7.4", EOLDate: "2022-11-28", Reason: "PHP 7.4 reached end of life", Severity: "medium", Replacement: "PHP 8.x"},
	{Product: "AngularJS", Version: "1", EOLDate: "2021-12-31", Reason: "AngularJS 1.x is end of life, no security updates", Severity: "medium", Replacement: "Angular 17+"},
	{Product: "Bootstrap", Version: "2", EOLDate: "2019-07-24", Reason: "Bootstrap 2.x is unmaintained", Severity: "low", Replacement: "Bootstrap 5.x"},
	{Product: "Bootstrap", Version: "3", EOLDate: "2019-07-24", Reason: "Bootstrap 3.x receives critical security patches only", Severity: "low", Replacement: "Bootstrap 5.x"},
	{Product: "jQuery", Version: "1", EOLDate: "2016-01-12", Reason: "jQuery 1.x is unmaintained", Severity: "low", Replacement: "jQuery 3.x or native JS"},
	{Product: "jQuery", Version: "2", EOLDate: "2016-01-12", Reason: "jQuery 2.x is unmaintained", Severity: "low", Replacement: "jQuery 3.x or native JS"},
	{Product: "IIS", Version: "6.0", EOLDate: "2015-07-14", Reason: "IIS 6.0 (Windows Server 2003) is end of life", Severity: "critical", Replacement: "IIS 10+"},
	{Product: "IIS", Version: "7.0", EOLDate: "2015-01-13", Reason: "IIS 7.0 (Windows Server 2008) extended support ended", Severity: "high", Replacement: "IIS 10+"},
	{Product: "IIS", Version: "7.5", EOLDate: "2020-01-14", Reason: "IIS 7.5 (Windows Server 2008 R2) extended support ended", Severity: "high", Replacement: "IIS 10+"},
	{Product: "IIS", Version: "8.0", EOLDate: "2023-10-10", Reason: "IIS 8.0 (Windows Server 2012) extended support ending soon", Severity: "medium", Replacement: "IIS 10+"},
	{Product: "IIS", Version: "8.5", EOLDate: "2023-10-10", Reason: "IIS 8.5 (Windows Server 2012 R2) extended support ending soon", Severity: "medium", Replacement: "IIS 10+"},
	{Product: "Microsoft ASP.NET", Version: "2.0", EOLDate: "2011-04-12", Reason: ".NET Framework 2.0 is deprecated", Severity: "high", Replacement: ".NET 6+"},
}

// VersionVulnResult contains the result of version-based vulnerability detection
type VersionVulnResult struct {
	Vulnerabilities []Vulnerability           `json:"vulnerabilities"`
	Warnings        []OutdatedSoftwareWarning `json:"warnings"`
	Sources         map[string]int            `json:"sources"` // Count by source (vulnx, nvd, hardcoded, searchsploit)
}

// DetectVersionVulnerabilities scans detected technologies for known vulnerabilities
// Uses hybrid approach: vulnx → NVD API → hardcoded database → searchsploit
func DetectVersionVulnerabilities(techByHost map[string][]string) *VersionVulnResult {
	return DetectVersionVulnerabilitiesWithChecker(techByHost, nil)
}

// DetectVersionVulnerabilitiesWithChecker scans with a tool checker for dynamic lookups
func DetectVersionVulnerabilitiesWithChecker(techByHost map[string][]string, checker InstalledChecker) *VersionVulnResult {
	result := &VersionVulnResult{
		Vulnerabilities: []Vulnerability{},
		Warnings:        []OutdatedSoftwareWarning{},
		Sources:         make(map[string]int),
	}

	// Create CVE lookup (will use dynamic sources if checker is available)
	lookup := NewCVELookup(checker)

	// Track what we've already reported to avoid duplicates
	reportedCVEs := make(map[string]bool)
	reportedExploits := make(map[string]bool)
	reportedWarnings := make(map[string]bool)

	for host, techs := range techByHost {
		for _, tech := range techs {
			product, version := parseTechVersion(tech)
			if product == "" || version == "" {
				continue
			}

			// Use hybrid CVE lookup (vulnx → NVD → hardcoded)
			cves, exploits, source := lookup.LookupAll(product, version)

			// Track source for reporting
			if source != "" && len(cves) > 0 {
				result.Sources[source] += len(cves)
			}

			// Add CVE vulnerabilities
			for _, cve := range cves {
				key := fmt.Sprintf("%s|%s", host, cve.ID)
				if reportedCVEs[key] {
					continue
				}
				reportedCVEs[key] = true

				severity := cve.Severity
				if severity == "" {
					severity = "medium" // Default if not specified
				}

				description := cve.Description
				if description == "" {
					description = fmt.Sprintf("Known vulnerability in %s %s", product, version)
				}
				description = fmt.Sprintf("%s\nDetected: %s %s on %s", description, product, version, host)

				toolName := "version-detector"
				if source != "" {
					toolName = fmt.Sprintf("version-detector (%s)", source)
				}

				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        host,
					TemplateID:  strings.ToLower(cve.ID),
					Name:        fmt.Sprintf("%s %s - %s", product, version, cve.ID),
					Severity:    severity,
					Type:        "outdated-software",
					Description: description,
					Tool:        toolName,
				})
			}

			// Add ExploitDB vulnerabilities
			for _, exploit := range exploits {
				key := fmt.Sprintf("%s|edb-%s", host, exploit.ID)
				if reportedExploits[key] {
					continue
				}
				reportedExploits[key] = true

				result.Sources["searchsploit"]++
				vulns := ConvertExploitsToVulns([]ExploitInfo{exploit}, host, product, version)
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			}

			// Check for outdated/EOL software (always use hardcoded list)
			for _, warning := range OutdatedSoftwareList {
				if matchesProduct(product, warning.Product) && versionMatchesMajor(version, warning.Version) {
					key := fmt.Sprintf("%s|%s|%s", host, warning.Product, warning.Version)
					if reportedWarnings[key] {
						continue
					}
					reportedWarnings[key] = true

					// Add as vulnerability with info severity
					result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
						Host:        host,
						TemplateID:  fmt.Sprintf("outdated-%s", strings.ToLower(strings.ReplaceAll(warning.Product, " ", "-"))),
						Name:        fmt.Sprintf("Outdated Software: %s %s (EOL: %s)", warning.Product, version, warning.EOLDate),
						Severity:    warning.Severity,
						Type:        "outdated-software",
						Description: fmt.Sprintf("%s. Detected version: %s. Recommended: %s", warning.Reason, version, warning.Replacement),
						Tool:        "version-detector",
					})
				}
			}
		}
	}

	return result
}

// parseTechVersion extracts product and version from tech string like "PHP:5.6.40"
func parseTechVersion(tech string) (product, version string) {
	// Handle format "Product:Version" (e.g., "PHP:5.6.40", "IIS:8.5")
	if idx := strings.Index(tech, ":"); idx > 0 {
		product = strings.TrimSpace(tech[:idx])
		version = strings.TrimSpace(tech[idx+1:])
		return
	}

	// Handle format "Product/Version" (e.g., "Apache/2.4.25")
	if idx := strings.Index(tech, "/"); idx > 0 {
		product = strings.TrimSpace(tech[:idx])
		version = strings.TrimSpace(tech[idx+1:])
		return
	}

	// Try regex for version-like suffix
	re := regexp.MustCompile(`^(.+?)\s*(\d+(?:\.\d+)*(?:-\w+)?)$`)
	if matches := re.FindStringSubmatch(tech); len(matches) == 3 {
		product = strings.TrimSpace(matches[1])
		version = strings.TrimSpace(matches[2])
		return
	}

	return "", ""
}

// matchesProduct checks if detected product matches known product (case-insensitive, partial match)
func matchesProduct(detected, known string) bool {
	detected = strings.ToLower(strings.TrimSpace(detected))
	known = strings.ToLower(strings.TrimSpace(known))

	// Exact match
	if detected == known {
		return true
	}

	// Known variations
	variations := map[string][]string{
		"php":                 {"php"},
		"iis":                 {"iis", "microsoft-iis", "microsoft iis", "internet information services"},
		"jquery":              {"jquery"},
		"apache http server":  {"apache", "apache http server", "apache httpd"},
		"apache":              {"apache", "apache http server", "apache httpd"},
		"nginx":               {"nginx"},
		"bootstrap":           {"bootstrap", "twitter bootstrap"},
		"angularjs":           {"angularjs", "angular.js", "angular"},
		"microsoft asp.net":   {"asp.net", "microsoft asp.net", "aspnet"},
	}

	for canonical, variants := range variations {
		if known == canonical {
			for _, v := range variants {
				if strings.Contains(detected, v) {
					return true
				}
			}
		}
	}

	return false
}

// versionInRange checks if a version is within a vulnerability range
// Range format: "< 5.6.41", ">= 7.0.0 < 7.1.33", "<= 8.5"
func versionInRange(version, rangeSpec string) bool {
	// Parse the range specification
	parts := strings.Fields(rangeSpec)

	i := 0
	for i < len(parts) {
		if i+1 >= len(parts) {
			break
		}

		op := parts[i]
		rangeVer := parts[i+1]

		var result bool
		switch op {
		case "<":
			result = compareVersions(version, rangeVer) < 0
		case "<=":
			result = compareVersions(version, rangeVer) <= 0
		case ">":
			result = compareVersions(version, rangeVer) > 0
		case ">=":
			result = compareVersions(version, rangeVer) >= 0
		case "=", "==":
			result = compareVersions(version, rangeVer) == 0
		default:
			// Unknown operator, skip
			i++
			continue
		}

		if !result {
			return false
		}

		i += 2
	}

	return true
}

// versionMatchesMajor checks if version matches a major version (e.g., "5.6.40" matches "5.6")
func versionMatchesMajor(version, majorVersion string) bool {
	// Handle single number major versions (e.g., "1" matches "1.9.1")
	if !strings.Contains(majorVersion, ".") {
		return strings.HasPrefix(version, majorVersion+".")
	}

	return strings.HasPrefix(version, majorVersion)
}

// compareVersions compares two version strings
// Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Remove any non-numeric suffix (e.g., "-ubuntu", "-debian")
	v1 = regexp.MustCompile(`[^0-9.].*$`).ReplaceAllString(v1, "")
	v2 = regexp.MustCompile(`[^0-9.].*$`).ReplaceAllString(v2, "")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int

		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return 0
}
