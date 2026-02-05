package vulnscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
)

// InstalledChecker interface for checking if tools are installed
type InstalledChecker interface {
	IsInstalled(name string) bool
}

// ExploitInfo contains exploit information from ExploitDB
type ExploitInfo struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Type        string `json:"type"` // local, remote, webapps, dos
	Platform    string `json:"platform"`
	Path        string `json:"path"`
	DatePublish string `json:"date"`
	CVE         string `json:"cve,omitempty"`
}

// CVELookup provides dynamic CVE lookup using multiple sources
type CVELookup struct {
	cache   *CVECache
	checker InstalledChecker
	mu      sync.Mutex
}

// NewCVELookup creates a new CVE lookup instance
func NewCVELookup(checker InstalledChecker) *CVELookup {
	return &CVELookup{
		cache:   NewCVECache(),
		checker: checker,
	}
}

// skipCVELookup is now defined in skip_list.go as SkipCVELookup (shared with aiguided scanner)
// Use ShouldSkipCVELookup(product) to check if a product should be skipped

// LookupCVEs looks up CVEs for a product/version using hybrid approach:
// 1. Check local cache
// 2. Query vulnx (if installed)
// 3. Query NVD API (if online)
// 4. Fall back to hardcoded database
func (l *CVELookup) LookupCVEs(product, version string) []CVEInfo {
	// Normalize product name
	product = normalizeProductName(product)

	// Skip products that shouldn't have CVE lookups (cloud services, CDNs, etc.)
	if ShouldSkipCVELookup(product) {
		return nil
	}

	// 1. Check cache first
	if cached, ok := l.cache.Get(product, version); ok {
		return cached.CVEs
	}

	var cves []CVEInfo
	var source string

	// 2. Try vulnx (ProjectDiscovery's CVE lookup tool)
	if l.checker != nil && l.checker.IsInstalled("vulnx") {
		cves, source = l.lookupVulnx(product, version)
		if len(cves) > 0 {
			l.cache.Set(product, version, cves, source)
			return cves
		}
	}

	// 3. Try NVD API
	cves, source = l.lookupNVD(product, version)
	if len(cves) > 0 {
		l.cache.Set(product, version, cves, source)
		return cves
	}

	// 4. Fall back to hardcoded database
	cves = l.lookupHardcoded(product, version)
	if len(cves) > 0 {
		l.cache.Set(product, version, cves, "hardcoded")
	}

	return cves
}

// lookupVulnx queries vulnx for CVEs
func (l *CVELookup) lookupVulnx(product, version string) ([]CVEInfo, string) {
	// vulnx command: vulnx -product "PHP" -version "5.6.40" -json
	args := []string{
		"-product", product,
		"-version", version,
		"-json",
		"-silent",
	}

	r := exec.Run("vulnx", args, &exec.Options{Timeout: 30 * time.Second})
	if r.Error != nil || r.Stdout == "" {
		return nil, ""
	}

	// Parse vulnx JSON output
	var result struct {
		CVEs []struct {
			ID          string  `json:"cve_id"`
			Severity    string  `json:"severity"`
			CVSS        float64 `json:"cvss_score"`
			Description string  `json:"description"`
			References  []string `json:"references"`
		} `json:"cves"`
	}

	if err := json.Unmarshal([]byte(r.Stdout), &result); err != nil {
		// Try alternative output format
		return l.parseVulnxAlternate(r.Stdout)
	}

	var cves []CVEInfo
	for _, c := range result.CVEs {
		cves = append(cves, CVEInfo{
			ID:          c.ID,
			Severity:    c.Severity,
			CVSS:        c.CVSS,
			Description: c.Description,
			References:  c.References,
		})
	}

	return cves, "vulnx"
}

// parseVulnxAlternate parses alternate vulnx output formats
func (l *CVELookup) parseVulnxAlternate(output string) ([]CVEInfo, string) {
	// Handle line-by-line CVE output
	var cves []CVEInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try parsing as single CVE JSON
		var cve struct {
			ID          string  `json:"cve_id"`
			Severity    string  `json:"severity"`
			CVSS        float64 `json:"cvss_score"`
			Description string  `json:"description"`
		}
		if err := json.Unmarshal([]byte(line), &cve); err == nil && cve.ID != "" {
			cves = append(cves, CVEInfo{
				ID:          cve.ID,
				Severity:    cve.Severity,
				CVSS:        cve.CVSS,
				Description: cve.Description,
			})
		}
	}

	if len(cves) > 0 {
		return cves, "vulnx"
	}
	return nil, ""
}

// lookupNVD queries the NVD API for CVEs
// API: https://services.nvd.nist.gov/rest/json/cves/2.0
func (l *CVELookup) lookupNVD(product, version string) ([]CVEInfo, string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Build CPE search query
	// Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
	cpeProduct := strings.ToLower(strings.ReplaceAll(product, " ", "_"))

	// Map common product names to their CPE vendors
	vendor := getVendorForProduct(product)

	// Use keyword search for better results
	apiURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s+%s&resultsPerPage=50",
		url.QueryEscape(product),
		url.QueryEscape(version),
	)

	// Create HTTP client with timeout
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, ""
	}

	// NVD API requires User-Agent header
	req.Header.Set("User-Agent", "reconator-go/1.0 (vulnerability-scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ""
	}

	// Parse NVD response
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CVSSMetricV2 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Published  string `json:"published"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria   string `json:"criteria"`
							Vulnerable bool   `json:"vulnerable"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, ""
	}

	var cves []CVEInfo
	for _, vuln := range nvdResp.Vulnerabilities {
		// Check if this CVE actually affects our product/version
		if !l.cveAffectsVersion(vuln.CVE.Configurations, vendor, cpeProduct, version) {
			continue
		}

		cve := CVEInfo{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
		}

		// Get description (prefer English)
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		// Get CVSS score and severity
		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			cve.CVSS = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			cve.Severity = strings.ToLower(vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		} else if len(vuln.CVE.Metrics.CVSSMetricV30) > 0 {
			cve.CVSS = vuln.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			cve.Severity = strings.ToLower(vuln.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity)
		} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
			cve.CVSS = vuln.CVE.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
			cve.Severity = strings.ToLower(vuln.CVE.Metrics.CVSSMetricV2[0].BaseSeverity)
		}

		// Get references
		for _, ref := range vuln.CVE.References {
			cve.References = append(cve.References, ref.URL)
		}

		cves = append(cves, cve)
	}

	if len(cves) > 0 {
		return cves, "nvd"
	}
	return nil, ""
}

// cveAffectsVersion checks if CVE configurations match our product/version
func (l *CVELookup) cveAffectsVersion(configs []struct {
	Nodes []struct {
		CPEMatch []struct {
			Criteria   string `json:"criteria"`
			Vulnerable bool   `json:"vulnerable"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}, vendor, product, version string) bool {
	// If no configurations, be conservative - only accept if product is well-known
	if len(configs) == 0 {
		// Only trust keyword-only matches for well-known products
		wellKnown := map[string]bool{
			"php": true, "iis": true, "jquery": true, "apache": true,
			"nginx": true, "bootstrap": true, "angularjs": true,
		}
		return wellKnown[strings.ToLower(product)]
	}

	// CPE format: cpe:2.3:a:vendor:product:version:...
	// We need to match the product field (4th component) exactly
	productLower := strings.ToLower(product)
	productNormalized := strings.ReplaceAll(productLower, " ", "_")
	vendorLower := strings.ToLower(vendor)

	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				// Parse CPE components
				// cpe:2.3:a:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
				cpeParts := strings.Split(strings.ToLower(match.Criteria), ":")
				if len(cpeParts) < 5 {
					continue
				}

				cpeVendor := cpeParts[3]
				cpeProduct := cpeParts[4]

				// Require exact product match (with common variations)
				productMatches := cpeProduct == productNormalized ||
					cpeProduct == productLower ||
					cpeProduct == strings.ReplaceAll(productLower, "-", "_") ||
					strings.Contains(cpeProduct, productNormalized)

				// Vendor should also match (but be more lenient)
				vendorMatches := cpeVendor == vendorLower ||
					strings.Contains(cpeVendor, vendorLower) ||
					strings.Contains(vendorLower, cpeVendor)

				if productMatches && vendorMatches {
					return true
				}

				// Also accept if vendor OR product match exactly (for single-name products like "jquery")
				if cpeProduct == productNormalized || cpeProduct == productLower {
					return true
				}
			}
		}
	}
	return false
}

// lookupHardcoded uses the hardcoded vulnerability database
func (l *CVELookup) lookupHardcoded(product, version string) []CVEInfo {
	var cves []CVEInfo

	for _, vuln := range KnownVulnerableVersions {
		if matchesProduct(product, vuln.Product) && versionInRange(version, vuln.AffectedRange) {
			for _, cveID := range vuln.CVEs {
				cves = append(cves, CVEInfo{
					ID:          cveID,
					Severity:    vuln.Severity,
					Description: vuln.Description,
					References:  vuln.References,
				})
			}
		}
	}

	return cves
}

// normalizeProductName normalizes product name for lookup
func normalizeProductName(product string) string {
	// Remove version from product name if present
	product = strings.TrimSpace(product)

	// Common normalizations
	normalizations := map[string]string{
		"microsoft-iis":     "IIS",
		"microsoft iis":     "IIS",
		"apache httpd":      "Apache HTTP Server",
		"apache http":       "Apache HTTP Server",
		"asp.net":           "Microsoft ASP.NET",
		"aspnet":            "Microsoft ASP.NET",
		"angular.js":        "AngularJS",
		"twitter bootstrap": "Bootstrap",
	}

	productLower := strings.ToLower(product)
	if normalized, ok := normalizations[productLower]; ok {
		return normalized
	}

	return product
}

// getVendorForProduct returns the CPE vendor for common products
func getVendorForProduct(product string) string {
	vendors := map[string]string{
		"php":                "php",
		"iis":                "microsoft",
		"jquery":             "jquery",
		"apache http server": "apache",
		"apache":             "apache",
		"nginx":              "nginx",
		"bootstrap":          "getbootstrap",
		"angularjs":          "angularjs",
		"microsoft asp.net":  "microsoft",
	}

	productLower := strings.ToLower(product)
	if vendor, ok := vendors[productLower]; ok {
		return vendor
	}
	return strings.ToLower(strings.ReplaceAll(product, " ", "_"))
}

// GetCache returns the cache instance for stats/management
func (l *CVELookup) GetCache() *CVECache {
	return l.cache
}

// LookupExploits searches ExploitDB via searchsploit for known exploits
// searchsploit must be installed (comes with Kali, or install exploit-database package)
func (l *CVELookup) LookupExploits(product, version string) []ExploitInfo {
	if l.checker == nil || !l.checker.IsInstalled("searchsploit") {
		return nil
	}

	// Build search query combining product and version
	query := fmt.Sprintf("%s %s", product, version)

	// Run searchsploit with JSON output
	// searchsploit -j "php 5.6" - returns JSON format
	args := []string{"-j", "--disable-colour", query}

	r := exec.Run("searchsploit", args, &exec.Options{Timeout: 30 * time.Second})
	if r.Error != nil || r.Stdout == "" {
		return nil
	}

	// Parse searchsploit JSON output
	var result struct {
		Exploits []struct {
			ID          string `json:"EDB-ID"`
			Title       string `json:"Title"`
			Type        string `json:"Type"`
			Platform    string `json:"Platform"`
			Path        string `json:"Path"`
			DatePublish string `json:"Date_Published"`
		} `json:"RESULTS_EXPLOIT"`
	}

	if err := json.Unmarshal([]byte(r.Stdout), &result); err != nil {
		return nil
	}

	var exploits []ExploitInfo
	seen := make(map[string]bool)

	for _, e := range result.Exploits {
		// Deduplicate
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true

		exploit := ExploitInfo{
			ID:          e.ID,
			Title:       e.Title,
			Type:        e.Type,
			Platform:    e.Platform,
			Path:        e.Path,
			DatePublish: e.DatePublish,
		}

		// Try to extract CVE from title (common pattern: "CVE-YYYY-NNNNN")
		if cve := extractCVEFromTitle(e.Title); cve != "" {
			exploit.CVE = cve
		}

		exploits = append(exploits, exploit)
	}

	return exploits
}

// extractCVEFromTitle extracts CVE ID from exploit title
func extractCVEFromTitle(title string) string {
	// Pattern: CVE-YYYY-NNNNN
	idx := strings.Index(strings.ToUpper(title), "CVE-")
	if idx == -1 {
		return ""
	}

	// Extract the CVE ID
	cveStart := idx
	cveEnd := idx + 4 // "CVE-"

	// Get the year part (4 digits)
	for cveEnd < len(title) && cveEnd < idx+8 {
		if title[cveEnd] >= '0' && title[cveEnd] <= '9' {
			cveEnd++
		} else {
			break
		}
	}

	// Check for dash after year
	if cveEnd < len(title) && title[cveEnd] == '-' {
		cveEnd++
		// Get the ID part (4-7 digits)
		for cveEnd < len(title) && cveEnd < idx+16 {
			if title[cveEnd] >= '0' && title[cveEnd] <= '9' {
				cveEnd++
			} else {
				break
			}
		}
	}

	cve := title[cveStart:cveEnd]
	// Validate it looks like a CVE
	if len(cve) >= 13 && strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
		return strings.ToUpper(cve)
	}
	return ""
}

// LookupAll performs comprehensive lookup using all sources and returns combined results
func (l *CVELookup) LookupAll(product, version string) (cves []CVEInfo, exploits []ExploitInfo, source string) {
	// Get CVEs
	cves = l.LookupCVEs(product, version)

	// Determine source from cache
	if cached, ok := l.cache.Get(product, version); ok {
		source = cached.Source
	}

	// Get exploits from ExploitDB
	exploits = l.LookupExploits(product, version)

	return cves, exploits, source
}

// ConvertExploitsToVulns converts ExploitDB results to Vulnerability entries
func ConvertExploitsToVulns(exploits []ExploitInfo, host, product, version string) []Vulnerability {
	var vulns []Vulnerability

	for _, exploit := range exploits {
		severity := "medium"
		// Remote and webapps exploits are typically more severe
		if exploit.Type == "remote" || exploit.Type == "webapps" {
			severity = "high"
		}

		templateID := fmt.Sprintf("edb-%s", exploit.ID)
		if exploit.CVE != "" {
			templateID = strings.ToLower(exploit.CVE)
		}

		vulns = append(vulns, Vulnerability{
			Host:       host,
			TemplateID: templateID,
			Name:       fmt.Sprintf("ExploitDB: %s", exploit.Title),
			Severity:   severity,
			Type:       "exploit-available",
			Description: fmt.Sprintf("Public exploit available in ExploitDB (EDB-%s)\n"+
				"Type: %s | Platform: %s\n"+
				"Detected: %s %s on %s\n"+
				"Exploit path: %s",
				exploit.ID, exploit.Type, exploit.Platform, product, version, host, exploit.Path),
			Tool: "searchsploit",
		})
	}

	return vulns
}
