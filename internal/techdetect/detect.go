package techdetect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// FooterVersionPattern defines a pattern for extracting versions from HTML content
type FooterVersionPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

type Result struct {
	Domain        string                 `json:"domain"`
	TechByHost    map[string][]string    `json:"tech_by_host"`
	TechCount     map[string]int         `json:"tech_count"`
	VersionByHost map[string][]string    `json:"version_by_host,omitempty"` // Service versions (e.g., "Grafana v9.1.1")
	HttpxURLs     []string               `json:"httpx_urls,omitempty"`      // Full URLs that responded to httpx (for screenshots)
	Total         int                    `json:"total"`
	Duration      time.Duration          `json:"duration"`
}

type Detector struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewDetector(cfg *config.Config, checker *tools.Checker) *Detector {
	return &Detector{cfg: cfg, c: checker}
}

// Detect runs technology detection on a list of hosts
func (d *Detector) Detect(hosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TechByHost:    make(map[string][]string),
		TechCount:     make(map[string]int),
		VersionByHost: make(map[string][]string),
	}

	if len(hosts) == 0 {
		return result, nil
	}

	// Use httpx with tech detection and header extraction
	if d.c.IsInstalled("httpx") {
		techResults, versionResults, httpxURLs := d.httpxTechDetect(hosts)
		result.HttpxURLs = httpxURLs // Store URLs with protocol for screenshots
		for host, techs := range techResults {
			result.TechByHost[host] = techs
			for _, tech := range techs {
				result.TechCount[tech]++
			}
		}
		for host, versions := range versionResults {
			result.VersionByHost[host] = versions
		}

		// BB-15: Detect versions from HTML body (footer, meta tags, UI elements)
		// Many apps like Grafana, NetBox, Jenkins display version in HTML, not headers
		fmt.Println("    [*] Footer/HTML version detection...")
		footerVersions := d.detectFooterVersions(hosts)
		footerCount := 0
		for host, versions := range footerVersions {
			footerCount += len(versions)
			// Add to version results
			existing := result.VersionByHost[host]
			for _, v := range versions {
				if !containsString(existing, v) {
					existing = append(existing, v)
				}
			}
			result.VersionByHost[host] = existing

			// Also add app name (without version) to tech results for filtering
			existingTech := result.TechByHost[host]
			for _, v := range versions {
				// Extract app name from "AppName vX.Y.Z"
				parts := strings.Split(v, " v")
				if len(parts) > 0 && parts[0] != "" {
					appName := parts[0]
					if !containsString(existingTech, appName) {
						existingTech = append(existingTech, appName)
						result.TechCount[appName]++
					}
				}
			}
			result.TechByHost[host] = existingTech
		}
		fmt.Printf("        footer_versions: %d detected\n", footerCount)

		// BB-16: Detect versions from API endpoints
		// Many apps expose version info via unauthenticated API endpoints
		fmt.Println("    [*] API endpoint version detection...")
		apiVersions := d.detectAPIVersions(hosts)
		apiCount := 0
		for host, versions := range apiVersions {
			apiCount += len(versions)
			existing := result.VersionByHost[host]
			for _, v := range versions {
				if !containsString(existing, v) {
					existing = append(existing, v)
				}
			}
			result.VersionByHost[host] = existing

			// Also add app name to tech results
			existingTech := result.TechByHost[host]
			for _, v := range versions {
				parts := strings.Split(v, " v")
				if len(parts) > 0 && parts[0] != "" {
					appName := parts[0]
					if !containsString(existingTech, appName) {
						existingTech = append(existingTech, appName)
						result.TechCount[appName]++
					}
				}
			}
			result.TechByHost[host] = existingTech
		}
		fmt.Printf("        api_versions: %d detected\n", apiCount)
	}

	result.Total = len(result.TechByHost)
	result.Duration = time.Since(start)
	return result, nil
}

// httpxTechDetect uses httpx with tech detection and version extraction
// Returns: techByHost (wappalyzer-based), versionByHost (from Server/X-Powered-By headers), httpxURLs (full URLs with protocol)
func (d *Detector) httpxTechDetect(hosts []string) (map[string][]string, map[string][]string, []string) {
	if !d.c.IsInstalled("httpx") {
		return nil, nil, nil
	}

	// Create temp file with hosts
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-hosts.txt")
	if err != nil {
		return nil, nil, nil
	}
	defer cleanup()

	// httpx with tech detection AND header extraction for version info
	// -server: extract Server header (e.g., "Apache/2.4.51", "nginx/1.21.0")
	// -web-server: alternative server detection
	// X-Powered-By is included in response-header extraction
	args := []string{
		"-l", tmpFile,
		"-tech-detect",
		"-server",           // Extract Server header
		"-include-response-header", // Include all response headers for version extraction
		"-json",
		"-silent",
	}
	if d.cfg.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", d.cfg.Threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return nil, nil, nil
	}

	// Parse JSON output
	techResults := make(map[string][]string)
	versionResults := make(map[string][]string)
	seenURLs := make(map[string]bool) // Deduplicate URLs
	var httpxURLs []string

	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			URL       string            `json:"url"`
			Tech      []string          `json:"tech"`
			WebServer string            `json:"webserver"`
			Header    map[string]string `json:"header,omitempty"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Collect unique URLs with protocol for screenshots
		// Strip path but keep protocol and host:port
		baseURL := entry.URL
		// Find position after "://" to locate the path separator
		if schemeEnd := strings.Index(baseURL, "://"); schemeEnd > 0 {
			hostStart := schemeEnd + 3 // Position after "://"
			if pathIdx := strings.Index(baseURL[hostStart:], "/"); pathIdx > 0 {
				baseURL = baseURL[:hostStart+pathIdx]
			}
		}
		if !seenURLs[baseURL] {
			seenURLs[baseURL] = true
			httpxURLs = append(httpxURLs, baseURL)
		}

		// Extract host from URL (strip scheme, path, and port)
		host := entry.URL
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		// Strip port to avoid counting same host with different ports multiple times
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			host = host[:idx]
		}

		// Merge techs for same host (might be from different ports)
		if len(entry.Tech) > 0 {
			existing := techResults[host]
			for _, tech := range entry.Tech {
				found := false
				for _, e := range existing {
					if e == tech {
						found = true
						break
					}
				}
				if !found {
					existing = append(existing, tech)
				}
			}
			techResults[host] = existing
		}

		// Extract version info from headers
		existingVersions := versionResults[host]

		// Server header often contains version (e.g., "Apache/2.4.51", "nginx/1.21.0")
		if entry.WebServer != "" {
			version := extractVersionFromHeader(entry.WebServer)
			if version != "" && !containsString(existingVersions, version) {
				existingVersions = append(existingVersions, version)
			}
		}

		// Check response headers for version info
		if entry.Header != nil {
			// X-Powered-By (e.g., "PHP/8.1.0", "ASP.NET", "Express")
			if xPoweredBy, ok := entry.Header["x-powered-by"]; ok && xPoweredBy != "" {
				version := extractVersionFromHeader(xPoweredBy)
				if version != "" && !containsString(existingVersions, version) {
					existingVersions = append(existingVersions, version)
				}
			}

			// Server header backup (sometimes in different format)
			if server, ok := entry.Header["server"]; ok && server != "" {
				version := extractVersionFromHeader(server)
				if version != "" && !containsString(existingVersions, version) {
					existingVersions = append(existingVersions, version)
				}
			}

			// X-AspNet-Version
			if aspVersion, ok := entry.Header["x-aspnet-version"]; ok && aspVersion != "" {
				version := "ASP.NET " + aspVersion
				if !containsString(existingVersions, version) {
					existingVersions = append(existingVersions, version)
				}
			}

			// X-Generator (common in CMS like WordPress, Drupal)
			if generator, ok := entry.Header["x-generator"]; ok && generator != "" {
				if !containsString(existingVersions, generator) {
					existingVersions = append(existingVersions, generator)
				}
			}
		}

		if len(existingVersions) > 0 {
			versionResults[host] = existingVersions
		}
	}

	return techResults, versionResults, httpxURLs
}

// extractVersionFromHeader extracts version info from a header value
// Examples: "Apache/2.4.51" -> "Apache/2.4.51", "nginx" -> "", "Grafana v9.1.1" -> "Grafana v9.1.1"
func extractVersionFromHeader(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}

	// Check if it contains version-like patterns
	// Pattern: software/version, software version, software vX.Y.Z
	hasVersion := false

	// Check for version patterns
	for _, pattern := range []string{"/", " v", " V", "."} {
		if strings.Contains(header, pattern) {
			hasVersion = true
			break
		}
	}

	// Also check for version numbers like "1.2.3", "v1.2", etc.
	if !hasVersion {
		for i := 0; i < len(header); i++ {
			if header[i] >= '0' && header[i] <= '9' {
				hasVersion = true
				break
			}
		}
	}

	if hasVersion {
		return header
	}
	return ""
}

// containsString checks if a slice contains a string
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// Common patterns for extracting versions from HTML body/footer
// Many applications display version info in footer, meta tags, or UI elements
var footerPatterns = []FooterVersionPattern{
	// Grafana - displays "Grafana v9.1.1" or "v9.1.1" in footer
	{Name: "Grafana", Pattern: regexp.MustCompile(`(?i)(?:grafana[^v]*?)?v(\d+\.\d+(?:\.\d+)?(?:-[a-z0-9]+)?)`),},
	// Netbox - displays "NetBox v3.5.1" in footer
	{Name: "NetBox", Pattern: regexp.MustCompile(`(?i)NetBox\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// GitLab - displays "GitLab Enterprise Edition 15.11.1" or in meta tag
	{Name: "GitLab", Pattern: regexp.MustCompile(`(?i)GitLab(?:\s+(?:Enterprise|Community)\s+Edition)?\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Jenkins - displays "Jenkins ver. 2.414.1" in footer
	{Name: "Jenkins", Pattern: regexp.MustCompile(`(?i)Jenkins\s+(?:ver\.\s*)?v?(\d+\.\d+(?:\.\d+)?)`),},
	// Kibana - displays "Kibana 8.9.0"
	{Name: "Kibana", Pattern: regexp.MustCompile(`(?i)Kibana\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Prometheus - displays "Prometheus v2.45.0"
	{Name: "Prometheus", Pattern: regexp.MustCompile(`(?i)Prometheus\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Alertmanager - displays "Alertmanager v0.26.0"
	{Name: "Alertmanager", Pattern: regexp.MustCompile(`(?i)Alertmanager\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Consul - displays "Consul v1.16.0"
	{Name: "Consul", Pattern: regexp.MustCompile(`(?i)Consul\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Vault - displays "Vault v1.14.0"
	{Name: "Vault", Pattern: regexp.MustCompile(`(?i)Vault\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Airflow - displays "Apache Airflow v2.7.0"
	{Name: "Airflow", Pattern: regexp.MustCompile(`(?i)(?:Apache\s+)?Airflow\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// JFrog Artifactory
	{Name: "Artifactory", Pattern: regexp.MustCompile(`(?i)Artifactory\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Harbor
	{Name: "Harbor", Pattern: regexp.MustCompile(`(?i)Harbor\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// SonarQube
	{Name: "SonarQube", Pattern: regexp.MustCompile(`(?i)SonarQube\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Jira - meta generator tag
	{Name: "Jira", Pattern: regexp.MustCompile(`(?i)Atlassian\s+Jira[^0-9]*v?(\d+\.\d+(?:\.\d+)?)`),},
	// Confluence
	{Name: "Confluence", Pattern: regexp.MustCompile(`(?i)Atlassian\s+Confluence[^0-9]*v?(\d+\.\d+(?:\.\d+)?)`),},
	// WordPress generator meta tag
	{Name: "WordPress", Pattern: regexp.MustCompile(`(?i)WordPress\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Drupal generator meta tag
	{Name: "Drupal", Pattern: regexp.MustCompile(`(?i)Drupal\s+v?(\d+(?:\.\d+)*)`),},
	// Django version in debug page
	{Name: "Django", Pattern: regexp.MustCompile(`(?i)Django\s+Version[:\s]+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Rails version in debug page
	{Name: "Rails", Pattern: regexp.MustCompile(`(?i)Rails\s+v?(\d+\.\d+(?:\.\d+)?)`),},
	// Spring Boot Actuator
	{Name: "Spring Boot", Pattern: regexp.MustCompile(`(?i)Spring\s+Boot\s+v?(\d+\.\d+(?:\.\d+)?)`),},
}

// detectFooterVersions scans HTML body for version info displayed in UI/footer
func (d *Detector) detectFooterVersions(hosts []string) map[string][]string {
	results := make(map[string][]string)

	if !d.c.IsInstalled("httpx") || len(hosts) == 0 {
		return results
	}

	// Create temp file with hosts
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-hosts.txt")
	if err != nil {
		return results
	}
	defer cleanup()

	// httpx with body preview - capture first 10KB of response body
	args := []string{
		"-l", tmpFile,
		"-body-preview", "10000",
		"-json",
		"-silent",
		"-no-color",
	}
	if d.cfg.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", d.cfg.Threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return results
	}

	// Parse JSON output
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			URL         string `json:"url"`
			BodyPreview string `json:"body_preview"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.BodyPreview == "" {
			continue
		}

		// Extract host from URL
		host := entry.URL
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			host = host[:idx]
		}

		// Check all footer patterns against body content
		for _, fp := range footerPatterns {
			if matches := fp.Pattern.FindStringSubmatch(entry.BodyPreview); len(matches) > 1 {
				version := fmt.Sprintf("%s v%s", fp.Name, matches[1])
				existing := results[host]
				if !containsString(existing, version) {
					results[host] = append(existing, version)
				}
			}
		}

		// Also check for meta generator tag
		if metaMatch := regexp.MustCompile(`<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`).FindStringSubmatch(entry.BodyPreview); len(metaMatch) > 1 {
			generator := strings.TrimSpace(metaMatch[1])
			if generator != "" {
				existing := results[host]
				if !containsString(existing, generator) {
					results[host] = append(existing, generator)
				}
			}
		}
	}

	return results
}

// APIVersionEndpoint defines an API endpoint that exposes version info
type APIVersionEndpoint struct {
	Name         string         // App name
	Path         string         // API path to check
	VersionRegex *regexp.Regexp // Regex to extract version from JSON response
}

// Common API endpoints that expose version information without authentication
var apiVersionEndpoints = []APIVersionEndpoint{
	// Grafana - /api/health returns {"commit":"...","database":"ok","version":"x.x.x"}
	{Name: "Grafana", Path: "/api/health", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// Prometheus - /api/v1/status/buildinfo returns version info
	{Name: "Prometheus", Path: "/api/v1/status/buildinfo", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// Alertmanager - /api/v2/status returns version
	{Name: "Alertmanager", Path: "/api/v2/status", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// Consul - /v1/agent/self returns version
	{Name: "Consul", Path: "/v1/agent/self", VersionRegex: regexp.MustCompile(`"Version"\s*:\s*"([^"]+)"`)},
	// Vault - /v1/sys/health returns version
	{Name: "Vault", Path: "/v1/sys/health", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// Kibana - /api/status returns version
	{Name: "Kibana", Path: "/api/status", VersionRegex: regexp.MustCompile(`"version"\s*:\s*{\s*"number"\s*:\s*"([^"]+)"`)},
	// Elasticsearch - / returns version
	{Name: "Elasticsearch", Path: "/", VersionRegex: regexp.MustCompile(`"version"\s*:\s*{\s*"number"\s*:\s*"([^"]+)"`)},
	// Harbor - /api/v2.0/systeminfo returns version
	{Name: "Harbor", Path: "/api/v2.0/systeminfo", VersionRegex: regexp.MustCompile(`"harbor_version"\s*:\s*"v?([^"]+)"`)},
	// Airflow - /api/v1/version returns version
	{Name: "Airflow", Path: "/api/v1/version", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// SonarQube - /api/system/status returns version
	{Name: "SonarQube", Path: "/api/system/status", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// ArgoCD - /api/version returns version
	{Name: "ArgoCD", Path: "/api/version", VersionRegex: regexp.MustCompile(`"Version"\s*:\s*"v?([^"]+)"`)},
	// Kubernetes API - /version returns server version
	{Name: "Kubernetes", Path: "/version", VersionRegex: regexp.MustCompile(`"gitVersion"\s*:\s*"v?([^"]+)"`)},
	// Spring Boot Actuator - /actuator/info returns build info
	{Name: "Spring Boot", Path: "/actuator/info", VersionRegex: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	// Rancher - /v3/settings/server-version returns version
	{Name: "Rancher", Path: "/v3/settings/server-version", VersionRegex: regexp.MustCompile(`"value"\s*:\s*"v?([^"]+)"`)},
}

// detectAPIVersions checks common API endpoints for version information
func (d *Detector) detectAPIVersions(hosts []string) map[string][]string {
	results := make(map[string][]string)

	if !d.c.IsInstalled("httpx") || len(hosts) == 0 {
		return results
	}

	// Build list of URLs to check (host + each API endpoint)
	var urlsToCheck []string
	hostMap := make(map[string]string) // URL -> original host

	for _, host := range hosts {
		// Normalize host to base URL
		baseURL := host
		if !strings.HasPrefix(baseURL, "http") {
			baseURL = "https://" + host
		}
		// Strip any path from the URL
		if idx := strings.Index(baseURL[8:], "/"); idx > 0 {
			baseURL = baseURL[:8+idx]
		}

		for _, endpoint := range apiVersionEndpoints {
			url := baseURL + endpoint.Path
			urlsToCheck = append(urlsToCheck, url)
			hostMap[url] = host
		}
	}

	if len(urlsToCheck) == 0 {
		return results
	}

	// Create temp file with URLs
	input := strings.Join(urlsToCheck, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-api-urls.txt")
	if err != nil {
		return results
	}
	defer cleanup()

	// Use httpx to fetch all URLs in parallel
	args := []string{
		"-l", tmpFile,
		"-body-preview", "2000",
		"-status-code",
		"-json",
		"-silent",
		"-no-color",
		"-mc", "200", // Only match 200 OK responses
	}
	if d.cfg.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", d.cfg.Threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return results
	}

	// Parse responses
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			URL         string `json:"url"`
			StatusCode  int    `json:"status_code"`
			BodyPreview string `json:"body_preview"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.StatusCode != 200 || entry.BodyPreview == "" {
			continue
		}

		// Find which endpoint this matches
		for _, endpoint := range apiVersionEndpoints {
			if strings.HasSuffix(entry.URL, endpoint.Path) {
				if matches := endpoint.VersionRegex.FindStringSubmatch(entry.BodyPreview); len(matches) > 1 {
					version := fmt.Sprintf("%s v%s", endpoint.Name, matches[1])

					// Extract host from URL
					host := entry.URL
					host = strings.TrimPrefix(host, "http://")
					host = strings.TrimPrefix(host, "https://")
					if idx := strings.Index(host, "/"); idx > 0 {
						host = host[:idx]
					}
					if idx := strings.LastIndex(host, ":"); idx > 0 {
						host = host[:idx]
					}

					existing := results[host]
					if !containsString(existing, version) {
						results[host] = append(existing, version)
					}
				}
				break
			}
		}
	}

	return results
}
