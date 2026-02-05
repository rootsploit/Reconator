package report

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/jsanalysis"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/trufflehog"
	"github.com/rootsploit/reconator/internal/vhost"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// Data holds all scan results for the report
type Data struct {
	// Metadata
	Target   string `json:"Target"`
	Version  string `json:"Version"`
	Date     string `json:"Date"`
	Duration string `json:"Duration"`
	Command  string `json:"Command"`

	// Phase Results
	Subdomain  *subdomain.Result   `json:"Subdomain,omitempty"`
	WAF        *waf.Result         `json:"WAF,omitempty"`
	Ports      *portscan.Result    `json:"Ports,omitempty"`
	VHost      *vhost.Result       `json:"VHost,omitempty"`
	Takeover   *takeover.Result    `json:"Takeover,omitempty"`
	Historic   *historic.Result    `json:"Historic,omitempty"`
	Tech       *techdetect.Result  `json:"Tech,omitempty"`
	DirBrute   *dirbrute.Result    `json:"DirBrute,omitempty"`
	VulnScan   *vulnscan.Result    `json:"VulnScan,omitempty"`
	AIGuided   *aiguided.Result    `json:"AIGuided,omitempty"`
	IPRange    *iprange.Result     `json:"IPRange,omitempty"`
	Screenshot *screenshot.Result  `json:"Screenshot,omitempty"`
	JSAnalysis *jsanalysis.Result  `json:"JSAnalysis,omitempty"`
	TruffleHog *trufflehog.Result  `json:"TruffleHog,omitempty"`
	SecHeaders *secheaders.Result  `json:"SecHeaders,omitempty"`
	OSINT      interface{}         `json:"OSINT,omitempty"`

	// Computed per-subdomain details
	SubdomainDetails []SubdomainDetail

	// Screenshots embedded as base64 for self-contained HTML
	ScreenshotImages []ScreenshotImage

	// Screenshot clusters for gallery view
	ScreenshotClusters []ScreenshotCluster

	// Technology summary for visualization
	TechSummary []TechCount

	// Logo embedded as base64 for branding
	LogoBase64 template.URL
}

// ScreenshotImage holds a screenshot with embedded base64 data
type ScreenshotImage struct {
	URL       string
	Host      string
	DataURI   template.URL // base64 encoded image (template.URL to prevent escaping)
	FilePath  string
	ClusterID string
}

// ScreenshotCluster groups screenshots by visual similarity
type ScreenshotCluster struct {
	ID          string
	Name        string
	Count       int
	Screenshots []ScreenshotImage
}

// TechCount for technology visualization
type TechCount struct {
	Name  string
	Count int
}

// SubdomainDetail holds aggregated information for a single subdomain
type SubdomainDetail struct {
	Name         string
	IsAlive      bool
	Ports        []int
	Services     []ServiceInfo
	Technologies []string
	Versions     []string // Software versions (e.g., "Grafana v9.1.1", "NetBox v3.5.1")
	Vulns        []VulnInfo
	TakeoverRisk bool
	TakeoverSvc  string
	WAFProtected bool
	WAFName      string
	DirFindings  int
	IPAddress    string
	StatusCode   int
	// Enhanced fields for richer display
	ASN          string // ASN info (e.g., "AS13335, Cloudflare")
	WebServer    string // Web server header (e.g., "nginx", "cloudflare")
	SSLIssuer    string // SSL certificate issuer
	SSLDaysLeft  int    // Days until SSL cert expiry
	SSLExpired   bool   // True if SSL cert is expired
}

// ServiceInfo holds service information for display
type ServiceInfo struct {
	Port       int
	Title      string
	StatusCode int
	WebServer  string // Web server (e.g., "nginx", "envoy")
	TLS        bool   // True if HTTPS (port 443, 8443, etc.)
}

// VulnInfo holds vulnerability information for display
type VulnInfo struct {
	Name     string
	Severity string
	Type     string
}

// aggregateSubdomainDetails builds per-subdomain view from all scan results
func aggregateSubdomainDetails(data *Data) []SubdomainDetail {
	if data.Subdomain == nil || len(data.Subdomain.Subdomains) == 0 {
		return nil
	}

	// Build lookup maps for efficient aggregation
	aliveSet := make(map[string]bool)
	if data.Ports != nil {
		for _, url := range data.Ports.AliveHosts {
			host := extractHost(url)
			aliveSet[host] = true
		}
	}

	portsByHost := make(map[string][]int)
	servicesByHost := make(map[string][]ServiceInfo)
	ipByHost := make(map[string]string)
	asnByHost := make(map[string]string)
	webServerByHost := make(map[string]string)
	if data.Ports != nil {
		for host, ports := range data.Ports.OpenPorts {
			portsByHost[host] = ports
		}
		for host, svcs := range data.Ports.Services {
			for _, svc := range svcs {
				// Determine if TLS based on port
				isTLS := svc.Port == 443 || svc.Port == 8443 || svc.Port == 9443 || svc.Port == 4443
				servicesByHost[host] = append(servicesByHost[host], ServiceInfo{
					Port:       svc.Port,
					Title:      svc.Title,
					StatusCode: svc.StatusCode,
					WebServer:  svc.WebServer,
					TLS:        isTLS,
				})
				// Capture IP, ASN, WebServer from first service with data
				if svc.IP != "" && ipByHost[host] == "" {
					ipByHost[host] = svc.IP
				}
				if svc.ASN != "" && asnByHost[host] == "" {
					asnByHost[host] = svc.ASN
				}
				if svc.WebServer != "" && webServerByHost[host] == "" {
					webServerByHost[host] = svc.WebServer
				}
			}
		}
	}

	// Extract SSL/TLS info
	sslIssuerByHost := make(map[string]string)
	sslDaysByHost := make(map[string]int)
	sslExpiredByHost := make(map[string]bool)
	if data.Ports != nil && data.Ports.TLSInfo != nil {
		for host, tls := range data.Ports.TLSInfo {
			sslIssuerByHost[host] = tls.Issuer
			sslDaysByHost[host] = tls.DaysLeft
			sslExpiredByHost[host] = tls.DaysLeft < 0
		}
	}

	// Normalize tech data - TechByHost keys may include ports (e.g., "app.example.com:443")
	// We need to map by plain hostname for subdomain lookup
	techByHost := make(map[string][]string)
	versionsByHost := make(map[string][]string)
	if data.Tech != nil {
		for hostWithPort, techs := range data.Tech.TechByHost {
			// Extract plain hostname without port
			host := extractHost(hostWithPort)
			// Merge techs if we've seen this host before (different ports)
			existing := techByHost[host]
			for _, tech := range techs {
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
			techByHost[host] = existing
		}
		// Also extract version info (footer/header versions like "Grafana v9.1.1")
		for hostWithPort, versions := range data.Tech.VersionByHost {
			host := extractHost(hostWithPort)
			existing := versionsByHost[host]
			for _, v := range versions {
				found := false
				for _, e := range existing {
					if e == v {
						found = true
						break
					}
				}
				if !found {
					existing = append(existing, v)
				}
			}
			versionsByHost[host] = existing
		}
	}

	vulnsByHost := make(map[string][]VulnInfo)
	if data.VulnScan != nil {
		for _, v := range data.VulnScan.Vulnerabilities {
			host := extractHost(v.Host)
			vulnsByHost[host] = append(vulnsByHost[host], VulnInfo{
				Name:     v.Name,
				Severity: v.Severity,
				Type:     v.Type,
			})
		}
	}

	takeoverByHost := make(map[string]string)
	if data.Takeover != nil {
		for _, t := range data.Takeover.Vulnerable {
			takeoverByHost[t.Subdomain] = t.Service
		}
	}

	wafByHost := make(map[string]string)
	wafProtected := make(map[string]bool)
	if data.WAF != nil {
		// CDNDetails maps host -> CDN/WAF name
		for host, cdnName := range data.WAF.CDNDetails {
			wafByHost[host] = cdnName
			wafProtected[host] = true
		}
	}

	dirByHost := make(map[string]int)
	if data.DirBrute != nil {
		// ByHost is already map[string]int (count per host)
		dirByHost = data.DirBrute.ByHost
	}

	// Build combined list of all hosts to include in report:
	// 1. Subdomains from enumeration
	// 2. Alive hosts (may include hosts discovered via httpx not in subdomain list)
	// 3. Hosts with tech data (may include hosts from historic URLs)
	allHosts := make(map[string]bool)
	for _, sub := range data.Subdomain.Subdomains {
		allHosts[sub] = true
	}
	// Add alive hosts that might not be in subdomain list
	for host := range aliveSet {
		allHosts[host] = true
	}
	// Add hosts with tech data
	for host := range techByHost {
		allHosts[host] = true
	}

	// Build per-subdomain details
	var details []SubdomainDetail
	for sub := range allHosts {
		detail := SubdomainDetail{
			Name:         sub,
			IsAlive:      aliveSet[sub],
			Ports:        portsByHost[sub],
			Services:     servicesByHost[sub],
			Technologies: techByHost[sub],
			Versions:     versionsByHost[sub],
			Vulns:        vulnsByHost[sub],
			WAFProtected: wafProtected[sub],
			WAFName:      wafByHost[sub],
			DirFindings:  dirByHost[sub],
			// Enhanced fields
			IPAddress:   ipByHost[sub],
			ASN:         asnByHost[sub],
			WebServer:   webServerByHost[sub],
			SSLIssuer:   sslIssuerByHost[sub],
			SSLDaysLeft: sslDaysByHost[sub],
			SSLExpired:  sslExpiredByHost[sub],
		}

		// Get status code from first service
		if len(detail.Services) > 0 {
			detail.StatusCode = detail.Services[0].StatusCode
		}

		if svc, ok := takeoverByHost[sub]; ok {
			detail.TakeoverRisk = true
			detail.TakeoverSvc = svc
		}

		details = append(details, detail)
	}

	// Sort by: alive status (alive first), then subdomain level, then security priority
	// This ensures operational hosts are shown first for quick visibility
	baseDomain := data.Subdomain.Domain
	baseLabels := strings.Count(baseDomain, ".") + 1

	sort.Slice(details, func(i, j int) bool {
		// First: base domain always comes first
		if details[i].Name == baseDomain {
			return true
		}
		if details[j].Name == baseDomain {
			return false
		}

		// Second: alive status (alive subdomains first)
		if details[i].IsAlive != details[j].IsAlive {
			return details[i].IsAlive
		}

		// Third: subdomain level (lower levels first - TLD, then level 1, then level 2, etc.)
		levelI := strings.Count(details[i].Name, ".") + 1 - baseLabels
		levelJ := strings.Count(details[j].Name, ".") + 1 - baseLabels
		if levelI != levelJ {
			return levelI < levelJ
		}

		// Fourth: security priority (takeover risks first, then vulns)
		if details[i].TakeoverRisk != details[j].TakeoverRisk {
			return details[i].TakeoverRisk
		}
		if len(details[i].Vulns) != len(details[j].Vulns) {
			return len(details[i].Vulns) > len(details[j].Vulns)
		}

		// Finally alphabetically within same level
		return details[i].Name < details[j].Name
	})

	return details
}

// extractHost extracts hostname from URL (strips scheme and port)
func extractHost(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	if idx := strings.Index(urlStr, ":"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	if idx := strings.Index(urlStr, "/"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	return urlStr
}

// loadScreenshotImages loads screenshots and embeds them as base64 data URIs
func loadScreenshotImages(data *Data, outputDir string) {
	if data.Screenshot == nil || len(data.Screenshot.Screenshots) == 0 {
		return
	}

	// Build cluster lookup - use filename as key since paths may differ
	clusterLookup := make(map[string]string) // filename -> cluster_id
	clusterNames := make(map[string]string)  // cluster_id -> cluster_name
	if data.Screenshot != nil {
		for _, cluster := range data.Screenshot.Clusters {
			clusterNames[cluster.ID] = cluster.Name
			for _, fp := range cluster.Screenshots {
				// Use just the filename for lookup (paths may differ between recon-box and local)
				clusterLookup[filepath.Base(fp)] = cluster.ID
			}
		}
	}

	// Limit to 500 screenshots to avoid huge HTML files
	maxScreenshots := 500
	count := 0

	// Try multiple screenshot directory names
	screenshotDirs := []string{
		filepath.Join(outputDir, "9-screenshots", "screenshots"),  // New location (v1.0+)
		filepath.Join(outputDir, "screenshots"),                   // Legacy location
		filepath.Join(outputDir, "9-screenshots"),                 // Phase directory
	}

	for _, ss := range data.Screenshot.Screenshots {
		if count >= maxScreenshots {
			break
		}

		var imgData []byte
		var err error
		found := false
		filename := filepath.Base(ss.FilePath)

		// Strategy 1: Try the file path as-is (absolute path)
		imgData, err = os.ReadFile(ss.FilePath)
		if err == nil {
			found = true
		}

		// Strategy 2: Try just the filename in screenshot directories
		if !found {
			for _, screenshotDir := range screenshotDirs {
				filePath := filepath.Join(screenshotDir, filename)
				imgData, err = os.ReadFile(filePath)
				if err == nil {
					found = true
					break
				}
			}
		}

		// Strategy 3: Try from reconator root (parent of outputDir) if path looks like scan_dir/target/...
		if !found {
			reconatorRoot := filepath.Dir(outputDir)
			fullPath := filepath.Join(reconatorRoot, ss.FilePath)
			imgData, err = os.ReadFile(fullPath)
			if err == nil {
				found = true
			}
		}

		// Strategy 4: Try stripping leading path components (handles results/target/screenshots/...)
		if !found {
			// Split path and try progressively shorter paths
			parts := strings.Split(ss.FilePath, "/")
			for i := range parts {
				subPath := filepath.Join(parts[i:]...)
				fullPath := filepath.Join(outputDir, subPath)
				imgData, err = os.ReadFile(fullPath)
				if err == nil {
					found = true
					break
				}
			}
		}

		if !found {
			continue
		}

		// Determine MIME type from extension
		ext := strings.ToLower(filepath.Ext(ss.FilePath))
		mimeType := "image/png"
		if ext == ".jpg" || ext == ".jpeg" {
			mimeType = "image/jpeg"
		}

		// Create base64 data URI
		b64 := base64.StdEncoding.EncodeToString(imgData)
		dataURI := fmt.Sprintf("data:%s;base64,%s", mimeType, b64)

		clusterID := clusterLookup[filename]

		// Use full host with port for display (don't deduplicate)
		displayHost := ss.Host
		if displayHost == "" {
			displayHost = extractHost(ss.URL)
		}

		data.ScreenshotImages = append(data.ScreenshotImages, ScreenshotImage{
			URL:       ss.URL,
			Host:      displayHost,
			DataURI:   template.URL(dataURI),
			FilePath:  ss.FilePath,
			ClusterID: clusterID,
		})
		count++
	}

	// Build screenshot clusters for gallery view
	clusterMap := make(map[string]*ScreenshotCluster)
	for _, img := range data.ScreenshotImages {
		clusterID := img.ClusterID
		if clusterID == "" {
			clusterID = "unclustered"
		}
		if _, ok := clusterMap[clusterID]; !ok {
			name := clusterNames[clusterID]
			if name == "" {
				name = "Other Screenshots"
			}
			clusterMap[clusterID] = &ScreenshotCluster{
				ID:          clusterID,
				Name:        name,
				Screenshots: []ScreenshotImage{},
			}
		}
		clusterMap[clusterID].Screenshots = append(clusterMap[clusterID].Screenshots, img)
		clusterMap[clusterID].Count++
	}

	// Convert to slice and sort by count
	for _, cluster := range clusterMap {
		data.ScreenshotClusters = append(data.ScreenshotClusters, *cluster)
	}
	sort.Slice(data.ScreenshotClusters, func(i, j int) bool {
		return data.ScreenshotClusters[i].Count > data.ScreenshotClusters[j].Count
	})
}

// buildTechSummary creates technology count summary for visualization
func buildTechSummary(data *Data) []TechCount {
	if data.Tech == nil || data.Tech.TechCount == nil {
		return nil
	}

	var summary []TechCount
	for name, count := range data.Tech.TechCount {
		summary = append(summary, TechCount{Name: name, Count: count})
	}

	// Sort by count descending
	sort.Slice(summary, func(i, j int) bool {
		return summary[i].Count > summary[j].Count
	})

	// Limit to top 20
	if len(summary) > 20 {
		summary = summary[:20]
	}

	return summary
}

// severityOrder defines the sort order for vulnerabilities
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// sortVulnerabilitiesBySeverity sorts vulnerabilities by:
// 1. Severity (critical > high > medium > low > info)
// 2. Subdomain level (TLD first, then level 1, level 2, etc.)
// 3. Alphabetically by host within same severity and level
func sortVulnerabilitiesBySeverity(data *Data) {
	if data.VulnScan == nil || len(data.VulnScan.Vulnerabilities) == 0 {
		return
	}

	baseDomain := data.Target
	baseLabels := strings.Count(baseDomain, ".") + 1 // example.com = 2 labels

	sort.Slice(data.VulnScan.Vulnerabilities, func(i, j int) bool {
		vi := data.VulnScan.Vulnerabilities[i]
		vj := data.VulnScan.Vulnerabilities[j]

		// Primary sort: severity (lower order = higher priority)
		iSeverity := severityOrder[strings.ToLower(vi.Severity)]
		jSeverity := severityOrder[strings.ToLower(vj.Severity)]
		if iSeverity != jSeverity {
			return iSeverity < jSeverity
		}

		// Secondary sort: subdomain level (lower level = higher priority)
		iHost := extractHostFromVuln(vi)
		jHost := extractHostFromVuln(vj)
		iLevel := getSubdomainLevel(iHost, baseLabels)
		jLevel := getSubdomainLevel(jHost, baseLabels)
		if iLevel != jLevel {
			return iLevel < jLevel
		}

		// Tertiary sort: alphabetically by host
		return iHost < jHost
	})
}

// extractHostFromVuln extracts the hostname from a vulnerability's URL or Host field
func extractHostFromVuln(v vulnscan.Vulnerability) string {
	host := v.Host
	if v.URL != "" {
		// Extract host from URL
		host = v.URL
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx > 0 {
			host = host[:idx]
		}
	}
	return strings.ToLower(host)
}

// getSubdomainLevel calculates the subdomain depth relative to the base domain
// Level 0: example.com (the TLD itself)
// Level 1: api.example.com
// Level 2: dev.api.example.com
func getSubdomainLevel(host string, baseLabels int) int {
	if host == "" {
		return 999 // Unknown hosts sort last
	}
	hostLabels := strings.Count(host, ".") + 1
	level := hostLabels - baseLabels
	if level < 0 {
		level = 0
	}
	return level
}

// mergeSecHeadersAsVulnerabilities converts security header findings into vulnerabilities
// and adds them to the VulnScan results for unified vulnerability view
// All security header issues are marked as "low" severity
func mergeSecHeadersAsVulnerabilities(data *Data) {
	if data.SecHeaders == nil || len(data.SecHeaders.HeaderFindings) == 0 {
		return
	}

	// Initialize VulnScan if nil
	if data.VulnScan == nil {
		data.VulnScan = &vulnscan.Result{
			Vulnerabilities: []vulnscan.Vulnerability{},
			BySeverity:      make(map[string]int),
			ByType:          make(map[string]int),
		}
	}

	for _, finding := range data.SecHeaders.HeaderFindings {
		// Skip hosts with no missing headers
		if len(finding.Missing) == 0 {
			continue
		}

		// Build description of missing headers
		var missingHeaders []string
		for _, issue := range finding.Missing {
			missingHeaders = append(missingHeaders, issue.Header)
		}

		vuln := vulnscan.Vulnerability{
			Host:        finding.Host,
			URL:         finding.URL,
			TemplateID:  "security-headers-missing",
			Name:        fmt.Sprintf("Missing Security Headers (%d)", len(finding.Missing)),
			Severity:    "low",
			Type:        "misconfiguration",
			Description: fmt.Sprintf("Missing headers: %s", strings.Join(missingHeaders, ", ")),
			Tool:        "httpx",
		}

		data.VulnScan.Vulnerabilities = append(data.VulnScan.Vulnerabilities, vuln)
		data.VulnScan.BySeverity["low"]++
		data.VulnScan.ByType["misconfiguration"]++
	}
}

// updateAISummaryWithVulnCounts updates the AI Summary's OneLiner and KeyFindings
// with accurate vulnerability counts from the full VulnScan results
// This ensures the AI Summary reflects the true state of all vulnerabilities found
func updateAISummaryWithVulnCounts(data *Data) {
	// Skip if no AI summary or no vulnscan results
	if data.AIGuided == nil || data.AIGuided.ExecutiveSummary == nil {
		return
	}
	if data.VulnScan == nil || len(data.VulnScan.Vulnerabilities) == 0 {
		return
	}

	// Count vulnerabilities by severity from VulnScan
	critCount := data.VulnScan.BySeverity["critical"]
	highCount := data.VulnScan.BySeverity["high"]
	medCount := data.VulnScan.BySeverity["medium"]
	lowCount := data.VulnScan.BySeverity["low"]

	// Update OneLiner with accurate counts
	target := data.Target
	if critCount > 0 || highCount > 0 {
		data.AIGuided.ExecutiveSummary.OneLiner = fmt.Sprintf("%s requires attention: %d critical, %d high, %d medium, %d low severity issues identified.",
			target, critCount, highCount, medCount, lowCount)
	} else if medCount > 0 || lowCount > 0 {
		data.AIGuided.ExecutiveSummary.OneLiner = fmt.Sprintf("%s has %d medium and %d low severity issues to review.",
			target, medCount, lowCount)
	}

	// Update KeyFindings with accurate counts
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

	// Add tech stack from original findings (preserve non-count items)
	for _, f := range data.AIGuided.ExecutiveSummary.KeyFindings {
		if strings.Contains(f, "Technology stack") || strings.Contains(f, "security headers") ||
			strings.Contains(f, "hosts directly accessible") || strings.Contains(f, "indicators detected") {
			findings = append(findings, f)
		}
	}

	if len(findings) > 0 {
		data.AIGuided.ExecutiveSummary.KeyFindings = findings
	}

	// Update risk assessment based on actual counts
	// Risk levels: CRITICAL (any critical vulns), HIGH (>3 high vulns), MEDIUM (any high vulns), LOW (only medium/low)
	if critCount > 0 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("CRITICAL - %d critical and %d high severity vulnerabilities require immediate attention", critCount, highCount)
	} else if highCount > 3 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("HIGH - %d high severity vulnerabilities detected, prioritize remediation", highCount)
	} else if highCount > 0 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("MEDIUM - %d high severity vulnerabilities detected", highCount)
	} else if medCount > 0 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("LOW - %d medium severity issues detected, review recommended", medCount)
	}
}

// Generate generates the HTML report
func Generate(data *Data, outputDir string) error {
	// Aggregate per-subdomain details
	data.SubdomainDetails = aggregateSubdomainDetails(data)

	// Load screenshots as base64 for embedding
	loadScreenshotImages(data, outputDir)

	// Load logo as base64 for branding
	// Try multiple possible logo locations
	logoPaths := []string{
		filepath.Join(outputDir, "../assets/logo-transparent.png"),
		filepath.Join(outputDir, "../../assets/logo-transparent.png"),
		"./assets/logo-transparent.png",
		"./web/public/logo.png",
	}
	for _, logoPath := range logoPaths {
		if logoData, err := os.ReadFile(logoPath); err == nil {
			b64Logo := base64.StdEncoding.EncodeToString(logoData)
			data.LogoBase64 = template.URL(fmt.Sprintf("data:image/png;base64,%s", b64Logo))
			break
		}
	}

	// Build tech summary
	data.TechSummary = buildTechSummary(data)

	// Merge security header findings into vulnerabilities for unified view
	mergeSecHeadersAsVulnerabilities(data)

	// Sort vulnerabilities by severity (critical -> high -> medium -> low -> info)
	sortVulnerabilitiesBySeverity(data)

	// Update AI Summary with accurate vulnerability counts from VulnScan
	updateAISummaryWithVulnCounts(data)

	const tpl = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconator - {{.Target}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a24;
            --bg-hover: #22222e;
            --border: #2a2a3a;
            --text-primary: #f4f4f5;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent: #6366f1;
            --accent-hover: #818cf8;
            --critical: #dc2626;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #8b5cf6;
            --success: #22c55e;
            --warning: #f59e0b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        /* Layout */
        .app {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            padding: 20px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 100;
        }

        .sidebar-header {
            padding: 0 20px 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--accent) 0%, #a855f7 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
        }

        .target-badge {
            margin-top: 12px;
            padding: 8px 12px;
            background: var(--bg-card);
            border-radius: 6px;
            font-size: 0.875rem;
            color: var(--text-secondary);
            word-break: break-all;
        }

        .nav-section {
            margin-bottom: 8px;
        }

        .nav-section-title {
            padding: 8px 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.05em;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 20px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.15s;
            cursor: pointer;
            border-left: 3px solid transparent;
        }

        .nav-item:hover, .nav-item.active {
            background: var(--bg-hover);
            color: var(--text-primary);
            border-left-color: var(--accent);
        }

        .nav-item .icon { font-size: 1.1rem; width: 24px; text-align: center; }
        .nav-item .badge {
            margin-left: auto;
            padding: 2px 8px;
            background: var(--bg-card);
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .nav-item .badge.critical { background: var(--critical); color: white; }
        .nav-item .badge.warning { background: var(--warning); color: black; }

        /* Main Content */
        .main {
            flex: 1;
            margin-left: 260px;
            padding: 24px 32px;
            max-width: calc(100% - 260px);
        }

        /* Sections */
        .section {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .section.active { display: block; }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .section-header {
            margin-bottom: 24px;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 4px;
        }

        .section-subtitle {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s;
        }

        .stat-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }

        .stat-card .label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .stat-card .value {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }

        .stat-card .subtext {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 8px;
        }

        .stat-card.critical .value { color: var(--critical); }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.success .value { color: var(--success); }
        .stat-card.accent .value { color: var(--accent); }

        /* Cards */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .card-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 600;
        }

        .card-title {
            font-size: 1rem;
            font-weight: 600;
        }

        .card-body { padding: 20px; }

        /* Tags/Badges */
        .tag {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 500;
            gap: 4px;
        }

        .tag.critical, .badge.critical { background: rgba(220, 38, 38, 0.2); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.3); }
        .tag.high, .badge.high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }
        .tag.medium, .badge.medium { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.3); }
        .tag.low, .badge.low { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }
        .tag.info, .badge.info { background: rgba(139, 92, 246, 0.2); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.3); }
        .tag.success, .badge.success { background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
        .badge.tool { background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }

        /* CVSS Badge */
        .cvss-badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            margin-right: 6px;
        }
        .cvss-badge.critical { background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color: white; }
        .cvss-badge.high { background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%); color: white; }
        .cvss-badge.medium { background: linear-gradient(135deg, #ca8a04 0%, #a16207 100%); color: white; }
        .cvss-badge.low { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: white; }

        .cvss-score {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        .cvss-score.critical { background: var(--critical); color: white; }
        .cvss-score.high { background: var(--warning); color: black; }
        .cvss-score.medium { background: #ca8a04; color: white; }
        .cvss-score.low { background: var(--info); color: white; }

        .cvss-vector {
            margin-left: 8px;
            font-size: 0.75rem;
            color: var(--text-muted);
            font-family: monospace;
        }

        /* Export Buttons */
        .export-btn {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 6px 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .export-btn:hover {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }
        .export-btn span { font-size: 1rem; }
        .tag.waf, .badge.waf { background: rgba(168, 85, 247, 0.2); color: #d8b4fe; border: 1px solid rgba(168, 85, 247, 0.3); }
        .tag.tech, .badge.tech { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.2); }
        .tag.takeover, .badge.takeover { background: rgba(220, 38, 38, 0.3); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.5); }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        /* Severity Breakdown */
        .severity-breakdown {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }

        .severity-item {
            flex: 1;
            min-width: 120px;
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 16px;
            transition: all 0.2s;
            border: 1px solid var(--border);
        }

        .severity-item:hover {
            transform: translateY(-2px);
            border-color: var(--accent);
        }

        .severity-item.critical .severity-count { color: var(--critical); }
        .severity-item.high .severity-count { color: var(--high); }
        .severity-item.medium .severity-count { color: var(--medium); }
        .severity-item.low .severity-count { color: var(--low); }
        .severity-item.info .severity-count { color: var(--info); }

        .severity-count {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 4px;
        }

        .severity-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .severity-bar {
            height: 4px;
            background: var(--bg-card);
            border-radius: 2px;
            overflow: hidden;
        }

        .severity-bar-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.5s ease;
        }

        .severity-bar-fill.critical { background: var(--critical); }
        .severity-bar-fill.high { background: var(--high); }
        .severity-bar-fill.medium { background: var(--medium); }
        .severity-bar-fill.low { background: var(--low); }
        .severity-bar-fill.info { background: var(--info); }

        /* Nessus-inspired Scan Phases UI */
        .scan-phases {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .scan-phase {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border-left: 3px solid transparent;
            transition: all 0.2s;
        }

        .scan-phase:hover {
            background: var(--bg-hover);
        }

        .scan-phase.completed {
            border-left-color: var(--success);
        }

        .scan-phase.skipped {
            border-left-color: var(--text-muted);
            opacity: 0.7;
        }

        .scan-phase.warning {
            border-left-color: var(--warning);
        }

        .scan-phase.critical {
            border-left-color: var(--critical);
        }

        .phase-icon {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            flex-shrink: 0;
        }

        .phase-icon.completed {
            background: rgba(34, 197, 94, 0.2);
            color: var(--success);
        }

        .phase-icon.skipped {
            background: rgba(113, 113, 122, 0.2);
            color: var(--text-muted);
        }

        .phase-icon.warning {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }

        .phase-icon.critical {
            background: rgba(220, 38, 38, 0.2);
            color: var(--critical);
        }

        .phase-info {
            flex: 1;
            min-width: 0;
        }

        .phase-name {
            font-weight: 500;
            font-size: 0.875rem;
            color: var(--text-primary);
            margin-bottom: 2px;
        }

        .phase-details {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .phase-stats {
            display: flex;
            gap: 12px;
            flex-shrink: 0;
        }

        .phase-stat {
            text-align: right;
        }

        .phase-stat-value {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1;
        }

        .phase-stat-label {
            font-size: 0.65rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .phase-stat-value.critical { color: var(--critical); }
        .phase-stat-value.warning { color: var(--warning); }
        .phase-stat-value.success { color: var(--success); }

        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th {
            text-align: left;
            padding: 12px 16px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
        }

        .data-table td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 0.875rem;
        }

        .data-table tr:hover td {
            background: var(--bg-hover);
        }

        .data-table a {
            color: var(--accent);
            text-decoration: none;
        }

        .data-table a:hover { text-decoration: underline; }

        .table-host-link {
            color: #93c5fd !important;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
        }

        .table-host-link:hover {
            color: #bfdbfe !important;
        }

        /* Search & Filters */
        .controls {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }

        .search-input {
            flex: 1;
            min-width: 200px;
            max-width: 300px;
            padding: 10px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent);
        }

        .filter-group {
            display: flex;
            gap: 4px;
            background: var(--bg-secondary);
            padding: 4px;
            border-radius: 8px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 6px 12px;
            background: transparent;
            border: none;
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
            white-space: nowrap;
        }

        .filter-btn:hover { color: var(--text-primary); }
        .filter-btn.active {
            background: var(--accent);
            color: white;
        }

        .count-display {
            padding: 8px 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        /* Dropdown Filter */
        .filter-dropdown {
            position: relative;
        }

        .filter-dropdown select {
            padding: 8px 32px 8px 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 0.8rem;
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23a1a1aa' d='M3 4.5L6 7.5L9 4.5'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 10px center;
        }

        .filter-dropdown select:focus {
            outline: none;
            border-color: var(--accent);
        }

        /* Asset List View */
        .asset-list {
            display: flex;
            flex-direction: column;
            gap: 1px;
            background: var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        .asset-row {
            display: flex;
            align-items: stretch;
            background: var(--bg-card);
            transition: background 0.15s;
            min-height: 100px;
        }

        .asset-row:hover {
            background: var(--bg-hover);
        }

        .asset-row.has-vuln { /* removed left border */ }
        .asset-row.has-takeover { background: linear-gradient(90deg, rgba(220, 38, 38, 0.08) 0%, var(--bg-card) 30%); }
        .asset-row.alive { /* no special styling */ }
        .asset-row.dead { /* no graying out - all assets equally visible */ }

        .asset-content {
            flex: 1;
            padding: 16px 20px;
            min-width: 0;
        }

        .asset-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-muted);
            flex-shrink: 0;
        }
        .status-dot.alive { background: var(--success); }
        .status-dot.dead { background: var(--text-muted); }
        .status-dot.vuln { background: var(--critical); }
        .status-dot.takeover { background: var(--critical); animation: pulse 2s infinite; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .asset-name {
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--text-primary);
            text-decoration: none;
        }

        .asset-name:hover { color: var(--accent); }

        .asset-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-left: auto;
        }

        .asset-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .meta-label {
            color: var(--text-muted);
        }

        .tech-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }

        .tech-tag {
            padding: 3px 8px;
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 4px;
            font-size: 0.7rem;
            color: #a5b4fc;
        }

        .port-badge {
            padding: 2px 6px;
            background: var(--bg-secondary);
            border-radius: 4px;
            font-size: 0.7rem;
            font-family: monospace;
            color: var(--text-secondary);
        }

        /* Inline Ports Section - Always visible */
        .ports-section {
            margin-top: 10px;
            padding: 10px 12px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .port-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 6px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .port-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }
        .port-item:first-child {
            padding-top: 0;
        }
        .port-url {
            font-family: monospace;
            font-size: 0.8rem;
            color: var(--accent);
            text-decoration: none;
            transition: color 0.2s;
        }
        .port-url:hover {
            color: var(--text-primary);
            text-decoration: underline;
        }
        .port-url.https {
            color: #22c55e;
        }
        .port-url.http {
            color: #f59e0b;
        }
        .port-badges {
            display: flex;
            gap: 6px;
            align-items: center;
            flex-wrap: wrap;
        }
        .port-server {
            font-size: 0.7rem;
            padding: 2px 6px;
            background: rgba(139, 92, 246, 0.2);
            color: #a78bfa;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: 500;
        }
        .port-title {
            color: var(--text-secondary);
            font-size: 0.75rem;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        /* Legacy support - remove toggle */
        .ports-toggle {
            display: none;
        }
        .ports-list {
            display: none;
            border-radius: 4px;
            font-size: 0.7rem;
            text-decoration: none;
        }
        .port-link a:hover {
            opacity: 0.9;
        }

        /* OSINT Section Styles */
        .osint-tabs {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .osint-tab {
            padding: 10px 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-card);
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }

        .osint-tab:hover {
            background: var(--bg-hover);
            border-color: var(--primary);
        }

        .osint-tab.active {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        .osint-stat-card {
            background: var(--bg-secondary);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }

        .osint-stat-label {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }

        .osint-stat-value {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .osint-stat-detail {
            margin-top: 8px;
            font-size: 0.7rem;
            color: #cbd5e1;
            word-break: break-word;
            overflow-wrap: break-word;
            font-family: 'Monaco', 'Consolas', monospace;
            background: rgba(15, 23, 42, 0.8);
            padding: 10px 12px;
            border-radius: 6px;
            border: 1px solid rgba(71, 85, 105, 0.4);
            max-height: 120px;
            overflow-y: auto;
            line-height: 1.5;
            white-space: pre-wrap;
        }

        .osint-status-ok { color: var(--success); }
        .osint-status-warn { color: var(--warning); }
        .osint-status-bad { color: var(--danger); }
        .osint-status-na { color: var(--text-muted); }

        /* Screenshot Thumbnail on Right */
        .asset-screenshot {
            width: 180px;
            flex-shrink: 0;
            background: var(--bg-secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            border-left: 1px solid var(--border);
            overflow: hidden;
        }

        .asset-screenshot a {
            display: block;
            width: 100%;
            height: 100%;
        }

        .asset-screenshot img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: top left;
            cursor: pointer;
            transition: opacity 0.2s;
        }

        .asset-screenshot img:hover { opacity: 0.8; }

        .asset-screenshot .no-screenshot {
            font-size: 0.7rem;
            color: var(--text-muted);
            text-align: center;
            padding: 10px;
        }

        /* Screenshot Gallery */
        .gallery-controls {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .view-toggle {
            display: flex;
            gap: 4px;
            background: var(--bg-secondary);
            padding: 4px;
            border-radius: 8px;
        }

        .view-btn {
            padding: 8px 14px;
            background: transparent;
            border: none;
            border-radius: 6px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.15s;
        }

        .view-btn:hover { color: var(--text-primary); }
        .view-btn.active {
            background: var(--accent);
            color: white;
        }

        .screenshot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 16px;
        }

        .screenshot-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.2s;
        }

        .screenshot-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }

        .screenshot-img {
            width: 100%;
            height: 180px;
            object-fit: cover;
            object-position: top;
            cursor: pointer;
            background: var(--bg-secondary);
        }

        .screenshot-info {
            padding: 12px 16px;
        }

        .screenshot-host {
            font-weight: 600;
            font-size: 0.9rem;
            margin-bottom: 4px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .screenshot-url {
            font-size: 0.75rem;
            color: var(--text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .screenshot-url a {
            color: var(--text-muted);
            text-decoration: none;
        }

        .screenshot-url a:hover { color: var(--accent); }

        /* Lightbox Modal */
        .lightbox {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            z-index: 10000;
            cursor: pointer;
        }

        .lightbox.active { display: flex; align-items: center; justify-content: center; }

        .lightbox-content {
            position: relative;
            max-width: 90%;
            max-height: 90%;
        }

        .lightbox-img {
            max-width: 100%;
            max-height: 85vh;
            border-radius: 8px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
        }

        .lightbox-info {
            position: absolute;
            bottom: -40px;
            left: 0;
            right: 0;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .lightbox-close {
            position: absolute;
            top: 20px;
            right: 30px;
            font-size: 40px;
            color: white;
            cursor: pointer;
            z-index: 10001;
            opacity: 0.7;
            transition: opacity 0.2s;
        }

        .lightbox-close:hover { opacity: 1; }

        .lightbox-nav {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            font-size: 50px;
            color: white;
            cursor: pointer;
            padding: 20px;
            opacity: 0.5;
            transition: opacity 0.2s;
            user-select: none;
        }

        .lightbox-nav:hover { opacity: 1; }
        .lightbox-prev { left: 20px; }
        .lightbox-next { right: 20px; }

        .lightbox-counter {
            position: absolute;
            top: 20px;
            left: 30px;
            color: white;
            font-size: 1rem;
            opacity: 0.7;
        }

        .screenshot-img {
            cursor: zoom-in;
        }

        .screenshot-card .zoom-icon {
            position: absolute;
            top: 8px;
            right: 8px;
            background: rgba(0, 0, 0, 0.6);
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            opacity: 0;
            transition: opacity 0.2s;
        }

        .screenshot-card:hover .zoom-icon { opacity: 1; }

        .screenshot-card { position: relative; }

        /* Cluster View */
        .cluster-section {
            margin-bottom: 32px;
        }

        .cluster-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }

        .cluster-name {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .cluster-count {
            padding: 4px 10px;
            background: var(--bg-secondary);
            border-radius: 12px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        /* Vulnerability Cards - Expandable */
        .vuln-item {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 10px;
            overflow: hidden;
            transition: box-shadow 0.2s;
            border-left: 4px solid var(--border);
        }

        .vuln-item:hover { box-shadow: 0 2px 12px rgba(0,0,0,0.15); transform: translateX(2px); }
        .vuln-item.critical { border-left-color: var(--critical); background: linear-gradient(90deg, rgba(220, 38, 38, 0.06) 0%, var(--bg-card) 15%); }
        .vuln-item.high { border-left-color: var(--high); background: linear-gradient(90deg, rgba(234, 88, 12, 0.06) 0%, var(--bg-card) 15%); }
        .vuln-item.medium { border-left-color: var(--medium); background: linear-gradient(90deg, rgba(202, 138, 4, 0.06) 0%, var(--bg-card) 15%); }
        .vuln-item.low { border-left-color: var(--info); background: linear-gradient(90deg, rgba(59, 130, 246, 0.04) 0%, var(--bg-card) 15%); }
        .vuln-item.info { border-left-color: var(--text-muted); }

        /* Vulnerability Summary Stats */
        .vuln-stats {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .vuln-stat {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            border-left: 3px solid var(--border);
        }

        .vuln-stat.critical { border-left-color: var(--critical); }
        .vuln-stat.high { border-left-color: var(--high); }
        .vuln-stat.medium { border-left-color: var(--medium); }
        .vuln-stat.low { border-left-color: var(--info); }
        .vuln-stat.info { border-left-color: var(--text-muted); }

        .vuln-stat-count {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .vuln-stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            cursor: pointer;
            user-select: none;
        }

        .vuln-header:hover { background: var(--bg-hover); }

        .vuln-title-row {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }

        .vuln-expand-icon {
            font-size: 0.7rem;
            color: var(--text-muted);
            transition: transform 0.2s;
            width: 12px;
        }

        .vuln-item.expanded .vuln-expand-icon { transform: rotate(90deg); }

        .vuln-name {
            font-weight: 600;
            font-size: 0.95rem;
        }

        .vuln-badges {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .vuln-summary {
            padding: 0 18px 12px 18px;
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: center;
        }

        .vuln-summary span {
            max-width: 500px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .vuln-summary .vuln-target-link {
            color: var(--accent);
            text-decoration: none;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.75rem;
            max-width: 450px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: inline-block;
        }

        .vuln-summary .vuln-target-link:hover {
            text-decoration: underline;
        }

        .vuln-summary a { color: var(--accent); text-decoration: none; }
        .vuln-summary a:hover { text-decoration: underline; }

        .vuln-type-badge {
            background: var(--bg-secondary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .vuln-details {
            display: none;
            padding: 0 18px 18px 18px;
            border-top: 1px solid var(--border);
            margin-top: 8px;
        }

        .vuln-item.expanded .vuln-details { display: block; }

        .vuln-detail-section {
            margin-bottom: 16px;
        }

        .vuln-detail-section:last-child { margin-bottom: 0; }

        .vuln-detail-label {
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }

        .vuln-detail-value {
            font-size: 0.85rem;
            color: var(--text-primary);
            line-height: 1.5;
        }

        .vuln-detail-value a {
            color: #93c5fd;
            text-decoration: none;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
        }

        .vuln-detail-value a:hover {
            color: #bfdbfe;
            text-decoration: underline;
        }

        .vuln-detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            padding-top: 12px;
        }

        .vuln-meta {
            display: flex;
            gap: 16px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .vuln-meta a { color: var(--accent); text-decoration: none; }
        .vuln-meta a:hover { text-decoration: underline; }

        /* Tech Chart */
        .tech-chart {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .tech-item { margin-bottom: 4px; }

        .tech-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 6px 8px;
            border-radius: 6px;
            transition: background 0.15s;
        }

        .tech-row:hover { background: var(--bg-hover); }
        .tech-row.expanded { background: var(--bg-hover); }

        .expand-icon {
            font-size: 0.7rem;
            color: var(--text-muted);
            transition: transform 0.2s;
            width: 12px;
        }

        .tech-row.expanded .expand-icon { transform: rotate(90deg); }

        .tech-assets {
            margin: 8px 0 16px 24px;
            padding: 12px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border-left: 2px solid var(--accent);
        }

        .tech-asset-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            background: var(--bg-card);
            border-radius: 6px;
            margin-bottom: 6px;
            font-size: 0.85rem;
        }

        .tech-asset-item:last-child { margin-bottom: 0; }
        .tech-asset-item a { color: var(--text-primary); text-decoration: none; }
        .tech-asset-item a:hover { color: var(--accent); }
        .tech-asset-item .status-dot { width: 6px; height: 6px; }

        .tech-name {
            width: 140px;
            font-size: 0.85rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: var(--text-secondary);
        }

        .tech-bar-bg {
            flex: 1;
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
        }

        .tech-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent) 0%, #a855f7 100%);
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .tech-count {
            width: 40px;
            text-align: right;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* Attack Chain Cards */
        .chain-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
        }

        .chain-card.critical { border-left: 4px solid var(--critical); }
        .chain-card.high { border-left: 4px solid var(--high); }

        .chain-title { font-size: 1.1rem; font-weight: 600; }

        .chain-desc {
            color: var(--text-secondary);
            margin-bottom: 16px;
            font-size: 0.9rem;
        }

        .chain-section { margin-bottom: 16px; }

        .chain-section-title {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .chain-vulns {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .chain-vuln-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            background: var(--bg-secondary);
            border-radius: 6px;
            font-size: 0.85rem;
        }

        .chain-steps {
            list-style: none;
            counter-reset: steps;
        }

        .chain-steps li {
            counter-increment: steps;
            padding: 8px 0 8px 36px;
            position: relative;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .chain-steps li::before {
            content: counter(steps);
            position: absolute;
            left: 0;
            width: 24px;
            height: 24px;
            background: var(--accent);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }

        .mitigation-list {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .mitigation-item {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            font-size: 0.85rem;
            color: var(--success);
        }

        .mitigation-item::before {
            content: "✓";
            font-weight: bold;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }

        .empty-state .icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        /* Footer */
        .footer {
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
        }

        /* Responsive */
        @media (max-width: 1024px) {
            .sidebar { width: 60px; padding: 10px 0; }
            .sidebar-header { padding: 0 10px 10px; }
            .logo span, .target-badge, .nav-section-title, .nav-item span:not(.icon), .nav-item .badge { display: none; }
            .nav-item { justify-content: center; padding: 12px 0; }
            .nav-item .icon { width: auto; font-size: 1.3rem; }
            .main { margin-left: 60px; max-width: calc(100% - 60px); padding: 16px; }
            .asset-screenshot { width: 120px; }
            .screenshot-grid { grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); }
        }

        @media (max-width: 768px) {
            .asset-screenshot { display: none; }
            .controls { flex-direction: column; align-items: stretch; }
            .filter-group { justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="app">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    {{if .LogoBase64}}
                    <img src="{{.LogoBase64}}" alt="Reconator" style="height: 36px; width: auto; object-fit: contain;">
                    {{end}}
                    <span>Reconator</span>
                </div>
                <div class="target-badge">{{.Target}}</div>
            </div>

            <nav>
                <div class="nav-section">
                    <div class="nav-section-title">Overview</div>
                    <a class="nav-item active" onclick="showSection('dashboard')">
                        <span class="icon">📊</span>
                        <span>Dashboard</span>
                    </a>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Assets</div>
                    <a class="nav-item" onclick="showSection('assets')">
                        <span class="icon">🌐</span>
                        <span>Subdomains</span>
                        <span class="badge">{{if .SubdomainDetails}}{{len .SubdomainDetails}}{{else}}0{{end}}</span>
                    </a>
                    <a class="nav-item" onclick="showSection('screenshots')">
                        <span class="icon">📸</span>
                        <span>Screenshots</span>
                        <span class="badge">{{if .ScreenshotImages}}{{len .ScreenshotImages}}{{else}}0{{end}}</span>
                    </a>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Security</div>
                    <a class="nav-item" onclick="showSection('vulnerabilities')">
                        <span class="icon">🔓</span>
                        <span>Vulnerabilities</span>
                        <span class="badge{{if .VulnScan}}{{if .VulnScan.Vulnerabilities}} critical{{end}}{{end}}">{{if .VulnScan}}{{len .VulnScan.Vulnerabilities}}{{else}}0{{end}}</span>
                    </a>
                    <a class="nav-item" onclick="showSection('takeovers')">
                        <span class="icon">⚠️</span>
                        <span>Takeovers</span>
                        <span class="badge{{if .Takeover}}{{if .Takeover.Vulnerable}} critical{{end}}{{end}}">{{if .Takeover}}{{len .Takeover.Vulnerable}}{{else}}0{{end}}</span>
                    </a>
                    {{if .SecHeaders}}
                    <a class="nav-item" onclick="showSection('osint')">
                        <span class="icon">🔍</span>
                        <span>OSINT</span>
                        <span class="badge{{if .SecHeaders.HeaderFindings}} info{{end}}">{{len .SecHeaders.HeaderFindings}}</span>
                    </a>
                    {{end}}
                    {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
                    <a class="nav-item" onclick="showSection('chains')">
                        <span class="icon">🔗</span>
                        <span>Attack Chains</span>
                        <span class="badge">{{len .AIGuided.ChainAnalysis.Chains}}</span>
                    </a>
                    {{end}}{{end}}{{end}}
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Intelligence</div>
                    <a class="nav-item" onclick="showSection('technologies')">
                        <span class="icon">🔧</span>
                        <span>Technologies</span>
                        <span class="badge">{{if .Tech}}{{len .Tech.TechCount}}{{else}}0{{end}}</span>
                    </a>
                    {{if .JSAnalysis}}
                    <a class="nav-item" onclick="showSection('jsanalysis')">
                        <span class="icon">📜</span>
                        <span>JS Analysis</span>
                        <span class="badge{{if .JSAnalysis.TaintFlows}} warning{{end}}">{{len .JSAnalysis.TaintFlows}}</span>
                    </a>
                    {{end}}
                </div>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="main">
            <!-- Dashboard -->
            <section class="section active" id="dashboard">
                <div class="section-header">
                    <h1 class="section-title">Attack Surface Overview</h1>
                    <p class="section-subtitle">Scan completed on {{.Date}} · Duration: {{.Duration}}</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-card accent" onclick="navigateToSection('assets')" style="cursor: pointer;">
                        <div class="label">🌐 Subdomains</div>
                        <div class="value">{{if .Subdomain}}{{.Subdomain.Total}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .Ports}}{{.Ports.AliveCount}} alive{{else}}DNS validated{{end}}</div>
                    </div>
                    <div class="stat-card success" onclick="navigateToSectionWithFilter('assets', 'alive')" style="cursor: pointer;">
                        <div class="label">✓ Live Hosts</div>
                        <div class="value">{{if .Ports}}{{.Ports.AliveCount}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .Ports}}{{if gt .Ports.AliveCount 0}}{{.Ports.TotalPorts}} open ports{{end}}{{end}}</div>
                    </div>
                    <div class="stat-card critical" onclick="navigateToSection('vulnerabilities')" style="cursor: pointer;">
                        <div class="label">🔓 Vulnerabilities</div>
                        <div class="value">{{if .VulnScan}}{{len .VulnScan.Vulnerabilities}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .VulnScan}}{{add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")}} critical/high{{end}}</div>
                    </div>
                    <div class="stat-card warning" onclick="navigateToSectionWithFilter('assets', 'takeover')" style="cursor: pointer;">
                        <div class="label">⚠️ Takeovers</div>
                        <div class="value">{{if .Takeover}}{{len .Takeover.Vulnerable}}{{else}}0{{end}}</div>
                        <div class="subtext">subdomain takeover risks</div>
                    </div>
                    <div class="stat-card" onclick="navigateToSection('technologies')" style="cursor: pointer;">
                        <div class="label">🔧 Technologies</div>
                        <div class="value">{{if .Tech}}{{len .Tech.TechCount}}{{else}}0{{end}}</div>
                        <div class="subtext">{{if .Tech}}{{.Tech.Total}} detections{{end}}</div>
                    </div>
                    {{if .WAF}}
                    <div class="stat-card" onclick="navigateToSectionWithFilter('assets', 'waf')" style="cursor: pointer;">
                        <div class="label">🛡️ WAF/CDN</div>
                        <div class="value">{{len .WAF.CDNHosts}}</div>
                        <div class="subtext">{{len .WAF.DirectHosts}} direct access</div>
                    </div>
                    {{end}}
                </div>

                {{if .AIGuided}}{{if .AIGuided.ExecutiveSummary}}
                <div class="card" style="margin-bottom: 20px; border: 1px solid var(--accent);">
                    <div class="card-header" style="background: linear-gradient(90deg, rgba(99, 102, 241, 0.1) 0%, transparent 100%);">
                        <span class="card-title">AI Security Summary</span>
                        {{if .AIGuided.AIProvider}}<span class="badge info">{{.AIGuided.AIProvider}}</span>{{end}}
                    </div>
                    <div class="card-body">
                        <div style="margin-bottom: 16px;">
                            <p style="font-size: 1rem; color: var(--text-primary); line-height: 1.6; margin: 0;">{{.AIGuided.ExecutiveSummary.OneLiner}}</p>
                        </div>
                        {{if .AIGuided.ExecutiveSummary.KeyFindings}}
                        <div style="margin-bottom: 16px;">
                            <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px;">Key Findings</div>
                            <ul style="margin: 0; padding-left: 20px; color: var(--text-secondary); font-size: 0.875rem; line-height: 1.7;">
                                {{range .AIGuided.ExecutiveSummary.KeyFindings}}<li>{{.}}</li>{{end}}
                            </ul>
                        </div>
                        {{end}}
                        {{if .AIGuided.ExecutiveSummary.ImmediateActions}}
                        <div style="margin-bottom: 16px;">
                            <div style="font-size: 0.85rem; font-weight: 600; color: var(--critical); margin-bottom: 8px;">Immediate Actions Required</div>
                            <ul style="margin: 0; padding-left: 20px; font-size: 0.875rem; line-height: 1.7;">
                                {{range .AIGuided.ExecutiveSummary.ImmediateActions}}<li style="color: var(--critical);">{{.}}</li>{{end}}
                            </ul>
                        </div>
                        {{end}}
                        {{if .AIGuided.ExecutiveSummary.RiskAssessment}}
                        <div style="padding: 12px 16px; background: var(--bg-secondary); border-radius: 8px;">
                            <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Risk Assessment</div>
                            <p style="margin: 0; color: var(--text-primary); font-size: 0.875rem;">{{.AIGuided.ExecutiveSummary.RiskAssessment}}</p>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}{{end}}

                {{if .VulnScan}}{{if .VulnScan.Vulnerabilities}}
                <div class="card" style="margin-bottom: 20px;">
                    <div class="card-header">
                        <span class="card-title">Vulnerability Severity Breakdown</span>
                        <span class="badge" style="background: var(--bg-secondary);">{{len .VulnScan.Vulnerabilities}} Total</span>
                    </div>
                    <div class="card-body">
                        <div class="severity-breakdown">
                            <div class="severity-item critical" onclick="navigateToSectionWithVulnFilter('critical')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "critical"}}</div>
                                <div class="severity-label">Critical</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill critical" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "critical") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item high" onclick="navigateToSectionWithVulnFilter('high')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "high"}}</div>
                                <div class="severity-label">High</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill high" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "high") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item medium" onclick="navigateToSectionWithVulnFilter('medium')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "medium"}}</div>
                                <div class="severity-label">Medium</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill medium" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "medium") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item low" onclick="navigateToSectionWithVulnFilter('low')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "low"}}</div>
                                <div class="severity-label">Low</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill low" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "low") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                            <div class="severity-item info" onclick="navigateToSectionWithVulnFilter('info')" style="cursor: pointer;">
                                <div class="severity-count">{{index .VulnScan.BySeverity "info"}}</div>
                                <div class="severity-label">Info</div>
                                <div class="severity-bar">
                                    <div class="severity-bar-fill info" style="width: {{if gt (len .VulnScan.Vulnerabilities) 0}}{{percent (index .VulnScan.BySeverity "info") (len .VulnScan.Vulnerabilities)}}{{else}}0{{end}}%"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {{end}}{{end}}

                <!-- Nessus-inspired Scan Phases Summary -->
                <div class="card" style="margin-bottom: 20px;">
                    <div class="card-header">
                        <span class="card-title">Scan Phases Summary</span>
                        <span class="badge" style="background: var(--bg-secondary);">{{.Duration}}</span>
                    </div>
                    <div class="card-body">
                        <div class="scan-phases">
                            <!-- Phase 1: Subdomain Enumeration -->
                            {{if .Subdomain}}
                            <div class="scan-phase completed" onclick="navigateToSection('assets')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Subdomain Enumeration</div>
                                    <div class="phase-details">DNS records, certificate transparency, web archives</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">{{.Subdomain.Total}}</div>
                                        <div class="phase-stat-label">Valid (DNSx)</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{if .Ports}}{{.Ports.AliveCount}}{{else}}0{{end}}</div>
                                        <div class="phase-stat-label">Alive (Httpx)</div>
                                    </div>
                                </div>
                            </div>
                            {{else}}
                            <div class="scan-phase skipped">
                                <div class="phase-icon skipped">—</div>
                                <div class="phase-info">
                                    <div class="phase-name">Subdomain Enumeration</div>
                                    <div class="phase-details">Skipped</div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 2: WAF Detection -->
                            {{if .WAF}}
                            <div class="scan-phase completed">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">WAF/CDN Detection</div>
                                    <div class="phase-details">Identified CDN-protected and direct-access hosts</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .WAF.CDNHosts}}</div>
                                        <div class="phase-stat-label">CDN</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">{{len .WAF.DirectHosts}}</div>
                                        <div class="phase-stat-label">Direct</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 3: Port Scanning -->
                            {{if .Ports}}
                            <div class="scan-phase completed" onclick="navigateToSection('assets')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Port Scanning & TLS Analysis</div>
                                    <div class="phase-details">Open ports, service detection, SSL/TLS inspection</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Ports.TotalPorts}}</div>
                                        <div class="phase-stat-label">Ports</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">{{.Ports.AliveCount}}</div>
                                        <div class="phase-stat-label">Live</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 4: Takeover Check -->
                            {{if .Takeover}}
                            <div class="scan-phase {{if .Takeover.Vulnerable}}critical{{else}}completed{{end}}">
                                <div class="phase-icon {{if .Takeover.Vulnerable}}critical{{else}}completed{{end}}">{{if .Takeover.Vulnerable}}!{{else}}✓{{end}}</div>
                                <div class="phase-info">
                                    <div class="phase-name">Subdomain Takeover Analysis</div>
                                    <div class="phase-details">Dangling DNS records, orphaned cloud resources</div>
                                </div>
                                <div class="phase-stats">
                                    {{if .Takeover.Vulnerable}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value critical">{{len .Takeover.Vulnerable}}</div>
                                        <div class="phase-stat-label">Vulnerable</div>
                                    </div>
                                    {{else}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value success">0</div>
                                        <div class="phase-stat-label">Issues</div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 5: Technology Detection -->
                            {{if .Tech}}
                            <div class="scan-phase completed" onclick="navigateToSection('technologies')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Technology Detection</div>
                                    <div class="phase-details">Frameworks, CMS, servers, libraries</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .Tech.TechCount}}</div>
                                        <div class="phase-stat-label">Technologies</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Tech.Total}}</div>
                                        <div class="phase-stat-label">Detections</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 6: Vulnerability Scanning -->
                            {{if .VulnScan}}
                            <div class="scan-phase {{if gt (add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")) 0}}critical{{else if gt (len .VulnScan.Vulnerabilities) 0}}warning{{else}}completed{{end}}" onclick="navigateToSection('vulnerabilities')" style="cursor: pointer;">
                                <div class="phase-icon {{if gt (add (index .VulnScan.BySeverity "critical") (index .VulnScan.BySeverity "high")) 0}}critical{{else if gt (len .VulnScan.Vulnerabilities) 0}}warning{{else}}completed{{end}}">{{if gt (len .VulnScan.Vulnerabilities) 0}}!{{else}}✓{{end}}</div>
                                <div class="phase-info">
                                    <div class="phase-name">Vulnerability Scanning</div>
                                    <div class="phase-details">Nuclei templates, CVE checks, misconfigurations</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value {{if gt (index .VulnScan.BySeverity "critical") 0}}critical{{end}}">{{index .VulnScan.BySeverity "critical"}}</div>
                                        <div class="phase-stat-label">Critical</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value {{if gt (index .VulnScan.BySeverity "high") 0}}warning{{end}}">{{index .VulnScan.BySeverity "high"}}</div>
                                        <div class="phase-stat-label">High</div>
                                    </div>
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .VulnScan.Vulnerabilities}}</div>
                                        <div class="phase-stat-label">Total</div>
                                    </div>
                                </div>
                            </div>
                            {{end}}

                            <!-- Phase 7: Screenshots -->
                            {{if .Screenshot}}{{if not .Screenshot.Skipped}}
                            <div class="scan-phase completed" onclick="navigateToSection('screenshots')" style="cursor: pointer;">
                                <div class="phase-icon completed">✓</div>
                                <div class="phase-info">
                                    <div class="phase-name">Visual Reconnaissance</div>
                                    <div class="phase-details">Screenshot capture and clustering</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{.Screenshot.TotalCaptures}}</div>
                                        <div class="phase-stat-label">Captures</div>
                                    </div>
                                    {{if .Screenshot.Clusters}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .Screenshot.Clusters}}</div>
                                        <div class="phase-stat-label">Clusters</div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                            {{end}}{{end}}

                            <!-- Phase 8: AI-Guided Scanning -->
                            {{if .AIGuided}}
                            <div class="scan-phase {{if gt (len .AIGuided.Vulnerabilities) 0}}warning{{else}}completed{{end}}">
                                <div class="phase-icon {{if gt (len .AIGuided.Vulnerabilities) 0}}warning{{else}}completed{{end}}">{{if gt (len .AIGuided.Vulnerabilities) 0}}!{{else}}✓{{end}}</div>
                                <div class="phase-info">
                                    <div class="phase-name">AI-Guided Analysis</div>
                                    <div class="phase-details">{{.AIGuided.AIProvider}} · Smart vulnerability correlation</div>
                                </div>
                                <div class="phase-stats">
                                    <div class="phase-stat">
                                        <div class="phase-stat-value">{{len .AIGuided.Vulnerabilities}}</div>
                                        <div class="phase-stat-label">Findings</div>
                                    </div>
                                    {{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
                                    <div class="phase-stat">
                                        <div class="phase-stat-value warning">{{len .AIGuided.ChainAnalysis.Chains}}</div>
                                        <div class="phase-stat-label">Chains</div>
                                    </div>
                                    {{end}}{{end}}
                                </div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>

                {{if .TechSummary}}
                <div class="card">
                    <div class="card-header">Technology Distribution</div>
                    <div class="card-body">
                        <div class="tech-chart">
                            {{$maxCount := 1}}
                            {{range .TechSummary}}{{if gt .Count $maxCount}}{{$maxCount = .Count}}{{end}}{{end}}
                            {{range .TechSummary}}
                            <div class="tech-row" onclick="filterByTech('{{.Name}}')" style="cursor: pointer;">
                                <span class="tech-name" title="{{.Name}}">{{.Name}}</span>
                                <div class="tech-bar-bg">
                                    <div class="tech-bar-fill" style="width: {{percent .Count $maxCount}}%"></div>
                                </div>
                                <span class="tech-count">{{.Count}}</span>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{end}}

                {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
                <div class="card">
                    <div class="card-header">Critical Attack Chains</div>
                    <div class="card-body">
                        {{range $i, $chain := .AIGuided.ChainAnalysis.Chains}}
                        {{if lt $i 3}}
                        <div class="chain-card {{$chain.Severity}}" style="margin-bottom: 16px;">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                                <span class="chain-title">{{$chain.Name}}</span>
                                <span class="badge {{$chain.Severity}}">{{$chain.Severity}}</span>
                            </div>
                            <p class="chain-desc">{{$chain.Description}}</p>
                            <div class="chain-section" style="margin-bottom: 0;">
                                <div class="chain-section-title">Impact</div>
                                <p style="font-size: 13px; color: var(--text-secondary);">{{$chain.Impact}}</p>
                            </div>
                        </div>
                        {{end}}
                        {{end}}
                    </div>
                </div>
                {{end}}{{end}}{{end}}
            </section>

            <!-- Assets Section - List View -->
            <section class="section" id="assets">
                <div class="section-header">
                    <h1 class="section-title">Subdomains</h1>
                    <p class="section-subtitle">{{if .SubdomainDetails}}{{len .SubdomainDetails}}{{else}}0{{end}} discovered assets</p>
                </div>

                {{if .SubdomainDetails}}
                <div class="controls">
                    <input type="text" class="search-input" placeholder="Search subdomains..." id="assetSearch" onkeyup="filterAssets()">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setAssetFilter('all', this)">All</button>
                        <button class="filter-btn" onclick="setAssetFilter('alive', this)">Live</button>
                        <button class="filter-btn" onclick="setAssetFilter('vulns', this)">Vulnerable</button>
                        <button class="filter-btn" onclick="setAssetFilter('takeover', this)">Takeover</button>
                        <button class="filter-btn" onclick="setAssetFilter('waf', this)">WAF</button>
                    </div>
                    <div class="filter-dropdown">
                        <select id="techFilter" onchange="filterAssets()">
                            <option value="">All Technologies</option>
                            {{range .TechSummary}}<option value="{{.Name}}">{{.Name}} ({{.Count}})</option>{{end}}
                        </select>
                    </div>
                    <div class="filter-dropdown">
                        <select id="portFilter" onchange="filterAssets()">
                            <option value="">All Ports</option>
                            <option value="80">Port 80</option>
                            <option value="443">Port 443</option>
                            <option value="8080">Port 8080</option>
                            <option value="8443">Port 8443</option>
                            <option value="3000">Port 3000</option>
                            <option value="5000">Port 5000</option>
                        </select>
                    </div>
                    <span class="count-display" id="assetCount">{{len .SubdomainDetails}} results</span>
                    <div class="export-group" style="display: flex; gap: 8px; margin-left: auto;">
                        <button class="export-btn" onclick="exportAssetsCSV()" title="Export as CSV">
                            <span>📄</span> CSV
                        </button>
                        <button class="export-btn" onclick="exportAssetsJSON()" title="Export as JSON">
                            <span>📋</span> JSON
                        </button>
                    </div>
                </div>

                <div class="asset-list" id="assetList">
                    {{range $idx, $sub := .SubdomainDetails}}
                    <div class="asset-row {{if $sub.TakeoverRisk}}has-takeover{{else if $sub.Vulns}}has-vuln{{else if $sub.IsAlive}}alive{{else}}dead{{end}}"
                         data-name="{{$sub.Name}}"
                         data-alive="{{$sub.IsAlive}}"
                         data-vulns="{{len $sub.Vulns}}"
                         data-takeover="{{$sub.TakeoverRisk}}"
                         data-waf="{{$sub.WAFProtected}}"
                         data-ports="{{range $i, $p := $sub.Ports}}{{if $i}},{{end}}{{$p}}{{end}}"
                         data-techs="{{range $i, $t := $sub.Technologies}}{{if $i}},{{end}}{{$t}}{{end}}"
                         data-ip="{{$sub.IPAddress}}"
                         data-asn="{{$sub.ASN}}">
                        <div class="asset-content">
                            <div class="asset-header">
                                <span class="status-dot {{if $sub.TakeoverRisk}}takeover{{else if $sub.Vulns}}vuln{{else if $sub.IsAlive}}alive{{else}}dead{{end}}"></span>
                                <a class="asset-name" href="https://{{$sub.Name}}" target="_blank">{{$sub.Name}}</a>
                                <div class="asset-badges">
                                    {{if $sub.TakeoverRisk}}<span class="badge takeover">Takeover</span>{{end}}
                                    {{if $sub.Vulns}}<span class="badge critical">{{len $sub.Vulns}} Vulns</span>{{end}}
                                    {{if $sub.WAFProtected}}<span class="badge waf">{{$sub.WAFName}}</span>{{end}}
                                </div>
                            </div>
                            <div class="asset-meta">
                                {{if $sub.StatusCode}}<span class="meta-item"><span class="badge {{if eq $sub.StatusCode 200}}success{{else if lt $sub.StatusCode 400}}info{{else if lt $sub.StatusCode 500}}medium{{else}}critical{{end}}">{{$sub.StatusCode}}</span></span>{{end}}
                                {{if $sub.ASN}}<span class="meta-item"><span class="badge info">{{$sub.ASN}}</span></span>{{end}}
                                {{if $sub.IPAddress}}<span class="meta-item"><span class="badge tech">{{$sub.IPAddress}}</span></span>{{end}}
                            </div>
                            <div class="asset-meta" style="margin-top: 6px;">
                                {{if $sub.SSLIssuer}}<span class="meta-item">{{if $sub.SSLExpired}}<span class="badge critical">SSL Expired</span>{{else if and $sub.SSLDaysLeft (lt $sub.SSLDaysLeft 30)}}<span class="badge medium">SSL {{$sub.SSLDaysLeft}}d</span>{{else if $sub.SSLDaysLeft}}<span class="badge success">SSL {{$sub.SSLDaysLeft}}d</span>{{end}} <span class="badge tech">{{$sub.SSLIssuer}}</span></span>{{end}}
                                {{if $sub.TakeoverRisk}}<span class="meta-item"><span class="badge takeover">{{$sub.TakeoverSvc}}</span></span>{{end}}
                            </div>
                            {{if $sub.Services}}
                            <div class="ports-section">
                                {{range $sub.Services}}
                                <div class="port-item">
                                    <a class="port-url {{if .TLS}}https{{else}}http{{end}}" href="{{if .TLS}}https{{else}}http{{end}}://{{$sub.Name}}:{{.Port}}" target="_blank">{{if .TLS}}https{{else}}http{{end}}://{{$sub.Name}}:{{.Port}}</a>
                                    <div class="port-badges">
                                        {{if .StatusCode}}<span class="badge {{if eq .StatusCode 200}}success{{else if lt .StatusCode 400}}info{{else if lt .StatusCode 500}}medium{{else}}critical{{end}}">{{.StatusCode}}</span>{{end}}
                                        {{if .WebServer}}<span class="port-server">{{.WebServer}}</span>{{end}}
                                        {{if .Title}}<span class="port-title" title="{{.Title}}">{{.Title}}</span>{{end}}
                                    </div>
                                </div>
                                {{end}}
                            </div>
                            {{end}}
                            {{if $sub.Technologies}}
                            <div class="tech-tags">
                                {{range $sub.Technologies}}<span class="tech-tag">{{.}}</span>{{end}}
                            </div>
                            {{end}}
                            {{if $sub.Vulns}}
                            <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border);">
                                {{range $sub.Vulns}}
                                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 0.75rem;">
                                    <span class="badge {{.Severity}}">{{.Severity}}</span>
                                    <span style="color: var(--text-secondary);">{{.Name}}</span>
                                </div>
                                {{end}}
                            </div>
                            {{end}}
                        </div>
                        <div class="asset-screenshot" data-host="{{$sub.Name}}">
                            <span class="no-screenshot">No screenshot</span>
                        </div>
                    </div>
                    {{end}}
                </div>
                {{else}}
                <div class="empty-state">
                    <div class="icon">🔍</div>
                    <p>No subdomains discovered</p>
                </div>
                {{end}}
            </section>

            <!-- Screenshots Section -->
            <section class="section" id="screenshots">
                <div class="section-header">
                    <h1 class="section-title">Screenshots</h1>
                    <p class="section-subtitle">{{if .ScreenshotImages}}{{len .ScreenshotImages}} captured web applications{{else}}No screenshots captured{{end}}</p>
                </div>

                {{if .ScreenshotImages}}
                <div class="controls">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setGalleryView('grid', this)">Grid</button>
                        <button class="filter-btn" onclick="setGalleryView('cluster', this)">Clusters</button>
                    </div>
                    <input type="text" class="search-input" placeholder="Search hosts..." id="screenshotSearch" onkeyup="filterScreenshots()">
                </div>

                <div id="gridView">
                    <div class="screenshot-grid" id="screenshotGrid">
                        {{range $index, $img := .ScreenshotImages}}
                        <div class="screenshot-card" data-host="{{$img.Host}}" data-url="{{$img.URL}}" data-index="{{$index}}">
                            <span class="zoom-icon">🔍 Click to enlarge</span>
                            <img class="screenshot-img" src="{{$img.DataURI}}" alt="{{$img.Host}}" loading="lazy" onclick="openLightbox({{$index}})">
                            <div class="screenshot-info">
                                <div class="screenshot-host">{{$img.Host}}</div>
                                <div class="screenshot-url"><a href="{{$img.URL}}" target="_blank" onclick="event.stopPropagation()">{{$img.URL}}</a></div>
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>

                <div id="clusterView" style="display: none;">
                    {{range .ScreenshotClusters}}
                    <div class="cluster-section">
                        <div class="cluster-header">
                            <span class="cluster-name">{{.Name}}</span>
                            <span class="cluster-count">{{.Count}} screenshots</span>
                        </div>
                        <div class="screenshot-grid">
                            {{range .Screenshots}}
                            <div class="screenshot-card" data-host="{{.Host}}" data-url="{{.URL}}">
                                <span class="zoom-icon">🔍 Click to enlarge</span>
                                <img class="screenshot-img" src="{{.DataURI}}" alt="{{.Host}}" loading="lazy" onclick="openLightboxByUrl('{{.DataURI}}', '{{.Host}}', '{{.URL}}')">
                                <div class="screenshot-info">
                                    <div class="screenshot-host">{{.Host}}</div>
                                    <div class="screenshot-url"><a href="{{.URL}}" target="_blank" onclick="event.stopPropagation()">{{.URL}}</a></div>
                                </div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
                {{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">📸</span>
                        <p style="margin-top: 16px;">No screenshots have been captured yet.</p>
                        <p style="font-size: 0.875rem;">Screenshots are captured during the port scanning phase when live hosts are discovered.</p>
                    </div>
                </div>
                {{end}}
            </section>

            <!-- Vulnerabilities Section -->
            <section class="section" id="vulnerabilities">
                <div class="section-header">
                    <h1 class="section-title">Vulnerabilities</h1>
                    <p class="section-subtitle">{{if .VulnScan}}{{len .VulnScan.Vulnerabilities}} security issues identified{{else}}No vulnerabilities scanned{{end}}</p>
                </div>

                {{if .VulnScan}}{{if .VulnScan.Vulnerabilities}}
                <!-- Severity Summary Stats -->
                <div class="vuln-stats">
                    {{if index .VulnScan.BySeverity "critical"}}<div class="vuln-stat critical"><span class="vuln-stat-count">{{index .VulnScan.BySeverity "critical"}}</span><span class="vuln-stat-label">Critical</span></div>{{end}}
                    {{if index .VulnScan.BySeverity "high"}}<div class="vuln-stat high"><span class="vuln-stat-count">{{index .VulnScan.BySeverity "high"}}</span><span class="vuln-stat-label">High</span></div>{{end}}
                    {{if index .VulnScan.BySeverity "medium"}}<div class="vuln-stat medium"><span class="vuln-stat-count">{{index .VulnScan.BySeverity "medium"}}</span><span class="vuln-stat-label">Medium</span></div>{{end}}
                    {{if index .VulnScan.BySeverity "low"}}<div class="vuln-stat low"><span class="vuln-stat-count">{{index .VulnScan.BySeverity "low"}}</span><span class="vuln-stat-label">Low</span></div>{{end}}
                    {{if index .VulnScan.BySeverity "info"}}<div class="vuln-stat info"><span class="vuln-stat-count">{{index .VulnScan.BySeverity "info"}}</span><span class="vuln-stat-label">Info</span></div>{{end}}
                </div>

                <div class="controls">
                    <input type="text" class="search-input" placeholder="Search vulnerabilities..." id="vulnSearch" onkeyup="filterVulns()">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setVulnFilter('all', this)">All</button>
                        <button class="filter-btn" onclick="setVulnFilter('critical', this)">Critical</button>
                        <button class="filter-btn" onclick="setVulnFilter('high', this)">High</button>
                        <button class="filter-btn" onclick="setVulnFilter('medium', this)">Medium</button>
                        <button class="filter-btn" onclick="setVulnFilter('low', this)">Low</button>
                        <button class="filter-btn" onclick="setVulnFilter('info', this)">Info</button>
                    </div>
                    <div class="export-group" style="display: flex; gap: 8px; margin-left: auto;">
                        <button class="export-btn" onclick="exportVulnsCSV()" title="Export as CSV">
                            <span>📄</span> CSV
                        </button>
                        <button class="export-btn" onclick="exportVulnsJSON()" title="Export as JSON">
                            <span>📋</span> JSON
                        </button>
                    </div>
                </div>

                <div class="vuln-list" id="vulnList">
                    {{range .VulnScan.Vulnerabilities}}
                    <div class="vuln-item {{.Severity}}" data-severity="{{.Severity}}" data-name="{{.Name}}" data-host="{{if .URL}}{{.URL}}{{else}}{{.Host}}{{end}}" data-cvss="{{.CVSS}}" data-cwe="{{.CWE}}" data-type="{{.Type}}" data-tool="{{.Tool}}" onclick="toggleVuln(this)">
                        <div class="vuln-header">
                            <div class="vuln-title-row">
                                <span class="vuln-expand-icon">▶</span>
                                <span class="vuln-name">{{.Name}}</span>
                            </div>
                            <div class="vuln-badges">
                                {{if gt .CVSS 0.0}}<span class="cvss-badge {{if ge .CVSS 9.0}}critical{{else if ge .CVSS 7.0}}high{{else if ge .CVSS 4.0}}medium{{else}}low{{end}}">CVSS {{printf "%.1f" .CVSS}}</span>{{end}}
                                <span class="badge {{.Severity}}">{{.Severity}}</span>
                                {{if .CWE}}<span class="badge info" style="font-size: 0.7rem;">{{.CWE}}</span>{{end}}
                                {{if .Tool}}<span class="badge tool" style="font-size: 0.7rem;">{{.Tool}}</span>{{end}}
                            </div>
                        </div>
                        <div class="vuln-summary">
                            {{if .URL}}<a href="{{.URL}}" target="_blank" class="vuln-target-link" onclick="event.stopPropagation()" title="{{.URL}}">{{.URL}}</a>
                            {{else if .Host}}<a href="https://{{.Host}}" target="_blank" class="vuln-target-link" onclick="event.stopPropagation()" title="{{.Host}}">{{.Host}}</a>{{end}}
                            <span class="vuln-type-badge">{{.Type}}</span>
                        </div>
                        <div class="vuln-details">
                            <div class="vuln-detail-grid">
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">Target</div>
                                    <div class="vuln-detail-value">
                                        {{if .URL}}<a href="{{.URL}}" target="_blank" onclick="event.stopPropagation()">{{.URL}}</a>
                                        {{else if .Host}}<a href="https://{{.Host}}" target="_blank" onclick="event.stopPropagation()">{{.Host}}</a>{{end}}
                                    </div>
                                </div>
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">Type</div>
                                    <div class="vuln-detail-value">{{.Type}}</div>
                                </div>
                                {{if gt .CVSS 0.0}}
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">CVSS Score</div>
                                    <div class="vuln-detail-value">
                                        <span class="cvss-score {{if ge .CVSS 9.0}}critical{{else if ge .CVSS 7.0}}high{{else if ge .CVSS 4.0}}medium{{else}}low{{end}}">{{printf "%.1f" .CVSS}}</span>
                                        {{if .CVSSVector}}<span class="cvss-vector">{{.CVSSVector}}</span>{{end}}
                                    </div>
                                </div>
                                {{end}}
                                {{if .CWE}}
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">CWE</div>
                                    <div class="vuln-detail-value"><a href="https://cwe.mitre.org/data/definitions/{{trimPrefix .CWE "CWE-"}}.html" target="_blank" onclick="event.stopPropagation()">{{.CWE}}</a></div>
                                </div>
                                {{end}}
                                {{if .TemplateID}}
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">Template ID</div>
                                    <div class="vuln-detail-value">{{.TemplateID}}</div>
                                </div>
                                {{end}}
                                {{if .Matcher}}
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">Matcher</div>
                                    <div class="vuln-detail-value">{{.Matcher}}</div>
                                </div>
                                {{end}}
                                {{if .Reference}}
                                <div class="vuln-detail-section">
                                    <div class="vuln-detail-label">Reference</div>
                                    <div class="vuln-detail-value"><a href="{{.Reference}}" target="_blank" onclick="event.stopPropagation()">{{.Reference}}</a></div>
                                </div>
                                {{end}}
                            </div>
                            {{if .Description}}
                            <div class="vuln-detail-section" style="margin-top: 16px;">
                                <div class="vuln-detail-label">Description</div>
                                <div class="vuln-detail-value">{{.Description}}</div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
                {{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">✅</span>
                        <p style="margin-top: 16px;">No vulnerabilities detected.</p>
                        <p style="font-size: 0.875rem;">Vulnerability scanning completed with no findings.</p>
                    </div>
                </div>
                {{end}}{{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">🔓</span>
                        <p style="margin-top: 16px;">Vulnerability scanning not yet performed.</p>
                        <p style="font-size: 0.875rem;">Run a full scan to detect security issues using Nuclei templates.</p>
                    </div>
                </div>
                {{end}}
            </section>

            <!-- Takeovers Section -->
            <section class="section" id="takeovers">
                <div class="section-header">
                    <h1 class="section-title">Subdomain Takeovers</h1>
                    <p class="section-subtitle">{{if .Takeover}}{{len .Takeover.Vulnerable}} vulnerable subdomains{{else}}No takeover scan performed{{end}}</p>
                </div>

                {{if .Takeover}}{{if .Takeover.Vulnerable}}
                <div class="card">
                    <div class="card-body" style="padding: 0;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Subdomain</th>
                                    <th>Service</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .Takeover.Vulnerable}}
                                <tr>
                                    <td><a href="https://{{.Subdomain}}" target="_blank">{{.Subdomain}}</a></td>
                                    <td>{{.Service}}</td>
                                    <td><span class="badge critical">Critical</span></td>
                                    <td><span class="badge takeover">Vulnerable</span></td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
                {{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">✅</span>
                        <p style="margin-top: 16px;">No subdomain takeover vulnerabilities found.</p>
                        <p style="font-size: 0.875rem;">All subdomains appear to be properly configured.</p>
                    </div>
                </div>
                {{end}}{{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">⚠️</span>
                        <p style="margin-top: 16px;">Takeover scanning not yet performed.</p>
                        <p style="font-size: 0.875rem;">Run a full scan to check for subdomain takeover vulnerabilities.</p>
                    </div>
                </div>
                {{end}}
            </section>

            <!-- OSINT Section -->
            {{if .SecHeaders}}
            <section class="section" id="osint">
                <div class="section-header">
                    <h1 class="section-title">OSINT & Security Analysis</h1>
                    <p class="section-subtitle">Email security, DNS security, and HTTP security header findings</p>
                </div>

                <!-- OSINT Category Tabs -->
                <div class="osint-tabs" style="display: flex; gap: 8px; margin-bottom: 24px; flex-wrap: wrap;">
                    <button class="osint-tab active" onclick="showOsintTab('email')">📧 Email Security</button>
                    <button class="osint-tab" onclick="showOsintTab('dns')">🌐 DNS Security</button>
                    <button class="osint-tab" onclick="showOsintTab('http')">🛡️ HTTP Headers</button>
                </div>

                <!-- Email Security Tab -->
                <div class="osint-content" id="osint-email">
                {{if .SecHeaders.EmailSecurity}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">
                        <span class="card-title">📧 Email Security (SPF/DKIM/DMARC)</span>
                        <span class="badge info" style="margin-left: auto;">DNS Records</span>
                    </div>
                    <div class="card-body">
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">SPF Record</div>
                                <div class="osint-stat-value">
                                    {{if .SecHeaders.EmailSecurity.SPF}}{{if .SecHeaders.EmailSecurity.SPF.Found}}<span class="osint-status-ok">✓ Present</span>{{else}}<span class="osint-status-bad">✗ Missing</span>{{end}}{{else}}<span class="osint-status-na">Not checked</span>{{end}}
                                </div>
                                {{if .SecHeaders.EmailSecurity.SPF}}{{if .SecHeaders.EmailSecurity.SPF.Record}}<div class="osint-stat-detail">{{.SecHeaders.EmailSecurity.SPF.Record}}</div>{{end}}{{end}}
                            </div>
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">DKIM Record</div>
                                <div class="osint-stat-value">
                                    {{if .SecHeaders.EmailSecurity.DKIM}}{{if .SecHeaders.EmailSecurity.DKIM.Found}}<span class="osint-status-ok">✓ Present</span>{{else}}<span class="osint-status-warn">⚠ Not Found</span>{{end}}{{else}}<span class="osint-status-na">Not checked</span>{{end}}
                                </div>
                                {{if .SecHeaders.EmailSecurity.DKIM}}
                                <div class="osint-stat-detail">{{if .SecHeaders.EmailSecurity.DKIM.Found}}DKIM configured (selectors: {{range $i, $s := .SecHeaders.EmailSecurity.DKIM.Selectors}}{{if $i}}, {{end}}{{$s}}{{end}}){{else}}Checked selectors: google, default, selector1, selector2{{end}}</div>
                                {{end}}
                            </div>
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">DMARC Record</div>
                                <div class="osint-stat-value">
                                    {{if .SecHeaders.EmailSecurity.DMARC}}{{if .SecHeaders.EmailSecurity.DMARC.Found}}<span class="osint-status-ok">✓ Present</span>{{else}}<span class="osint-status-bad">✗ Missing</span>{{end}}{{else}}<span class="osint-status-na">Not checked</span>{{end}}
                                </div>
                                {{if .SecHeaders.EmailSecurity.DMARC}}{{if .SecHeaders.EmailSecurity.DMARC.Record}}<div class="osint-stat-detail">{{.SecHeaders.EmailSecurity.DMARC.Record}}</div>{{end}}{{end}}
                            </div>
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">Security Score</div>
                                <div class="osint-stat-value osint-score">
                                    {{if ge .SecHeaders.EmailSecurity.Score 80}}<span class="osint-status-ok">{{.SecHeaders.EmailSecurity.Score}}/100</span>
                                    {{else if ge .SecHeaders.EmailSecurity.Score 50}}<span class="osint-status-warn">{{.SecHeaders.EmailSecurity.Score}}/100</span>
                                    {{else}}<span class="osint-status-bad">{{.SecHeaders.EmailSecurity.Score}}/100</span>{{end}}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {{else}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-body" style="text-align: center; padding: 48px; color: var(--text-muted);">
                        <div style="font-size: 2rem; margin-bottom: 12px;">📧</div>
                        <div>Email security checks not performed for this scan</div>
                    </div>
                </div>
                {{end}}
                </div>

                <!-- DNS Security Tab -->
                <div class="osint-content" id="osint-dns" style="display: none;">
                {{if .SecHeaders.DNSSecurity}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">
                        <span class="card-title">🌐 DNS Security Analysis</span>
                        <span class="badge {{if ge .SecHeaders.DNSSecurity.Score 80}}success{{else if ge .SecHeaders.DNSSecurity.Score 50}}warning{{else}}danger{{end}}" style="margin-left: auto;">Score: {{.SecHeaders.DNSSecurity.Score}}/100</span>
                    </div>
                    <div class="card-body">
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
                            <!-- CAA Records -->
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">CAA Records</div>
                                <div class="osint-stat-value">
                                    {{if .SecHeaders.DNSSecurity.CAA.HasRecords}}
                                    <span class="osint-status-ok">✓ Configured</span>
                                    {{else}}
                                    <span class="osint-status-missing">✗ Not Found</span>
                                    {{end}}
                                </div>
                                <div class="osint-stat-detail">
                                    {{if .SecHeaders.DNSSecurity.CAA.HasRecords}}
                                    {{range .SecHeaders.DNSSecurity.CAA.Records}}
                                    <div style="font-size: 0.75rem; color: var(--text-muted);">{{.Tag}}: {{.Value}}</div>
                                    {{end}}
                                    {{if .SecHeaders.DNSSecurity.CAA.HasReporting}}<span class="badge success" style="font-size: 0.65rem;">Has Reporting</span>{{end}}
                                    {{else}}
                                    Any CA can issue certificates for this domain
                                    {{end}}
                                </div>
                            </div>
                            <!-- DNSSEC -->
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">DNSSEC</div>
                                <div class="osint-stat-value">
                                    {{if .SecHeaders.DNSSecurity.DNSSEC.Enabled}}
                                        {{if .SecHeaders.DNSSecurity.DNSSEC.Validated}}
                                        <span class="osint-status-ok">✓ Enabled & Validated</span>
                                        {{else}}
                                        <span class="osint-status-warning">⚠ Enabled (Incomplete)</span>
                                        {{end}}
                                    {{else}}
                                    <span class="osint-status-missing">✗ Not Enabled</span>
                                    {{end}}
                                </div>
                                <div class="osint-stat-detail">
                                    {{if .SecHeaders.DNSSecurity.DNSSEC.Enabled}}
                                    Cryptographic DNS response validation
                                    {{else}}
                                    DNS responses can be spoofed
                                    {{end}}
                                </div>
                            </div>
                            <!-- Zone Transfer (AXFR) -->
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">Zone Transfer (AXFR)</div>
                                <div class="osint-stat-value">
                                    {{if .SecHeaders.DNSSecurity.ZoneTransfer.Vulnerable}}
                                    <span class="osint-status-fail">⚠ VULNERABLE</span>
                                    {{else}}
                                    <span class="osint-status-ok">✓ Protected</span>
                                    {{end}}
                                </div>
                                <div class="osint-stat-detail">
                                    {{if .SecHeaders.DNSSecurity.ZoneTransfer.Vulnerable}}
                                    <span style="color: var(--danger);">{{len .SecHeaders.DNSSecurity.ZoneTransfer.VulnerableNS}} NS allows transfer ({{.SecHeaders.DNSSecurity.ZoneTransfer.RecordsExposed}} records exposed)</span>
                                    {{else}}
                                    Zone transfer properly restricted
                                    {{end}}
                                </div>
                            </div>
                            <!-- Nameservers -->
                            <div class="osint-stat-card">
                                <div class="osint-stat-label">Nameservers</div>
                                <div class="osint-stat-value">
                                    {{if ge .SecHeaders.DNSSecurity.Nameservers.Count 2}}
                                    <span class="osint-status-ok">{{.SecHeaders.DNSSecurity.Nameservers.Count}} NS</span>
                                    {{else}}
                                    <span class="osint-status-warning">{{.SecHeaders.DNSSecurity.Nameservers.Count}} NS (SPOF)</span>
                                    {{end}}
                                </div>
                                <div class="osint-stat-detail">
                                    {{range .SecHeaders.DNSSecurity.Nameservers.Servers}}
                                    <div style="font-size: 0.7rem; color: var(--text-muted);">{{.}}</div>
                                    {{end}}
                                    {{if .SecHeaders.DNSSecurity.Nameservers.Diverse}}
                                    <span class="badge success" style="font-size: 0.65rem;">Diverse Providers</span>
                                    {{end}}
                                    {{if .SecHeaders.DNSSecurity.Nameservers.DanglingNS}}
                                    <span class="badge critical" style="font-size: 0.65rem;">⚠ Dangling NS Detected</span>
                                    {{end}}
                                </div>
                            </div>
                        </div>

                        <!-- DNS Issues Summary -->
                        {{$dnsIssues := 0}}
                        {{if .SecHeaders.DNSSecurity.CAA.Issues}}{{$dnsIssues = len .SecHeaders.DNSSecurity.CAA.Issues}}{{end}}
                        {{if gt $dnsIssues 0}}
                        <div style="margin-top: 16px; padding: 12px; background: rgba(251, 191, 36, 0.1); border-radius: 8px; border-left: 3px solid var(--warning);">
                            <strong>DNS Security Issues:</strong>
                            <ul style="margin: 8px 0 0 16px; padding: 0;">
                            {{range .SecHeaders.DNSSecurity.CAA.Issues}}
                            <li style="font-size: 0.85rem; color: var(--text-secondary);">{{.}}</li>
                            {{end}}
                            {{range .SecHeaders.DNSSecurity.DNSSEC.Issues}}
                            <li style="font-size: 0.85rem; color: var(--text-secondary);">{{.}}</li>
                            {{end}}
                            {{range .SecHeaders.DNSSecurity.Nameservers.Issues}}
                            <li style="font-size: 0.85rem; color: var(--text-secondary);">{{.}}</li>
                            {{end}}
                            </ul>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{else}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">
                        <span class="card-title">🌐 DNS Security Analysis</span>
                        <span class="badge info" style="margin-left: auto;">DNS Records</span>
                    </div>
                    <div class="card-body">
                        <div style="padding: 24px; text-align: center; color: var(--text-muted);">
                            DNS security checks not performed for this scan
                        </div>
                    </div>
                </div>
                {{end}}
                </div>

                <!-- HTTP Headers Tab -->
                <div class="osint-content" id="osint-http" style="display: none;">

                {{if .SecHeaders.HeaderFindings}}
                <div class="controls">
                    <input type="text" class="search-input" placeholder="Search by host or header..." id="secheaderSearch" onkeyup="filterSecHeaders()">
                </div>

                <div class="card">
                    <div class="card-body" style="padding: 0; max-height: 600px; overflow-y: auto;">
                        <table class="data-table" id="secheaderTable">
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>Missing Headers</th>
                                    <th>Weak Configs</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .SecHeaders.HeaderFindings}}
                                <tr data-host="{{.Host}}" data-missing="{{range .Missing}}{{.Header}} {{end}}">
                                    <td><a href="{{.URL}}" target="_blank" class="table-host-link">{{.Host}}</a></td>
                                    <td>
                                        {{range .Missing}}
                                        <span class="badge warning" style="margin: 2px; font-size: 0.7rem;">{{.Header}}</span>
                                        {{end}}
                                        {{if not .Missing}}<span style="color: var(--text-muted);">None</span>{{end}}
                                    </td>
                                    <td>
                                        {{range .Weak}}
                                        <span class="badge medium" style="margin: 2px; font-size: 0.7rem;" title="{{.Value}}">{{.Header}}</span>
                                        {{end}}
                                        {{if not .Weak}}<span style="color: var(--text-muted);">None</span>{{end}}
                                    </td>
                                    <td>
                                        {{$total := len .Missing}}{{$weak := len .Weak}}
                                        {{if or (gt $total 0) (gt $weak 0)}}<span class="badge low">Low</span>
                                        {{else}}<span class="badge success">OK</span>{{end}}
                                    </td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Common Missing Headers Summary -->
                <div class="card" style="margin-top: 24px;">
                    <div class="card-header">
                        <span class="card-title">Recommendations</span>
                    </div>
                    <div class="card-body">
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;">
                            <div style="padding: 12px; background: var(--bg-secondary); border-radius: 8px;">
                                <div style="font-weight: 600; margin-bottom: 8px;">X-Frame-Options</div>
                                <div style="font-size: 0.85rem; color: var(--text-muted);">Prevents clickjacking attacks. Add: <code>X-Frame-Options: DENY</code> or <code>SAMEORIGIN</code></div>
                            </div>
                            <div style="padding: 12px; background: var(--bg-secondary); border-radius: 8px;">
                                <div style="font-weight: 600; margin-bottom: 8px;">Content-Security-Policy</div>
                                <div style="font-size: 0.85rem; color: var(--text-muted);">Prevents XSS and injection attacks. Define trusted content sources.</div>
                            </div>
                            <div style="padding: 12px; background: var(--bg-secondary); border-radius: 8px;">
                                <div style="font-weight: 600; margin-bottom: 8px;">Strict-Transport-Security</div>
                                <div style="font-size: 0.85rem; color: var(--text-muted);">Forces HTTPS. Add: <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code></div>
                            </div>
                            <div style="padding: 12px; background: var(--bg-secondary); border-radius: 8px;">
                                <div style="font-weight: 600; margin-bottom: 8px;">X-Content-Type-Options</div>
                                <div style="font-size: 0.85rem; color: var(--text-muted);">Prevents MIME sniffing. Add: <code>X-Content-Type-Options: nosniff</code></div>
                            </div>
                        </div>
                    </div>
                </div>
                {{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">✅</span>
                        <p style="margin-top: 16px;">All HTTP security headers properly configured.</p>
                    </div>
                </div>
                {{end}}
                </div><!-- End osint-http -->
            </section>
            {{end}}

            <!-- Attack Chains Section -->
            {{if .AIGuided}}{{if .AIGuided.ChainAnalysis}}{{if .AIGuided.ChainAnalysis.Chains}}
            <section class="section" id="chains">
                <div class="section-header">
                    <h1 class="section-title">Attack Chains</h1>
                    <p class="section-subtitle">AI-identified vulnerability chains</p>
                </div>

                {{range .AIGuided.ChainAnalysis.Chains}}
                <div class="chain-card {{.Severity}}">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                        <span class="chain-title">{{.Name}}</span>
                        <span class="badge {{.Severity}}">{{.Severity}}</span>
                    </div>
                    <p class="chain-desc">{{.Description}}</p>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 20px;">
                        <div class="chain-section" style="margin-bottom: 0;">
                            <div class="chain-section-title">Impact</div>
                            <p style="font-size: 13px; color: var(--text-secondary);">{{.Impact}}</p>
                        </div>
                        <div class="chain-section" style="margin-bottom: 0;">
                            <div class="chain-section-title">Likelihood</div>
                            <p style="font-size: 13px; color: var(--text-secondary);">{{.Likelihood}}</p>
                        </div>
                    </div>

                    <div class="chain-section">
                        <div class="chain-section-title">Vulnerabilities in Chain</div>
                        <div class="chain-vulns">
                            {{range .Vulns}}
                            <div class="chain-vuln-item">
                                <span class="badge {{.Severity}}">{{.Severity}}</span>
                                <span>{{.Name}}</span>
                                <span style="color: var(--text-muted); margin-left: auto; font-size: 0.8rem;">{{.Host}}</span>
                            </div>
                            {{end}}
                        </div>
                    </div>

                    <div class="chain-section">
                        <div class="chain-section-title">Exploitation Steps</div>
                        <ol class="chain-steps">
                            {{range .Steps}}
                            <li>{{.}}</li>
                            {{end}}
                        </ol>
                    </div>

                    <div class="chain-section" style="margin-bottom: 0;">
                        <div class="chain-section-title">Mitigations</div>
                        <div class="mitigation-list">
                            {{range .Mitigations}}
                            <div class="mitigation-item">{{.}}</div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{end}}
            </section>
            {{end}}{{end}}{{end}}

            <!-- Technologies Section -->
            <section class="section" id="technologies">
                <div class="section-header">
                    <h1 class="section-title">Technologies</h1>
                    <p class="section-subtitle">{{if .Tech}}{{.Tech.Total}} detections across {{len .Tech.TechCount}} technologies{{else}}No technology detection performed{{end}}</p>
                </div>

                {{if .Tech}}
                <div class="card">
                    <div class="card-header">Technology Stack</div>
                    <div class="card-body">
                        <div class="tech-chart">
                            {{$maxCount := 1}}
                            {{range .TechSummary}}{{if gt .Count $maxCount}}{{$maxCount = .Count}}{{end}}{{end}}
                            {{range .TechSummary}}
                            <div class="tech-item">
                                <div class="tech-row" onclick="toggleTechAssets('{{.Name}}', this)" style="cursor: pointer;">
                                    <span class="expand-icon">▶</span>
                                    <span class="tech-name" title="{{.Name}}">{{.Name}}</span>
                                    <div class="tech-bar-bg">
                                        <div class="tech-bar-fill" style="width: {{percent .Count $maxCount}}%"></div>
                                    </div>
                                    <span class="tech-count">{{.Count}}</span>
                                </div>
                                <div class="tech-assets" style="display: none;"></div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
                {{else}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">🔧</span>
                        <p style="margin-top: 16px;">Technology detection not yet performed.</p>
                        <p style="font-size: 0.875rem;">Run a full scan to identify web technologies and frameworks.</p>
                    </div>
                </div>
                {{end}}
            </section>

            <!-- JavaScript Analysis Section -->
            {{if .JSAnalysis}}
            <section class="section" id="jsanalysis">
                <div class="section-header">
                    <h1 class="section-title">JavaScript Analysis</h1>
                    <p class="section-subtitle">{{.JSAnalysis.FilesScanned}} files analyzed · {{len .JSAnalysis.Endpoints}} endpoints · {{len .JSAnalysis.TaintFlows}} potential DOM XSS flows</p>
                </div>

                <!-- Taint Flows (Most Important) -->
                {{if .JSAnalysis.TaintFlows}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">Potential DOM XSS Vulnerabilities</div>
                    <div class="card-body" style="padding: 0;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Source</th>
                                    <th>Sink</th>
                                    <th>File</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .JSAnalysis.TaintFlows}}
                                <tr class="vuln-row" data-severity="{{.Severity}}">
                                    <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                                    <td><code>{{.SourceType}}</code> (line {{.SourceLine}})</td>
                                    <td><code>{{.SinkType}}</code> (line {{.SinkLine}})</td>
                                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{{.File}}"><a href="{{.File}}" target="_blank" style="color: var(--accent); text-decoration: none;">{{.File}}</a></td>
                                    <td>{{.Description}}</td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
                {{end}}

                <!-- DOM XSS Sources -->
                {{if .JSAnalysis.DOMXSSSources}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">User-Controllable Sources ({{len .JSAnalysis.DOMXSSSources}})</div>
                    <div class="card-body" style="padding: 0; max-height: 400px; overflow-y: auto;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Category</th>
                                    <th>Control</th>
                                    <th>File</th>
                                    <th>Line</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .JSAnalysis.DOMXSSSources}}
                                <tr>
                                    <td><code>{{.Type}}</code></td>
                                    <td><span class="tag">{{.Category}}</span></td>
                                    <td>{{if eq .Controllability "full"}}<span style="color: var(--critical);">Full</span>{{else}}<span style="color: var(--warning);">Partial</span>{{end}}</td>
                                    <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{{.Source}}"><a href="{{.Source}}" target="_blank" style="color: var(--accent); text-decoration: none;">{{.Source}}</a></td>
                                    <td>{{.Line}}</td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
                {{end}}

                <!-- DOM XSS Sinks -->
                {{if .JSAnalysis.DOMXSSSinks}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">Dangerous Sinks ({{len .JSAnalysis.DOMXSSSinks}})</div>
                    <div class="card-body" style="padding: 0; max-height: 400px; overflow-y: auto;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Sink Type</th>
                                    <th>Has Input</th>
                                    <th>File</th>
                                    <th>Line</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .JSAnalysis.DOMXSSSinks}}
                                <tr>
                                    <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                                    <td><code>{{.Type}}</code></td>
                                    <td>{{if .HasInput}}<span style="color: var(--critical);">Yes</span>{{else}}<span style="color: var(--text-muted);">No</span>{{end}}</td>
                                    <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{{.Source}}"><a href="{{.Source}}" target="_blank" style="color: var(--accent); text-decoration: none;">{{.Source}}</a></td>
                                    <td>{{.Line}}</td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
                {{end}}

                <!-- Extracted Endpoints -->
                {{if .JSAnalysis.Endpoints}}
                <div class="card" style="margin-bottom: 24px;">
                    <div class="card-header">Extracted Endpoints ({{len .JSAnalysis.Endpoints}})</div>
                    <div class="card-body" style="padding: 0; max-height: 400px; overflow-y: auto;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Path</th>
                                    <th>Sensitive</th>
                                    <th>Source File</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .JSAnalysis.Endpoints}}
                                <tr>
                                    <td><code>{{.Path}}</code></td>
                                    <td>{{if .Sensitive}}<span style="color: var(--warning);">Yes</span>{{else}}<span style="color: var(--text-muted);">No</span>{{end}}</td>
                                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{{.Source}}"><a href="{{.Source}}" target="_blank" style="color: var(--accent); text-decoration: none;">{{.Source}}</a></td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
                {{end}}

                <!-- Secrets -->
                {{if .JSAnalysis.Secrets}}
                <div class="card">
                    <div class="card-header">Potential Secrets ({{len .JSAnalysis.Secrets}})</div>
                    <div class="card-body" style="padding: 0;">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Value (Masked)</th>
                                    <th>Source File</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .JSAnalysis.Secrets}}
                                <tr>
                                    <td><span class="tag">{{.Type}}</span></td>
                                    <td><code>{{.Value}}</code></td>
                                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{{.Source}}"><a href="{{.Source}}" target="_blank" style="color: var(--accent); text-decoration: none;">{{.Source}}</a></td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </div>
                {{end}}

                {{if and (not .JSAnalysis.TaintFlows) (not .JSAnalysis.DOMXSSSinks) (not .JSAnalysis.Endpoints)}}
                <div class="card">
                    <div class="card-body" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <span style="font-size: 3rem;">📜</span>
                        <p style="margin-top: 16px;">No significant JavaScript findings.</p>
                        <p style="font-size: 0.875rem;">JavaScript analysis completed but no DOM XSS patterns or endpoints were detected.</p>
                    </div>
                </div>
                {{end}}
            </section>
            {{end}}

            <footer class="footer">
                Generated by Reconator v{{.Version}} · {{.Date}}
            </footer>
        </main>
    </div>

    <script>
        // Screenshot lookup for asset list
        const screenshotMap = new Map();
        {{range .ScreenshotImages}}
        screenshotMap.set('{{.Host}}', '{{.DataURI}}');
        {{end}}

        // Populate screenshots in asset list (open in new tab on click)
        document.querySelectorAll('.asset-screenshot').forEach(el => {
            const host = el.dataset.host;
            const img = screenshotMap.get(host);
            if (img) {
                el.innerHTML = '<a href="' + img + '" target="_blank"><img src="' + img + '" loading="lazy"></a>';
            }
        });

        // Navigation
        function showSection(id) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            event.currentTarget.classList.add('active');
        }

        // Navigate to section from dashboard stat-card
        function navigateToSection(id) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            const navItem = document.querySelector('.nav-item[onclick*="' + id + '"]');
            if (navItem) navItem.classList.add('active');
        }

        // Navigate to section and apply filter
        function navigateToSectionWithFilter(section, filter) {
            navigateToSection(section);

            if (section === 'assets') {
                assetFilter = filter;
                document.querySelectorAll('#assets .filter-group .filter-btn').forEach(b => b.classList.remove('active'));
                const filterBtn = document.querySelector('#assets .filter-btn[onclick*="' + filter + '"]');
                if (filterBtn) filterBtn.classList.add('active');
                filterAssets();
            }
        }

        // Navigate to vulnerabilities section with severity filter
        function navigateToSectionWithVulnFilter(severity) {
            navigateToSection('vulnerabilities');
            vulnFilter = severity;
            document.querySelectorAll('#vulnerabilities .filter-group .filter-btn').forEach(b => b.classList.remove('active'));
            const filterBtn = document.querySelector('#vulnerabilities .filter-btn[onclick*="' + severity + '"]');
            if (filterBtn) filterBtn.classList.add('active');
            filterVulns();
        }

        // Toggle expandable ports list
        function togglePorts(element, event) {
            event.stopPropagation();
            const targetId = element.dataset.target;
            const portsList = document.getElementById(targetId);
            if (portsList) {
                portsList.classList.toggle('show');
                element.classList.toggle('expanded');
            }
        }

        // Asset Filtering
        let assetFilter = 'all';

        function setAssetFilter(filter, btn) {
            assetFilter = filter;
            document.querySelectorAll('#assets .filter-group .filter-btn').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            filterAssets();
        }

        function filterAssets() {
            const search = document.getElementById('assetSearch').value.toLowerCase();
            const techFilter = document.getElementById('techFilter')?.value || '';
            const portFilter = document.getElementById('portFilter')?.value || '';
            const rows = document.querySelectorAll('.asset-row');
            let count = 0;

            rows.forEach(row => {
                const name = row.dataset.name.toLowerCase();
                const alive = row.dataset.alive === 'true';
                const hasVulns = parseInt(row.dataset.vulns) > 0;
                const hasTakeover = row.dataset.takeover === 'true';
                const hasWaf = row.dataset.waf === 'true';
                const ports = row.dataset.ports || '';
                const techs = row.dataset.techs || '';

                let show = name.includes(search);

                // Status filter
                if (show && assetFilter !== 'all') {
                    switch(assetFilter) {
                        case 'alive': show = alive; break;
                        case 'vulns': show = hasVulns; break;
                        case 'takeover': show = hasTakeover; break;
                        case 'waf': show = hasWaf; break;
                    }
                }

                // Technology filter
                if (show && techFilter) {
                    show = techs.toLowerCase().includes(techFilter.toLowerCase());
                }

                // Port filter
                if (show && portFilter) {
                    show = ports.split(',').includes(portFilter);
                }

                row.style.display = show ? 'flex' : 'none';
                if (show) count++;
            });

            document.getElementById('assetCount').textContent = count + ' results';
        }

        // Filter by technology (from dashboard click) - navigates to Technologies tab and expands
        function filterByTech(techName) {
            // Navigate to technologies section
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById('technologies').classList.add('active');
            const navItem = document.querySelector('.nav-item[onclick*="technologies"]');
            if (navItem) navItem.classList.add('active');

            // Find and expand the matching tech row
            setTimeout(() => {
                const techRows = document.querySelectorAll('#technologies .tech-row');
                techRows.forEach(row => {
                    const name = row.querySelector('.tech-name');
                    if (name && name.textContent.toLowerCase().includes(techName.toLowerCase())) {
                        // Collapse any already expanded
                        if (!row.classList.contains('expanded')) {
                            toggleTechAssets(techName, row);
                        }
                        // Scroll into view
                        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                });
            }, 100);
        }

        // Toggle tech assets in-place (for Technologies section) - with fingerprint data
        function toggleTechAssets(techName, barElement) {
            const techItem = barElement.closest('.tech-item');
            const assetsPanel = techItem.querySelector('.tech-assets');
            const isExpanded = barElement.classList.contains('expanded');

            if (isExpanded) {
                // Collapse
                barElement.classList.remove('expanded');
                assetsPanel.style.display = 'none';
                assetsPanel.innerHTML = '';
            } else {
                // Expand - find matching assets and display them with fingerprint data
                barElement.classList.add('expanded');

                // Get all assets with this technology
                const rows = document.querySelectorAll('.asset-row');
                let html = '';

                rows.forEach(row => {
                    const techs = (row.dataset.techs || '').toLowerCase();
                    if (techs.includes(techName.toLowerCase())) {
                        const name = row.dataset.name;
                        const alive = row.dataset.alive === 'true';
                        const ip = row.dataset.ip || '';
                        const asn = row.dataset.asn || '';

                        html += '<div class="tech-asset-item" style="flex-wrap: wrap;">' +
                            '<span class="status-dot ' + (alive ? 'alive' : 'dead') + '"></span>' +
                            '<a href="https://' + name + '" target="_blank" style="flex: 1; min-width: 150px;">' + name + '</a>' +
                            '<div style="display: flex; gap: 6px; flex-wrap: wrap;">';

                        if (ip) {
                            html += '<span class="badge tech" style="font-size: 0.65rem;">' + ip + '</span>';
                        }
                        if (asn) {
                            html += '<span class="badge info" style="font-size: 0.65rem;">' + asn + '</span>';
                        }

                        html += '</div></div>';
                    }
                });

                if (html) {
                    assetsPanel.innerHTML = html;
                } else {
                    assetsPanel.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No assets found</div>';
                }
                assetsPanel.style.display = 'block';
            }
        }

        // Vulnerability Filtering
        let vulnFilter = 'all';

        function setVulnFilter(filter, btn) {
            vulnFilter = filter;
            document.querySelectorAll('#vulnerabilities .filter-group .filter-btn').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            filterVulns();
        }

        function filterVulns() {
            const search = document.getElementById('vulnSearch')?.value.toLowerCase() || '';
            document.querySelectorAll('.vuln-item').forEach(item => {
                const name = item.dataset.name.toLowerCase();
                const host = item.dataset.host.toLowerCase();
                const severity = item.dataset.severity;

                let show = name.includes(search) || host.includes(search);
                if (show && vulnFilter !== 'all') show = severity === vulnFilter;

                item.style.display = show ? 'block' : 'none';
            });
        }

        function toggleVuln(el) {
            el.classList.toggle('expanded');
        }

        // Export Vulnerabilities as CSV
        function exportVulnsCSV() {
            const vulns = document.querySelectorAll('.vuln-item');
            if (vulns.length === 0) {
                alert('No vulnerabilities to export');
                return;
            }

            // CSV header
            let csv = 'Name,Severity,CVSS,CWE,Type,Host/URL,Tool,Description\n';

            vulns.forEach(item => {
                const name = (item.dataset.name || '').replace(/"/g, '""');
                const severity = item.dataset.severity || '';
                const cvss = item.dataset.cvss || '';
                const cwe = item.dataset.cwe || '';
                const type = item.dataset.type || '';
                const host = (item.dataset.host || '').replace(/"/g, '""');
                const tool = item.dataset.tool || '';
                const descEl = item.querySelector('.vuln-detail-value:last-child');
                const desc = descEl ? descEl.textContent.trim().replace(/"/g, '""').replace(/\n/g, ' ') : '';

                csv += '"' + name + '","' + severity + '","' + cvss + '","' + cwe + '","' + type + '","' + host + '","' + tool + '","' + desc + '"\n';
            });

            downloadFile(csv, 'vulnerabilities.csv', 'text/csv');
        }

        // Export Vulnerabilities as JSON
        function exportVulnsJSON() {
            const vulns = document.querySelectorAll('.vuln-item');
            if (vulns.length === 0) {
                alert('No vulnerabilities to export');
                return;
            }

            const data = [];
            vulns.forEach(item => {
                const vuln = {
                    name: item.dataset.name || '',
                    severity: item.dataset.severity || '',
                    cvss: parseFloat(item.dataset.cvss) || 0,
                    cwe: item.dataset.cwe || '',
                    type: item.dataset.type || '',
                    host: item.dataset.host || '',
                    tool: item.dataset.tool || '',
                };
                const descEl = item.querySelector('.vuln-detail-value:last-child');
                if (descEl) vuln.description = descEl.textContent.trim();
                data.push(vuln);
            });

            downloadFile(JSON.stringify(data, null, 2), 'vulnerabilities.json', 'application/json');
        }

        // Helper function to download files
        function downloadFile(content, filename, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        // Export Assets as CSV
        function exportAssetsCSV() {
            const assets = document.querySelectorAll('.asset-row');
            if (assets.length === 0) {
                alert('No assets to export');
                return;
            }

            // CSV header
            let csv = 'Subdomain,Alive,IP,Ports,Technologies,Vulnerabilities,WAF,Takeover Risk\n';

            assets.forEach(row => {
                const name = (row.dataset.name || '').replace(/"/g, '""');
                const alive = row.dataset.alive === 'true' ? 'Yes' : 'No';
                const ip = (row.dataset.ip || '').replace(/"/g, '""');
                const ports = (row.dataset.ports || '').replace(/"/g, '""');
                const techs = (row.dataset.techs || '').replace(/"/g, '""');
                const vulns = row.dataset.vulns || '0';
                const waf = row.dataset.waf === 'true' ? 'Yes' : 'No';
                const takeover = row.dataset.takeover === 'true' ? 'Yes' : 'No';

                csv += '"' + name + '","' + alive + '","' + ip + '","' + ports + '","' + techs + '","' + vulns + '","' + waf + '","' + takeover + '"\n';
            });

            downloadFile(csv, 'subdomains.csv', 'text/csv');
        }

        // Export Assets as JSON
        function exportAssetsJSON() {
            const assets = document.querySelectorAll('.asset-row');
            if (assets.length === 0) {
                alert('No assets to export');
                return;
            }

            const data = [];
            assets.forEach(row => {
                data.push({
                    subdomain: row.dataset.name || '',
                    alive: row.dataset.alive === 'true',
                    ip: row.dataset.ip || '',
                    ports: (row.dataset.ports || '').split(',').filter(p => p).map(p => parseInt(p)),
                    technologies: (row.dataset.techs || '').split(',').filter(t => t),
                    vulnerabilities: parseInt(row.dataset.vulns) || 0,
                    waf: row.dataset.waf === 'true',
                    takeover_risk: row.dataset.takeover === 'true',
                });
            });

            downloadFile(JSON.stringify(data, null, 2), 'subdomains.json', 'application/json');
        }

        // Screenshot Gallery
        function setGalleryView(view, btn) {
            document.querySelectorAll('#screenshots .filter-group .filter-btn').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('gridView').style.display = view === 'grid' ? 'block' : 'none';
            document.getElementById('clusterView').style.display = view === 'cluster' ? 'block' : 'none';
        }

        function filterScreenshots() {
            const search = document.getElementById('screenshotSearch').value.toLowerCase();
            document.querySelectorAll('.screenshot-card').forEach(card => {
                const host = card.dataset.host.toLowerCase();
                const url = card.dataset.url.toLowerCase();
                card.style.display = (host.includes(search) || url.includes(search)) ? 'block' : 'none';
            });
        }

        // OSINT Tab switching
        function showOsintTab(tab) {
            // Hide all content
            document.querySelectorAll('.osint-content').forEach(el => el.style.display = 'none');
            // Remove active from all tabs
            document.querySelectorAll('.osint-tab').forEach(el => el.classList.remove('active'));
            // Show selected content
            const content = document.getElementById('osint-' + tab);
            if (content) content.style.display = 'block';
            // Set active tab
            event.target.classList.add('active');
        }

        function filterSecHeaders() {
            const search = document.getElementById('secheaderSearch').value.toLowerCase();
            document.querySelectorAll('#secheaderTable tbody tr').forEach(row => {
                const host = (row.dataset.host || '').toLowerCase();
                const missing = (row.dataset.missing || '').toLowerCase();
                row.style.display = (host.includes(search) || missing.includes(search)) ? '' : 'none';
            });
        }

        // Lightbox functionality
        const screenshotData = [
            {{range .ScreenshotImages}}
            { src: "{{.DataURI}}", host: "{{.Host}}", url: "{{.URL}}" },
            {{end}}
        ];
        let currentLightboxIndex = 0;

        function openLightbox(index) {
            currentLightboxIndex = index;
            const data = screenshotData[index];
            if (!data) return;

            document.getElementById('lightboxImg').src = data.src;
            document.getElementById('lightboxHost').textContent = data.host;
            document.getElementById('lightboxUrl').href = data.url;
            document.getElementById('lightboxUrl').textContent = data.url;
            document.getElementById('lightboxCounter').textContent = (index + 1) + ' / ' + screenshotData.length;
            document.getElementById('lightbox').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function openLightboxByUrl(src, host, url) {
            document.getElementById('lightboxImg').src = src;
            document.getElementById('lightboxHost').textContent = host;
            document.getElementById('lightboxUrl').href = url;
            document.getElementById('lightboxUrl').textContent = url;
            document.getElementById('lightboxCounter').textContent = '';
            document.getElementById('lightbox').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeLightbox() {
            document.getElementById('lightbox').classList.remove('active');
            document.body.style.overflow = '';
        }

        function navigateLightbox(direction) {
            if (screenshotData.length === 0) return;
            currentLightboxIndex = (currentLightboxIndex + direction + screenshotData.length) % screenshotData.length;
            openLightbox(currentLightboxIndex);
        }

        // Keyboard navigation
        document.addEventListener('keydown', function(e) {
            const lb = document.getElementById('lightbox');
            if (!lb || !lb.classList.contains('active')) return;
            if (e.key === 'Escape') closeLightbox();
            if (e.key === 'ArrowLeft') navigateLightbox(-1);
            if (e.key === 'ArrowRight') navigateLightbox(1);
        });
    </script>

    <!-- Lightbox Modal -->
    <div id="lightbox" class="lightbox" onclick="if(event.target===this)closeLightbox()">
        <span class="lightbox-close" onclick="closeLightbox()">&times;</span>
        <span class="lightbox-counter" id="lightboxCounter"></span>
        <span class="lightbox-nav lightbox-prev" onclick="event.stopPropagation();navigateLightbox(-1)">&#10094;</span>
        <div class="lightbox-content" onclick="event.stopPropagation()">
            <img id="lightboxImg" class="lightbox-img" src="" alt="Screenshot">
            <div class="lightbox-info">
                <strong id="lightboxHost"></strong><br>
                <a id="lightboxUrl" href="" target="_blank" style="color: var(--accent);"></a>
            </div>
        </div>
        <span class="lightbox-nav lightbox-next" onclick="event.stopPropagation();navigateLightbox(1)">&#10095;</span>
    </div>
</body>
</html>
`

	// Helper functions for template
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"ge":  func(a, b int) bool { return a >= b },
		"percent": func(value, max int) int {
			if max == 0 {
				return 0
			}
			return (value * 100) / max
		},
		"trimPrefix": func(s, prefix string) string {
			return strings.TrimPrefix(s, prefix)
		},
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tpl)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(outputDir, fmt.Sprintf("report_%s.html", data.Target)))
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, data)
}
