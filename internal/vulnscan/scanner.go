package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	TotalScanned     int             `json:"total_scanned"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
	BySeverity       map[string]int  `json:"by_severity"`
	ByType           map[string]int  `json:"by_type"`
	Duration         time.Duration   `json:"duration"`
	ScanMode         string          `json:"scan_mode"`          // "fast", "deep", "custom", or "tech-aware"
	DetectedTech     []string        `json:"detected_tech"`      // Technologies detected and scanned for
	TargetedTags     []string        `json:"targeted_tags"`      // Nuclei tags used based on tech
	TechAwareScan    bool            `json:"tech_aware_scan"`    // Whether tech-aware scanning was used
}

type Vulnerability struct {
	Host        string `json:"host"`
	URL         string `json:"url,omitempty"`
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Matcher     string `json:"matcher,omitempty"`
	Tool        string `json:"tool"`
}

type Scanner struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
}

// TechInput contains technology detection data for tech-aware scanning
type TechInput struct {
	TechByHost map[string][]string // host -> [technologies]
	TechCount  map[string]int      // technology -> count across all hosts
}

// NucleiScanType represents a category of nuclei scan for parallel execution
type NucleiScanType struct {
	Name        string   // Scan type name (e.g., "CRLF Injection")
	Tags        []string // Nuclei tags to use
	Severity    []string // Severity levels to scan
	Description string   // Human-readable description
	Category    string   // Category: "web" uses URLs, "dns" uses subdomains, "network" for SSH
	CustomPaths []string // Custom paths to check (for endpoint discovery without nuclei templates)
}

// nucleiParallelScanTypes defines all nuclei scan types to run in parallel
// Each scan type runs as a separate nuclei process for maximum parallelism
var nucleiParallelScanTypes = []NucleiScanType{
	// High Priority - Common Bug Bounty Findings
	{
		Name:        "CRLF-Injection",
		Tags:        []string{"crlf"},
		Severity:    []string{"critical", "high", "medium"},
		Description: "CRLF Injection / HTTP Response Splitting",
		Category:    "web",
	},
	{
		Name:        "Open-Redirect",
		Tags:        []string{"redirect", "open-redirect"},
		Severity:    []string{"critical", "high", "medium"},
		Description: "Open Redirect Vulnerabilities",
		Category:    "web",
	},
	{
		Name:        "XXE",
		Tags:        []string{"xxe"},
		Severity:    []string{"critical", "high"},
		Description: "XML External Entity Injection",
		Category:    "web",
	},
	{
		Name:        "SSRF",
		Tags:        []string{"ssrf", "oast"},
		Severity:    []string{"critical", "high"},
		Description: "Server-Side Request Forgery",
		Category:    "web",
	},
	{
		Name:        "SSTI",
		Tags:        []string{"ssti"},
		Severity:    []string{"critical", "high"},
		Description: "Server-Side Template Injection",
		Category:    "web",
	},
	{
		Name:        "RCE",
		Tags:        []string{"rce"},
		Severity:    []string{"critical"},
		Description: "Remote Code Execution",
		Category:    "web",
	},
	{
		Name:        "LFI-RFI",
		Tags:        []string{"lfi", "rfi", "fileread"},
		Severity:    []string{"critical", "high"},
		Description: "Local/Remote File Inclusion",
		Category:    "web",
	},
	{
		Name:        "SQLi",
		Tags:        []string{"sqli"},
		Severity:    []string{"critical", "high"},
		Description: "SQL Injection",
		Category:    "web",
	},
	// DNS/Takeover Related
	{
		Name:        "DNS-Takeover",
		Tags:        []string{"dns-takeover", "takeover", "subdomain-takeover"},
		Severity:    []string{"critical", "high"},
		Description: "DNS/Subdomain Takeover",
		Category:    "dns",
	},
	// Cache/Header Related
	{
		Name:        "Cache-Poisoning",
		Tags:        []string{"cache", "cache-poisoning"},
		Severity:    []string{"critical", "high", "medium"},
		Description: "Web Cache Poisoning",
		Category:    "web",
	},
	{
		Name:        "Host-Header",
		Tags:        []string{"host-header"},
		Severity:    []string{"critical", "high", "medium"},
		Description: "Host Header Injection",
		Category:    "web",
	},
	{
		Name:        "CORS",
		Tags:        []string{"cors", "cors-misconfig"},
		Severity:    []string{"critical", "high", "medium"},
		Description: "CORS Misconfiguration",
		Category:    "web",
	},
	// Deserialization
	{
		Name:        "Deserialization",
		Tags:        []string{"deserialization", "java-deserialization"},
		Severity:    []string{"critical", "high"},
		Description: "Insecure Deserialization",
		Category:    "web",
	},
	// Authentication/Authorization
	{
		Name:        "Auth-Bypass",
		Tags:        []string{"auth-bypass", "default-login"},
		Severity:    []string{"critical", "high"},
		Description: "Authentication Bypass / Default Credentials",
		Category:    "web",
	},
	// SSL/TLS Certificate & Protocol Issues
	{
		Name:        "SSL-TLS-Critical",
		Tags:        []string{"ssl", "tls", "expired-ssl", "weak-cipher-suites"},
		Severity:    []string{"medium"},
		Description: "SSL/TLS Critical Issues (Expired Cert, Weak Ciphers, Old Protocol)",
		Category:    "web",
	},
	{
		Name:        "SSL-TLS-Low",
		Tags:        []string{"self-signed-ssl", "mismatched-ssl-certificate", "mismatched-ssl"},
		Severity:    []string{"low"},
		Description: "SSL/TLS Configuration Issues (Self-Signed, Mismatched)",
		Category:    "web",
	},
	{
		Name:        "SSL-TLS-Info",
		Tags:        []string{"ssl-issuer", "ssl-dns-names", "tls-version"},
		Severity:    []string{"info"},
		Description: "SSL/TLS Information Gathering",
		Category:    "web",
	},
	// SSH Security (ports: 22, 2222, 22222, 2022, 22022)
	{
		Name:        "SSH-Auth",
		Tags:        []string{"ssh-password-auth", "ssh-auth-methods"},
		Severity:    []string{"medium"},
		Description: "SSH Authentication Issues (Password Auth Enabled)",
		Category:    "network",
	},
	{
		Name:        "SSH-Weak-Algo",
		Tags:        []string{"ssh-weak-algo-supported", "ssh-cbc-mode-ciphers", "ssh-weak-mac-algo"},
		Severity:    []string{"low"},
		Description: "SSH Weak Algorithms",
		Category:    "network",
	},
	{
		Name:        "SSH-Detection",
		Tags:        []string{"openssh-detect", "ssh-server-enumeration"},
		Severity:    []string{"info"},
		Description: "SSH Service Detection & Version",
		Category:    "network",
	},
	// SMTP Security (ports: 25, 465, 587, 2525)
	// Common issues: open relay, unauthenticated access, VRFY/EXPN commands
	{
		Name:        "SMTP-Open-Relay",
		Tags:        []string{"smtp-open-relay", "open-relay"},
		Severity:    []string{"high"},
		Description: "SMTP Open Relay (Unauthenticated Mail Sending)",
		Category:    "smtp",
	},
	{
		Name:        "SMTP-Misconfig",
		Tags:        []string{"smtp-vrfy-expn", "smtp-user-enum", "smtp-commands"},
		Severity:    []string{"medium"},
		Description: "SMTP Misconfigurations (VRFY/EXPN enabled, User Enumeration)",
		Category:    "smtp",
	},
	{
		Name:        "SMTP-Detection",
		Tags:        []string{"smtp-detect", "smtp-service-detect", "smtp"},
		Severity:    []string{"info"},
		Description: "SMTP Service Detection & Banner",
		Category:    "smtp",
	},
	// Debug/Monitoring Endpoints Exposure
	{
		Name:        "Debug-Endpoints",
		Tags:        []string{"debug", "prometheus", "actuator", "metrics", "pprof", "phpinfo", "config-exposure"},
		Severity:    []string{"low", "medium", "info"},
		Description: "Exposed Debug/Monitoring Endpoints (Prometheus, Actuator, pprof)",
		Category:    "web",
	},
	// MCP (Model Context Protocol) Endpoint Exposure
	// Exposed /mcp endpoints can allow unauthorized AI model interactions
	{
		Name:        "MCP-Endpoints",
		Tags:        []string{"mcp", "api", "exposure", "config"},
		Severity:    []string{"medium", "low", "info"},
		Description: "MCP (Model Context Protocol) Endpoint Exposure",
		Category:    "web",
		CustomPaths: []string{"/mcp", "/mcp/", "/.well-known/mcp", "/api/mcp", "/v1/mcp"},
	},
	// Log4J / Log4Shell (CVE-2021-44228)
	{
		Name:        "Log4J",
		Tags:        []string{"log4j", "log4shell", "cve-2021-44228", "jndi"},
		Severity:    []string{"critical", "high"},
		Description: "Log4J/Log4Shell Remote Code Execution",
		Category:    "web",
	},
	// Spring4Shell / SpringShell (CVE-2022-22965)
	{
		Name:        "Spring4Shell",
		Tags:        []string{"spring4shell", "springshell", "cve-2022-22965", "spring-cloud"},
		Severity:    []string{"critical", "high"},
		Description: "Spring4Shell/SpringShell Remote Code Execution",
		Category:    "web",
	},
	// Kubernetes Misconfigurations
	{
		Name:        "Kubernetes",
		Tags:        []string{"kubernetes", "k8s", "kube", "kubectl", "helm", "etcd"},
		Severity:    []string{"critical", "high", "medium", "low", "info"},
		Description: "Kubernetes Misconfigurations & Exposures",
		Category:    "web",
	},
	// Docker Misconfigurations
	{
		Name:        "Docker",
		Tags:        []string{"docker", "docker-api", "container", "portainer", "registry"},
		Severity:    []string{"critical", "high", "medium", "low"},
		Description: "Docker API & Container Misconfigurations",
		Category:    "web",
	},
	// Cloud Metadata & IMDS
	{
		Name:        "Cloud-Metadata",
		Tags:        []string{"aws", "azure", "gcp", "metadata", "imds", "cloud"},
		Severity:    []string{"critical", "high", "medium"},
		Description: "Cloud Metadata Service (IMDS) Exposure",
		Category:    "web",
	},
}

// techToNucleiTags maps detected technologies to relevant nuclei tags
// This enables targeted vulnerability scanning based on actual tech stack
var techToNucleiTags = map[string][]string{
	// Web Servers
	"nginx":      {"nginx", "cve-nginx"},
	"apache":     {"apache", "cve-apache"},
	"iis":        {"iis", "cve-iis", "microsoft"},
	"tomcat":     {"tomcat", "apache-tomcat", "cve-tomcat"},
	"jetty":      {"jetty"},
	"caddy":      {"caddy"},
	"litespeed":  {"litespeed"},

	// Programming Languages / Frameworks
	"php":        {"php", "cve-php"},
	"wordpress":  {"wordpress", "wp-plugin", "cve-wordpress"},
	"drupal":     {"drupal", "cve-drupal"},
	"joomla":     {"joomla", "cve-joomla"},
	"laravel":    {"laravel", "php"},
	"symfony":    {"symfony", "php"},
	"codeigniter": {"codeigniter", "php"},
	"yii":        {"yii", "php"},

	"python":     {"python"},
	"django":     {"django", "python"},
	"flask":      {"flask", "python"},
	"fastapi":    {"python"},

	"ruby":       {"ruby"},
	"rails":      {"rails", "ruby-on-rails"},

	"java":       {"java"},
	"spring":     {"spring", "springboot", "cve-spring"},
	"struts":     {"struts", "apache-struts"},

	"node.js":    {"nodejs", "node"},
	"express":    {"express", "nodejs"},
	"next.js":    {"nextjs"},
	"nuxt.js":    {"nuxtjs"},
	"react":      {"react"},
	"angular":    {"angular"},
	"vue.js":     {"vuejs"},

	"asp.net":    {"asp", "aspnet", "microsoft"},
	".net":       {"dotnet", "microsoft"},

	"go":         {"go", "golang"},
	"gin":        {"go", "golang"},

	// CMS / Platforms
	"magento":    {"magento", "cve-magento"},
	"shopify":    {"shopify"},
	"prestashop": {"prestashop"},
	"opencart":   {"opencart"},
	"woocommerce": {"woocommerce", "wordpress"},
	"typo3":      {"typo3"},
	"craft-cms":  {"craftcms"},
	"ghost":      {"ghost"},
	"contentful": {"contentful"},
	"strapi":     {"strapi"},
	"directus":   {"directus"},

	// Databases (exposed interfaces)
	"mysql":      {"mysql", "cve-mysql", "database"},
	"postgresql": {"postgresql", "postgres", "database"},
	"mongodb":    {"mongodb", "nosql", "database"},
	"redis":      {"redis", "cve-redis"},
	"elasticsearch": {"elasticsearch", "elastic"},
	"couchdb":    {"couchdb", "nosql"},
	"cassandra":  {"cassandra", "nosql"},
	"memcached":  {"memcached"},

	// DevOps / Infrastructure
	"jenkins":    {"jenkins", "cve-jenkins", "cicd"},
	"gitlab":     {"gitlab", "cve-gitlab"},
	"github":     {"github"},
	"bitbucket":  {"bitbucket"},
	"bamboo":     {"bamboo"},
	"teamcity":   {"teamcity"},
	"circleci":   {"circleci"},
	"travis":     {"travis"},
	"docker":     {"docker"},
	"kubernetes": {"kubernetes", "k8s"},
	"ansible":    {"ansible"},
	"terraform":  {"terraform"},
	"vagrant":    {"vagrant"},
	"prometheus": {"prometheus"},
	"grafana":    {"grafana", "cve-grafana"},
	"kibana":     {"kibana", "elastic"},
	"splunk":     {"splunk"},
	"nagios":     {"nagios"},
	"zabbix":     {"zabbix"},

	// Cloud Services
	"aws":        {"aws", "amazon"},
	"azure":      {"azure", "microsoft"},
	"gcp":        {"gcp", "google-cloud"},
	"cloudflare": {"cloudflare"},
	"fastly":     {"fastly"},
	"akamai":     {"akamai"},

	// Application Servers / Middleware
	"weblogic":   {"weblogic", "oracle", "cve-weblogic"},
	"websphere":  {"websphere", "ibm"},
	"jboss":      {"jboss", "wildfly"},
	"glassfish":  {"glassfish"},
	"coldfusion": {"coldfusion", "adobe"},

	// Security / Network
	"fortinet":   {"fortinet", "fortigate"},
	"paloalto":   {"paloalto"},
	"cisco":      {"cisco"},
	"f5":         {"f5", "bigip"},
	"citrix":     {"citrix", "cve-citrix"},
	"sonicwall":  {"sonicwall"},
	"sophos":     {"sophos"},

	// File Sharing / Collaboration
	"sharepoint": {"sharepoint", "microsoft"},
	"confluence": {"confluence", "atlassian", "cve-confluence"},
	"jira":       {"jira", "atlassian", "cve-jira"},
	"nextcloud":  {"nextcloud"},
	"owncloud":   {"owncloud"},
	"alfresco":   {"alfresco"},

	// Email
	"exchange":   {"exchange", "microsoft", "cve-exchange"},
	"zimbra":     {"zimbra", "cve-zimbra"},
	"roundcube":  {"roundcube"},

	// API / Gateway
	"kong":       {"kong", "api-gateway"},
	"swagger":    {"swagger", "openapi"},
	"graphql":    {"graphql"},

	// Other
	"vbulletin":  {"vbulletin"},
	"phpbb":      {"phpbb"},
	"discourse":  {"discourse"},
	"moodle":     {"moodle"},
	"sap":        {"sap"},
	"oracle":     {"oracle"},
	"vmware":     {"vmware", "cve-vmware"},
	"veeam":      {"veeam"},
	"plesk":      {"plesk"},
	"cpanel":     {"cpanel"},
	"phpmyadmin": {"phpmyadmin"},
	"adminer":    {"adminer"},
}

// getNucleiTagsForTech converts detected technologies to nuclei tags
func getNucleiTagsForTech(techByHost map[string][]string) []string {
	tagSet := make(map[string]bool)

	// Collect all unique technologies
	for _, techs := range techByHost {
		for _, tech := range techs {
			// Normalize tech name (lowercase, trim spaces)
			techLower := strings.ToLower(strings.TrimSpace(tech))

			// Try exact match first
			if tags, ok := techToNucleiTags[techLower]; ok {
				for _, tag := range tags {
					tagSet[tag] = true
				}
				continue
			}

			// Try partial matching for common variations
			for key, tags := range techToNucleiTags {
				if strings.Contains(techLower, key) || strings.Contains(key, techLower) {
					for _, tag := range tags {
						tagSet[tag] = true
					}
					break
				}
			}
		}
	}

	// Convert to sorted slice
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	return tags
}

// getDetectedTechList returns a deduplicated list of all detected technologies
func getDetectedTechList(techByHost map[string][]string) []string {
	techSet := make(map[string]bool)
	for _, techs := range techByHost {
		for _, tech := range techs {
			techSet[tech] = true
		}
	}

	techs := make([]string, 0, len(techSet))
	for tech := range techSet {
		techs = append(techs, tech)
	}
	sort.Strings(techs)

	return techs
}

// Scan performs vulnerability scanning using nuclei templates and dalfox
// Deprecated: Use ScanWithTech for tech-aware scanning
func (s *Scanner) Scan(hosts []string, categorizedURLs *historic.CategorizedURLs) (*Result, error) {
	return s.ScanWithTech(hosts, categorizedURLs, nil)
}

// ScanWithTech performs tech-aware vulnerability scanning
// When techInput is provided, nuclei scans target only technologies detected in the tech phase
func (s *Scanner) ScanWithTech(hosts []string, categorizedURLs *historic.CategorizedURLs, techInput *TechInput) (*Result, error) {
	start := time.Now()

	// Determine scan mode and prepare tech-specific tags
	scanMode := s.getScanMode()
	var techTags []string
	var detectedTech []string
	techAwareScan := false

	// If tech data is available and not in custom/deep mode, use tech-aware scanning
	if techInput != nil && len(techInput.TechByHost) > 0 && s.cfg.NucleiTags == "" && !s.cfg.DeepScan {
		techTags = getNucleiTagsForTech(techInput.TechByHost)
		detectedTech = getDetectedTechList(techInput.TechByHost)
		if len(techTags) > 0 {
			scanMode = "tech-aware"
			techAwareScan = true
		}
	}

	result := &Result{
		TotalScanned:    len(hosts),
		Vulnerabilities: []Vulnerability{},
		BySeverity:      make(map[string]int),
		ByType:          make(map[string]int),
		ScanMode:        scanMode,
		DetectedTech:    detectedTech,
		TargetedTags:    techTags,
		TechAwareScan:   techAwareScan,
	}

	if len(hosts) == 0 {
		return result, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Create temp file with hosts for nuclei
	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-hosts.txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Run nuclei vulnerability scan
	if s.c.IsInstalled("nuclei") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("        Running nuclei vulnerability scan [%s mode]...\n", result.ScanMode)

			var vulns []Vulnerability
			if techAwareScan {
				// Tech-aware scan: run targeted scan based on detected tech
				vulns = s.nucleiTechAwareScan(tmp, techTags)
			} else {
				// Standard scan mode (fast/deep/custom)
				vulns = s.nucleiScan(tmp)
			}

			mu.Lock()
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			mu.Unlock()
			fmt.Printf("        nuclei: %d vulnerabilities found\n", len(vulns))
		}()
	}

	// Run dalfox for XSS scanning on categorized XSS URLs (parallel with nuclei)
	if s.c.IsInstalled("dalfox") && categorizedURLs != nil && len(categorizedURLs.XSS) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running dalfox XSS scan...")
			vulns := s.dalfoxScan(categorizedURLs.XSS)
			mu.Lock()
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			mu.Unlock()
			fmt.Printf("        dalfox: %d XSS vulnerabilities found\n", len(vulns))
		}()
	}

	// Run sxss for fast XSS reflection scanning on ALL URLs with parameters (parallel with dalfox)
	// sxss is faster than dalfox and good for initial triage of reflectable parameters
	if s.c.IsInstalled("sxss") && categorizedURLs != nil && len(categorizedURLs.XSS) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("        Running sxss XSS reflection scan on %d URLs...\n", len(categorizedURLs.XSS))
			vulns := s.sxssScan(categorizedURLs.XSS)
			mu.Lock()
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			mu.Unlock()
			fmt.Printf("        sxss: %d XSS reflections found\n", len(vulns))
		}()
	}

	// Run targeted nuclei scan on categorized URLs (only in deep mode or with custom tags)
	if s.c.IsInstalled("nuclei") && categorizedURLs != nil && (s.cfg.DeepScan || s.cfg.NucleiTags != "") {
		var allCategorizedURLs []string
		urlSet := make(map[string]bool)

		for _, urls := range [][]string{
			categorizedURLs.SQLi,
			categorizedURLs.SSRF,
			categorizedURLs.LFI,
			categorizedURLs.SSTI,
			categorizedURLs.RCE,
		} {
			for _, u := range urls {
				if !urlSet[u] {
					urlSet[u] = true
					allCategorizedURLs = append(allCategorizedURLs, u)
				}
			}
		}

		if len(allCategorizedURLs) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Printf("        Running nuclei targeted scan on %d categorized URLs...\n", len(allCategorizedURLs))
				vulns := s.nucleiTargeted(allCategorizedURLs, "sqli,ssrf,lfi,ssti,rce,injection")
				mu.Lock()
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
				mu.Unlock()
				fmt.Printf("        nuclei-targeted: %d vulnerabilities found\n", len(vulns))
			}()
		}
	}

	// Run secret scanner on JS files and URLs (parallel with other scans)
	if categorizedURLs != nil && len(categorizedURLs.JSFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("        Running secret scanner on %d JS files/URLs...\n", len(categorizedURLs.JSFiles))
			detector := NewSecretDetector(s.cfg)
			secretResult, err := detector.DetectSecrets(context.Background(), nil, categorizedURLs.JSFiles)
			if err != nil {
				fmt.Printf("        secret scanner error: %v\n", err)
				return
			}
			// Convert secrets to vulnerabilities
			if secretResult != nil && len(secretResult.Secrets) > 0 {
				mu.Lock()
				for _, secret := range secretResult.Secrets {
					result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
						URL:         secret.Source,
						TemplateID:  "secret-" + strings.ToLower(strings.ReplaceAll(secret.Type, " ", "-")),
						Name:        secret.Type + " exposed",
						Severity:    secret.Severity,
						Type:        "secret",
						Description: fmt.Sprintf("Exposed %s found in %s", secret.Type, secret.Source),
						Tool:        "secret-scanner",
					})
				}
				mu.Unlock()
				fmt.Printf("        secret scanner: %d secrets found\n", len(secretResult.Secrets))
			}
		}()
	}

	// BB-8: Run quick tests using qsreplace + httpx pipeline (parallel with other scans)
	// Tests for SSTI, SQLi, XSS reflection, LFI, SSRF, and Open Redirect
	if categorizedURLs != nil && s.c.IsInstalled("qsreplace") && s.c.IsInstalled("httpx") {
		hasCategorizedURLs := len(categorizedURLs.SSTI) > 0 || len(categorizedURLs.SQLi) > 0 ||
			len(categorizedURLs.XSS) > 0 || len(categorizedURLs.LFI) > 0 ||
			len(categorizedURLs.SSRF) > 0 || len(categorizedURLs.Redirect) > 0
		if hasCategorizedURLs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Println("        Running quick tests (SSTI/SQLi/XSS/LFI/SSRF/Redirect)...")
				qt := NewQuickTester(s.c, s.cfg.Threads)
				qtResult := qt.RunQuickTests(categorizedURLs)
				if qtResult != nil && len(qtResult.Vulnerabilities) > 0 {
					mu.Lock()
					result.Vulnerabilities = append(result.Vulnerabilities, qtResult.Vulnerabilities...)
					mu.Unlock()
					fmt.Printf("        quick tests: %d potential vulnerabilities found\n", len(qtResult.Vulnerabilities))
				}
			}()
		}
	}

	// BB-9: Run SSH/SMTP network scans (parallel with other scans)
	// SSH ports: 22, 2222, 22222, 2022, 22022
	// SMTP ports: 25, 465, 587, 2525
	if s.c.IsInstalled("nuclei") && len(hosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running SSH/SMTP network scans...")
			netVulns := s.runNetworkScans(hosts)
			if len(netVulns) > 0 {
				mu.Lock()
				result.Vulnerabilities = append(result.Vulnerabilities, netVulns...)
				mu.Unlock()
				fmt.Printf("        network scans: %d findings (SSH/SMTP)\n", len(netVulns))
			}
		}()
	}

	wg.Wait()

	// Run version-based vulnerability detection if tech data is available
	if techInput != nil && len(techInput.TechByHost) > 0 {
		fmt.Println("        Running version-based vulnerability detection...")
		versionResult := DetectVersionVulnerabilities(techInput.TechByHost)
		if versionResult != nil && len(versionResult.Vulnerabilities) > 0 {
			result.Vulnerabilities = append(result.Vulnerabilities, versionResult.Vulnerabilities...)
			fmt.Printf("        version-detector: %d vulnerabilities/warnings found\n", len(versionResult.Vulnerabilities))
		}
	}

	// Dedupe vulnerabilities
	seen := make(map[string]bool)
	var unique []Vulnerability
	for _, v := range result.Vulnerabilities {
		key := fmt.Sprintf("%s|%s|%s", v.URL, v.TemplateID, v.Tool)
		if v.URL == "" {
			key = fmt.Sprintf("%s|%s|%s", v.Host, v.TemplateID, v.Tool)
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
			result.BySeverity[v.Severity]++
			result.ByType[v.Type]++
		}
	}
	result.Vulnerabilities = unique
	result.Duration = time.Since(start)

	return result, nil
}

// getScanMode returns the current scan mode based on config
func (s *Scanner) getScanMode() string {
	if s.cfg.NucleiTags != "" {
		return "custom"
	}
	if s.cfg.DeepScan {
		return "deep"
	}
	return "fast"
}

// getTimeout returns the appropriate timeout based on scan mode
func (s *Scanner) getTimeout() time.Duration {
	if s.cfg.NucleiTimeout > 0 {
		return time.Duration(s.cfg.NucleiTimeout) * time.Minute
	}
	if s.cfg.DeepScan {
		return 30 * time.Minute
	}
	return 10 * time.Minute
}

// nucleiScan runs nuclei with appropriate templates based on scan mode
func (s *Scanner) nucleiScan(hostsFile string) []Vulnerability {
	var vulns []Vulnerability

	home, err := os.UserHomeDir()
	if err != nil {
		return vulns
	}
	templateDir := home + "/nuclei-templates"

	// Base args with optimized settings
	args := []string{
		"-l", hostsFile,
		"-severity", "critical,high",
		"-jsonl",
		"-exclude-tags", "dos,fuzz",
		"-ss", "host-spray",
		"-mhe", "3",
		"-timeout", "5",
		"-duc",
		"-silent", // Suppress banner and info messages
		"-nc",     // No color output
	}

	// Add templates based on scan mode
	if s.cfg.NucleiTags != "" {
		// Custom tags mode
		args = append(args, "-tags", s.cfg.NucleiTags)
		fmt.Printf("        [nuclei] Using custom tags: %s\n", s.cfg.NucleiTags)
	} else if s.cfg.DeepScan {
		// Deep scan: all high-impact templates
		args = s.addDeepScanTemplates(args, templateDir)
		fmt.Println("        [nuclei] Deep scan: running all vulnerability templates")
	} else {
		// Fast scan: priority templates only
		args = s.addFastScanTemplates(args, templateDir)
		fmt.Println("        [nuclei] Fast scan: running priority templates (CVEs, misconfigs, exposures)")
	}

	// Performance tuning
	args = s.addPerformanceArgs(args)

	timeout := s.getTimeout()
	r := exec.Run("nuclei", args, &exec.Options{Timeout: timeout})
	if r.Error != nil {
		if r.Stderr != "" {
			fmt.Printf("        [nuclei error] %s\n", strings.TrimSpace(r.Stderr))
		}
		return vulns
	}

	return s.parseNucleiOutput(r.Stdout)
}

// addFastScanTemplates adds templates for fast priority scan (~10 min)
// Focus: Critical/High CVEs (recent), Misconfigurations, Exposed configs
func (s *Scanner) addFastScanTemplates(args []string, templateDir string) []string {
	if _, err := os.Stat(templateDir); err == nil {
		// Use specific high-impact template directories
		args = append(args,
			// Critical exposures - quick wins
			"-t", templateDir+"/http/exposures/configs/",
			"-t", templateDir+"/http/exposures/backups/",
			"-t", templateDir+"/http/exposures/logs/",
			// Misconfigurations - common issues
			"-t", templateDir+"/http/misconfiguration/",
			// Default credentials - easy wins
			"-t", templateDir+"/http/default-logins/",
		)
		// Add recent CVEs using tags (more targeted than all CVEs)
		args = append(args, "-tags", "cve2024,cve2023,cve2025")
	} else {
		// Fallback: tag-based filtering
		args = append(args, "-tags", "exposure,misconfig,default-login,cve2024,cve2023")
	}

	return args
}

// addDeepScanTemplates adds all vulnerability templates for comprehensive scan (~30 min)
func (s *Scanner) addDeepScanTemplates(args []string, templateDir string) []string {
	if _, err := os.Stat(templateDir); err == nil {
		args = append(args,
			"-t", templateDir+"/http/cves/",
			"-t", templateDir+"/http/vulnerabilities/",
			"-t", templateDir+"/http/exposures/",
			"-t", templateDir+"/http/default-logins/",
			"-t", templateDir+"/http/misconfiguration/",
		)
	} else {
		args = append(args, "-tags", "cve,exposure,misconfig,default-login,vulnerability")
	}

	return args
}

// addPerformanceArgs adds performance tuning arguments
func (s *Scanner) addPerformanceArgs(args []string) []string {
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
		args = append(args, "-bs", fmt.Sprintf("%d", s.cfg.Threads*2))
		args = append(args, "-pc", fmt.Sprintf("%d", s.cfg.Threads))
	} else {
		args = append(args, "-c", "50", "-bs", "100", "-pc", "50")
	}

	if s.cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.cfg.RateLimit))
	} else {
		args = append(args, "-rl", "500")
	}

	return args
}

// nucleiTechAwareScan runs nuclei with tags derived from detected technologies
// This is the core of tech-aware scanning - only scan for CVEs relevant to detected tech stack
func (s *Scanner) nucleiTechAwareScan(hostsFile string, techTags []string) []Vulnerability {
	var vulns []Vulnerability

	if len(techTags) == 0 {
		fmt.Println("        [nuclei] No tech-specific tags found, falling back to fast scan")
		return s.nucleiScan(hostsFile)
	}

	// Combine tech tags with always-useful tags
	allTags := append([]string{}, techTags...)
	// Always include exposure/misconfig checks - they're fast and high-value
	allTags = append(allTags, "exposure", "misconfig", "default-login")

	tagsStr := strings.Join(allTags, ",")

	fmt.Printf("        [nuclei] Tech-aware scan: %d technologies detected\n", len(techTags))
	fmt.Printf("        [nuclei] Using tags: %s\n", tagsStr)

	// Base args with optimized settings for tech-aware scan
	args := []string{
		"-l", hostsFile,
		"-tags", tagsStr,
		"-severity", "critical,high",
		"-jsonl",
		"-exclude-tags", "dos,fuzz",
		"-ss", "host-spray",
		"-mhe", "3",
		"-timeout", "5",
		"-duc",
		"-silent", // Suppress banner and info messages
		"-nc",     // No color output
	}

	// Performance tuning
	args = s.addPerformanceArgs(args)

	// Tech-aware scans should be faster than fast scans since they're more targeted
	// 5 minute timeout is enough for targeted scanning
	timeout := 5 * time.Minute
	if s.cfg.NucleiTimeout > 0 {
		timeout = time.Duration(s.cfg.NucleiTimeout) * time.Minute
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: timeout})
	if r.Error != nil {
		if r.Stderr != "" {
			fmt.Printf("        [nuclei error] %s\n", strings.TrimSpace(r.Stderr))
		}
		return vulns
	}

	return s.parseNucleiOutput(r.Stdout)
}

// nucleiTargeted runs nuclei with specific tags for targeted scanning
func (s *Scanner) nucleiTargeted(urls []string, tag string) []Vulnerability {
	var vulns []Vulnerability

	if len(urls) == 0 {
		return vulns
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-urls.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	args := []string{
		"-l", tmp,
		"-tags", tag,
		"-severity", "critical,high,medium",
		"-jsonl",
		"-silent", // Suppress banner and info messages
		"-nc",     // No color output
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}

	timeout := 15 * time.Minute
	if s.cfg.DeepScan {
		timeout = 30 * time.Minute
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: timeout})
	if r.Error != nil {
		return vulns
	}

	return s.parseNucleiOutput(r.Stdout)
}

// parseNucleiOutput parses nuclei JSON output
func (s *Scanner) parseNucleiOutput(output string) []Vulnerability {
	var vulns []Vulnerability

	for _, line := range exec.Lines(output) {
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
			MatcherName string `json:"matcher-name"`
			Type        string `json:"type"`
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

		vulns = append(vulns, Vulnerability{
			Host:        entry.Host,
			URL:         entry.MatchedAt,
			TemplateID:  entry.TemplateID,
			Name:        entry.Info.Name,
			Severity:    entry.Info.Severity,
			Type:        vulnType,
			Description: entry.Info.Description,
			Matcher:     entry.MatcherName,
			Tool:        "nuclei",
		})
	}

	return vulns
}

// dalfoxScan runs dalfox for XSS scanning
func (s *Scanner) dalfoxScan(urls []string) []Vulnerability {
	var vulns []Vulnerability

	if len(urls) == 0 {
		return vulns
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-xss-urls.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	outFile, err := os.CreateTemp("", "dalfox-*.json")
	if err != nil {
		return vulns
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := []string{
		"file", tmp,
		"--silence",
		"--format", "json",
		"-o", outPath,
		"--skip-bav",
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-w", fmt.Sprintf("%d", s.cfg.Threads))
	}

	// Dalfox timeout: 10 min for fast, 20 min for deep
	timeout := 10 * time.Minute
	if s.cfg.DeepScan {
		timeout = 20 * time.Minute
	}

	r := exec.Run("dalfox", args, &exec.Options{Timeout: timeout})
	if r.Error != nil {
		// Still try to parse output file
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		return vulns
	}

	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Data       string `json:"data"`
			URL        string `json:"url"`
			Param      string `json:"param"`
			Type       string `json:"type"`
			MessageStr string `json:"message_str"`
			Severity   string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.URL != "" {
			severity := entry.Severity
			if severity == "" {
				severity = "high"
			}
			vulns = append(vulns, Vulnerability{
				URL:         entry.URL,
				TemplateID:  "dalfox-xss",
				Name:        fmt.Sprintf("XSS via %s parameter", entry.Param),
				Severity:    severity,
				Type:        "xss",
				Description: entry.MessageStr,
				Tool:        "dalfox",
			})
		}
	}

	return vulns
}

// sxssScan runs sxss for fast XSS reflection scanning
// sxss is a concurrent Go tool similar to kxss that checks for XSS reflection
func (s *Scanner) sxssScan(urls []string) []Vulnerability {
	var vulns []Vulnerability

	if len(urls) == 0 {
		return vulns
	}

	// Create temp file with URLs
	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-sxss-urls.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	// Build sxss command - sxss is lightweight, use high concurrency
	concurrency := 150
	if s.cfg.Threads > 0 && s.cfg.Threads > 150 {
		concurrency = s.cfg.Threads
	}

	// Run sxss: cat urls.txt | sxss -concurrency N -retries 3
	cmd := fmt.Sprintf("cat %s | sxss -concurrency %d -retries 3", tmp, concurrency)

	// sxss timeout: 5 min for fast, 10 min for deep
	timeout := 5 * time.Minute
	if s.cfg.DeepScan {
		timeout = 10 * time.Minute
	}

	r := exec.Run("sh", []string{"-c", cmd}, &exec.Options{Timeout: timeout})
	if r.Error != nil {
		return vulns
	}

	// Parse sxss output - each line is a vulnerable URL with reflected parameter info
	// Format: URL with reflected parameter details
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}

		// sxss outputs vulnerable URLs with reflection info
		// Extract the URL and parameter from the output
		vulns = append(vulns, Vulnerability{
			URL:         line,
			TemplateID:  "sxss-xss-reflection",
			Name:        "XSS Reflection Detected",
			Severity:    "medium",
			Type:        "xss",
			Description: fmt.Sprintf("Parameter reflection detected by sxss: %s", line),
			Tool:        "sxss",
		})
	}

	return vulns
}

// runNetworkScans runs SSH and SMTP network security scans
// SSH ports: 22, 2222, 22222, 2022, 22022
// SMTP ports: 25, 465, 587, 2525
func (s *Scanner) runNetworkScans(hosts []string) []Vulnerability {
	var allVulns []Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Extract unique hostnames from URLs
	hostnameSet := make(map[string]bool)
	for _, host := range hosts {
		hostname := host
		hostname = strings.TrimPrefix(hostname, "https://")
		hostname = strings.TrimPrefix(hostname, "http://")
		hostname = strings.Split(hostname, "/")[0]
		hostname = strings.Split(hostname, ":")[0]
		hostnameSet[hostname] = true
	}

	var hostnames []string
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	if len(hostnames) == 0 {
		return nil
	}

	// Limit to first 100 hosts for network scans (they're slow)
	if len(hostnames) > 100 {
		hostnames = hostnames[:100]
	}

	// SSH scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		sshPorts := []string{"22", "2222", "22222", "2022", "22022"}
		var sshTargets []string
		for _, hostname := range hostnames {
			for _, port := range sshPorts {
				sshTargets = append(sshTargets, fmt.Sprintf("%s:%s", hostname, port))
			}
		}

		sshFile, cleanup, err := exec.TempFile(strings.Join(sshTargets, "\n"), "-nuclei-ssh.txt")
		if err != nil {
			return
		}
		defer cleanup()

		// Run SSH scans in sequence (not all at once to avoid overwhelming)
		sshScans := []struct {
			name     string
			tags     string
			severity string
		}{
			{"SSH-Auth", "ssh-password-auth,ssh-auth-methods", "medium"},
			{"SSH-Weak-Algo", "ssh-weak-algo-supported,ssh-cbc-mode-ciphers,ssh-weak-mac-algo", "low"},
			{"SSH-Detection", "openssh-detect,ssh-server-enumeration", "info"},
		}

		for _, scan := range sshScans {
			args := []string{
				"-l", sshFile,
				"-tags", scan.tags,
				"-severity", scan.severity,
				"-jsonl",
				"-silent",
				"-nc",
				"-duc",
				"-timeout", "3",
				"-c", "25",
			}

			r := exec.Run("nuclei", args, &exec.Options{Timeout: 3 * time.Minute})
			if r.Error != nil {
				continue
			}

			vulns := s.parseNucleiOutput(r.Stdout)
			if len(vulns) > 0 {
				mu.Lock()
				allVulns = append(allVulns, vulns...)
				mu.Unlock()
			}
		}
	}()

	// SMTP scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		smtpPorts := []string{"25", "465", "587", "2525"}
		var smtpTargets []string
		for _, hostname := range hostnames {
			for _, port := range smtpPorts {
				smtpTargets = append(smtpTargets, fmt.Sprintf("%s:%s", hostname, port))
			}
		}

		smtpFile, cleanup, err := exec.TempFile(strings.Join(smtpTargets, "\n"), "-nuclei-smtp.txt")
		if err != nil {
			return
		}
		defer cleanup()

		// Run SMTP scans
		smtpScans := []struct {
			name     string
			tags     string
			severity string
		}{
			{"SMTP-Open-Relay", "smtp-open-relay,open-relay", "high"},
			{"SMTP-Misconfig", "smtp-vrfy-expn,smtp-user-enum,smtp-commands", "medium"},
			{"SMTP-Detection", "smtp-detect,smtp-service-detect,smtp", "info"},
		}

		for _, scan := range smtpScans {
			args := []string{
				"-l", smtpFile,
				"-tags", scan.tags,
				"-severity", scan.severity,
				"-jsonl",
				"-silent",
				"-nc",
				"-duc",
				"-timeout", "3",
				"-c", "25",
			}

			r := exec.Run("nuclei", args, &exec.Options{Timeout: 3 * time.Minute})
			if r.Error != nil {
				continue
			}

			vulns := s.parseNucleiOutput(r.Stdout)
			if len(vulns) > 0 {
				mu.Lock()
				allVulns = append(allVulns, vulns...)
				mu.Unlock()
			}
		}
	}()

	wg.Wait()
	return allVulns
}

// runParallelNucleiScans runs multiple nuclei scan types in parallel
// Each scan type targets a specific vulnerability category (CRLF, XXE, SSRF, etc.)
func (s *Scanner) runParallelNucleiScans(hosts []string, urls []string, subdomains []string) []Vulnerability {
	if !s.c.IsInstalled("nuclei") {
		return nil
	}

	if len(hosts) == 0 && len(urls) == 0 && len(subdomains) == 0 {
		return nil
	}

	fmt.Printf("        [ParallelNuclei] Starting %d parallel scan types...\n", len(nucleiParallelScanTypes))

	// Create temp files for targets
	var hostFile, urlFile, subdomainFile string
	var cleanupHost, cleanupURL, cleanupSubdomain func()

	if len(hosts) > 0 {
		var err error
		hostFile, cleanupHost, err = exec.TempFile(strings.Join(hosts, "\n"), "-nuclei-hosts.txt")
		if err == nil {
			defer cleanupHost()
		}
	}

	if len(urls) > 0 {
		var err error
		urlFile, cleanupURL, err = exec.TempFile(strings.Join(urls, "\n"), "-nuclei-urls.txt")
		if err == nil {
			defer cleanupURL()
		}
	}

	if len(subdomains) > 0 {
		var err error
		subdomainFile, cleanupSubdomain, err = exec.TempFile(strings.Join(subdomains, "\n"), "-nuclei-subs.txt")
		if err == nil {
			defer cleanupSubdomain()
		}
	}

	// Create SSH targets file for network category (SSH ports: 22, 2222, 22222, 2022, 22022)
	var sshFile string
	var cleanupSSH func()
	if len(hosts) > 0 {
		sshPorts := []string{"22", "2222", "22222", "2022", "22022"}
		var sshTargets []string
		for _, host := range hosts {
			// Extract hostname from URL if needed
			hostname := host
			hostname = strings.TrimPrefix(hostname, "https://")
			hostname = strings.TrimPrefix(hostname, "http://")
			hostname = strings.Split(hostname, "/")[0]
			hostname = strings.Split(hostname, ":")[0] // Remove any existing port

			for _, port := range sshPorts {
				sshTargets = append(sshTargets, fmt.Sprintf("%s:%s", hostname, port))
			}
		}
		var err error
		sshFile, cleanupSSH, err = exec.TempFile(strings.Join(sshTargets, "\n"), "-nuclei-ssh.txt")
		if err == nil {
			defer cleanupSSH()
		}
	}

	// Create SMTP targets file for smtp category (SMTP ports: 25, 465, 587, 2525)
	var smtpFile string
	var cleanupSMTP func()
	if len(hosts) > 0 {
		smtpPorts := []string{"25", "465", "587", "2525"}
		var smtpTargets []string
		for _, host := range hosts {
			// Extract hostname from URL if needed
			hostname := host
			hostname = strings.TrimPrefix(hostname, "https://")
			hostname = strings.TrimPrefix(hostname, "http://")
			hostname = strings.Split(hostname, "/")[0]
			hostname = strings.Split(hostname, ":")[0] // Remove any existing port

			for _, port := range smtpPorts {
				smtpTargets = append(smtpTargets, fmt.Sprintf("%s:%s", hostname, port))
			}
		}
		var err error
		smtpFile, cleanupSMTP, err = exec.TempFile(strings.Join(smtpTargets, "\n"), "-nuclei-smtp.txt")
		if err == nil {
			defer cleanupSMTP()
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allVulns []Vulnerability
	scansRun := 0

	// Run each scan type in parallel
	for _, scanType := range nucleiParallelScanTypes {
		// Choose target file based on category
		var targetFile string
		switch scanType.Category {
		case "dns":
			targetFile = subdomainFile
		case "network":
			targetFile = sshFile // SSH targets with ports
		case "smtp":
			targetFile = smtpFile // SMTP targets with ports (25, 465, 587, 2525)
		case "web":
			if urlFile != "" {
				targetFile = urlFile
			} else {
				targetFile = hostFile
			}
		default:
			targetFile = hostFile
		}

		if targetFile == "" {
			continue
		}

		wg.Add(1)
		go func(st NucleiScanType, tf string) {
			defer wg.Done()

			vulns := s.runSingleNucleiScanType(st, tf)
			if len(vulns) > 0 {
				mu.Lock()
				allVulns = append(allVulns, vulns...)
				scansRun++
				mu.Unlock()
				fmt.Printf("        [ParallelNuclei] %s: %d vulnerabilities\n", st.Name, len(vulns))
			}
		}(scanType, targetFile)
	}

	wg.Wait()

	fmt.Printf("        [ParallelNuclei] Completed: %d scans found %d vulnerabilities\n", scansRun, len(allVulns))

	return allVulns
}

// runSingleNucleiScanType executes a single nuclei scan type
func (s *Scanner) runSingleNucleiScanType(scanType NucleiScanType, targetFile string) []Vulnerability {
	var allVulns []Vulnerability

	// If scan type has custom paths, check them with httpx
	if len(scanType.CustomPaths) > 0 {
		customVulns := s.checkCustomPaths(scanType, targetFile)
		allVulns = append(allVulns, customVulns...)
	}

	// Run nuclei with tags if tags are defined
	if len(scanType.Tags) > 0 {
		args := []string{
			"-l", targetFile,
			"-tags", strings.Join(scanType.Tags, ","),
			"-severity", strings.Join(scanType.Severity, ","),
			"-jsonl",
			"-silent",
			"-nc",  // No color
			"-duc", // Disable update check
		}

		// Add threads
		if s.cfg.Threads > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads/2)) // Use half threads per scan type
		} else {
			args = append(args, "-c", "25")
		}

		// Shorter timeout per scan type since they're targeted
		r := exec.Run("nuclei", args, &exec.Options{Timeout: 5 * time.Minute})
		if r.Error == nil {
			nucleiVulns := s.parseNucleiOutput(r.Stdout)
			allVulns = append(allVulns, nucleiVulns...)
		}
	}

	return allVulns
}

// checkCustomPaths uses httpx to check for exposed custom paths (e.g., /mcp, /debug)
func (s *Scanner) checkCustomPaths(scanType NucleiScanType, targetFile string) []Vulnerability {
	if !s.c.IsInstalled("httpx") {
		return nil
	}

	// Read hosts from target file
	content, err := os.ReadFile(targetFile)
	if err != nil {
		return nil
	}
	hosts := exec.Lines(string(content))
	if len(hosts) == 0 {
		return nil
	}

	// Generate URLs for all custom paths
	var pathURLs []string
	for _, host := range hosts {
		// Clean host
		cleanHost := strings.TrimPrefix(host, "http://")
		cleanHost = strings.TrimPrefix(cleanHost, "https://")
		cleanHost = strings.Split(cleanHost, "/")[0]

		for _, path := range scanType.CustomPaths {
			// Try both HTTP and HTTPS
			pathURLs = append(pathURLs, fmt.Sprintf("https://%s%s", cleanHost, path))
			pathURLs = append(pathURLs, fmt.Sprintf("http://%s%s", cleanHost, path))
		}
	}

	if len(pathURLs) == 0 {
		return nil
	}

	// Create temp file for path URLs
	tmpFile, cleanup, err := exec.TempFile(strings.Join(pathURLs, "\n"), "-custompaths.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// Use httpx to check which paths are accessible (2xx/3xx status)
	args := []string{
		"-l", tmpFile,
		"-mc", "200,201,202,301,302,307,308", // Only match successful responses
		"-json",
		"-silent",
		"-no-color",
	}
	if s.cfg.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", s.cfg.Threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}

	var vulns []Vulnerability
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			URL        string `json:"url"`
			StatusCode int    `json:"status_code"`
			Title      string `json:"title"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Found an accessible endpoint
		vulns = append(vulns, Vulnerability{
			URL:        entry.URL,
			TemplateID: fmt.Sprintf("custom-%s-exposure", strings.ToLower(scanType.Name)),
			Name:       fmt.Sprintf("%s Endpoint Exposed", scanType.Name),
			Severity:   "medium",
			Type:       "exposure",
			Description: fmt.Sprintf("%s - Exposed endpoint accessible without authentication (Status: %d)",
				scanType.Description, entry.StatusCode),
			Tool: "httpx-custom",
		})
	}

	if len(vulns) > 0 {
		fmt.Printf("        [CustomPaths] %s: Found %d exposed endpoints\n", scanType.Name, len(vulns))
	}

	return vulns
}

// runCRLFuzz runs CRLFuzz Go tool for CRLF injection detection
// CRLFuzz is faster and more specialized than nuclei for CRLF
func (s *Scanner) runCRLFuzz(urls []string) []Vulnerability {
	if !s.c.IsInstalled("crlfuzz") || len(urls) == 0 {
		return nil
	}

	fmt.Printf("        [CRLFuzz] Scanning %d URLs for CRLF injection...\n", len(urls))

	tmpFile, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-crlfuzz.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	args := []string{
		"-l", tmpFile,
		"-s", // Silent - only output vulnerable URLs
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}

	r := exec.Run("crlfuzz", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return nil
	}

	var vulns []Vulnerability
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		vulns = append(vulns, Vulnerability{
			URL:         line,
			TemplateID:  "crlfuzz-crlf",
			Name:        "CRLF Injection",
			Severity:    "medium",
			Type:        "crlf",
			Description: "CRLF injection vulnerability detected by CRLFuzz",
			Tool:        "crlfuzz",
		})
	}

	if len(vulns) > 0 {
		fmt.Printf("        [CRLFuzz] Found %d CRLF vulnerabilities\n", len(vulns))
	}

	return vulns
}

// runDNSTake runs DNSTake Go tool for DNS takeover detection
// DNSTake checks for dangling DNS records pointing to unclaimed resources
func (s *Scanner) runDNSTake(subdomains []string) []Vulnerability {
	if !s.c.IsInstalled("dnstake") || len(subdomains) == 0 {
		return nil
	}

	fmt.Printf("        [DNSTake] Scanning %d subdomains for DNS takeover...\n", len(subdomains))

	tmpFile, cleanup, err := exec.TempFile(strings.Join(subdomains, "\n"), "-dnstake.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	args := []string{
		"-l", tmpFile,
		"-s", // Silent
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}

	r := exec.Run("dnstake", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return nil
	}

	var vulns []Vulnerability
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		// DNSTake outputs vulnerable subdomains with status
		if strings.Contains(strings.ToLower(line), "vulnerable") {
			subdomain := line
			subdomain = strings.TrimPrefix(subdomain, "[VULNERABLE] ")
			subdomain = strings.TrimPrefix(subdomain, "[vulnerable] ")
			subdomain = strings.TrimSpace(subdomain)

			vulns = append(vulns, Vulnerability{
				Host:        subdomain,
				TemplateID:  "dnstake-takeover",
				Name:        "DNS Zone Takeover",
				Severity:    "critical",
				Type:        "dns-takeover",
				Description: "DNS zone is vulnerable to takeover - CNAME points to unregistered/unclaimed resource",
				Tool:        "dnstake",
			})
		}
	}

	if len(vulns) > 0 {
		fmt.Printf("        [DNSTake] Found %d DNS takeover vulnerabilities\n", len(vulns))
	}

	return vulns
}

// ScanWithParallel performs comprehensive vulnerability scanning with parallel nuclei scans
// This is the enhanced version that runs multiple nuclei scan types in parallel
func (s *Scanner) ScanWithParallel(hosts []string, urls []string, subdomains []string, categorizedURLs *historic.CategorizedURLs, techInput *TechInput) (*Result, error) {
	start := time.Now()

	// Get base result from standard scan
	result, err := s.ScanWithTech(hosts, categorizedURLs, techInput)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run parallel nuclei scans (CRLF, XXE, SSRF, DNS-Takeover, etc.)
	if s.c.IsInstalled("nuclei") && (len(hosts) > 0 || len(urls) > 0 || len(subdomains) > 0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := s.runParallelNucleiScans(hosts, urls, subdomains)
			if len(vulns) > 0 {
				mu.Lock()
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
				mu.Unlock()
			}
		}()
	}

	// Run CRLFuzz Go tool (faster than nuclei for CRLF)
	if s.c.IsInstalled("crlfuzz") && len(urls) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := s.runCRLFuzz(urls)
			if len(vulns) > 0 {
				mu.Lock()
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
				mu.Unlock()
			}
		}()
	}

	// Run DNSTake Go tool (specialized for DNS takeover)
	if s.c.IsInstalled("dnstake") && len(subdomains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := s.runDNSTake(subdomains)
			if len(vulns) > 0 {
				mu.Lock()
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Re-dedupe after adding parallel scan results
	seen := make(map[string]bool)
	var unique []Vulnerability
	result.BySeverity = make(map[string]int)
	result.ByType = make(map[string]int)

	for _, v := range result.Vulnerabilities {
		key := fmt.Sprintf("%s|%s|%s", v.URL, v.TemplateID, v.Tool)
		if v.URL == "" {
			key = fmt.Sprintf("%s|%s|%s", v.Host, v.TemplateID, v.Tool)
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
			result.BySeverity[v.Severity]++
			result.ByType[v.Type]++
		}
	}
	result.Vulnerabilities = unique
	result.Duration = time.Since(start)

	return result, nil
}

// GetParallelScanTypes returns all configured parallel nuclei scan types
func GetParallelScanTypes() []NucleiScanType {
	return nucleiParallelScanTypes
}
