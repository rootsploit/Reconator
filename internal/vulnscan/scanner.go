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

	wg.Wait()

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
		"-silent", "-jsonl",
		"-exclude-tags", "dos,fuzz",
		"-ss", "host-spray",
		"-mhe", "3",
		"-timeout", "5",
		"-duc",
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
		"-silent", "-jsonl",
		"-exclude-tags", "dos,fuzz",
		"-ss", "host-spray",
		"-mhe", "3",
		"-timeout", "5",
		"-duc",
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
		"-silent", "-jsonl",
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
