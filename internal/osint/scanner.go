package osint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/tools"
)

// Scanner orchestrates all OSINT sub-modules
type Scanner struct {
	cfg    *config.Config
	c      *tools.Checker
	output string
}

// NewScanner creates a new OSINT scanner
func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
}

// isSilent returns true if silent mode is enabled
func (s *Scanner) isSilent() bool {
	return s.cfg != nil && s.cfg.Silent
}

// Scan runs all OSINT modules against the target domain
func (s *Scanner) Scan(target string) (*Result, error) {
	if !s.cfg.EnableOSINT {
		return nil, nil
	}

	start := time.Now()
	result := &Result{
		Target: target,
	}

	if !s.isSilent() {
		fmt.Printf("    [OSINT] Starting passive OSINT for %s\n", target)
	}

	// 1. WHOIS lookup
	if !s.isSilent() {
		fmt.Printf("    [OSINT] Running WHOIS lookup...\n")
	}
	whois, err := s.runWHOIS(target)
	if err != nil {
		if !s.isSilent() {
			fmt.Printf("    [OSINT] WHOIS failed: %v\n", err)
		}
	} else {
		result.WHOIS = whois
		if whois.OrgName != "" && !s.isSilent() {
			fmt.Printf("    [OSINT] WHOIS: Org=%s, Registrar=%s\n", whois.OrgName, whois.Registrar)
		}
	}

	// 2. ASN enrichment
	if !s.isSilent() {
		fmt.Printf("    [OSINT] Running ASN enrichment...\n")
	}
	asn, err := s.runASN(target)
	if err != nil {
		if !s.isSilent() {
			fmt.Printf("    [OSINT] ASN failed: %v\n", err)
		}
	} else {
		result.ASN = asn
		provider := asn.Provider
		if provider == "" {
			provider = asn.OrgName
		}
		if !s.isSilent() {
			fmt.Printf("    [OSINT] ASN: AS%d (%s), %d CIDRs\n", asn.ASN, provider, len(asn.CIDRs))
		}
	}

	// 3. Certificate Transparency
	if !s.isSilent() {
		fmt.Printf("    [OSINT] Querying Certificate Transparency logs...\n")
	}
	ctEntries, err := s.runCertTransparency(target)
	if err != nil {
		if !s.isSilent() {
			fmt.Printf("    [OSINT] CT failed: %v\n", err)
		}
	} else {
		result.CertTransparency = ctEntries
		subs := extractCTSubdomains(ctEntries, target)
		if !s.isSilent() {
			fmt.Printf("    [OSINT] CT: %d certificates, %d unique subdomains\n", len(ctEntries), len(subs))
		}
	}

	// 4. Related domain discovery
	if !s.isSilent() {
		fmt.Printf("    [OSINT] Discovering related domains...\n")
	}
	related := s.runRelatedDomains(target, result.WHOIS, result.ASN, result.CertTransparency)
	result.RelatedDomains = related
	if len(related) > 0 && !s.isSilent() {
		fmt.Printf("    [OSINT] Found %d related domains\n", len(related))
	}

	// 5. Breach data checks - DISABLED (requires HIBP API key)
	// fmt.Printf("    [OSINT] Checking breach databases...\n")
	// breaches, err := s.runBreachCheck(target)
	// if err != nil {
	// 	fmt.Printf("    [OSINT] Breach check failed: %v\n", err)
	// } else {
	// 	result.BreachData = breaches
	// 	if len(breaches) > 0 {
	// 		fmt.Printf("    [OSINT] Found %d known breaches\n", len(breaches))
	// 	}
	// }

	// 6. DNS Records (SPF, DMARC, DKIM, MX, NS)
	if !s.isSilent() {
		fmt.Printf("    [OSINT] Collecting DNS records...\n")
	}
	dnsRecords := runDNSRecords(target)
	result.DNSRecords = dnsRecords
	if dnsRecords != nil {
		dnsCount := len(dnsRecords.TXT) + len(dnsRecords.MX) + len(dnsRecords.NS) + len(dnsRecords.DKIM)
		if dnsRecords.SPF != "" {
			dnsCount++
		}
		if dnsRecords.DMARC != "" {
			dnsCount++
		}
		if !s.isSilent() {
			fmt.Printf("    [OSINT] DNS: %d records (SPF: %v, DMARC: %v, DKIM: %d selectors)\n",
				dnsCount, dnsRecords.SPF != "", dnsRecords.DMARC != "", len(dnsRecords.DKIM))
		}
	}

	// 7. Still generate Google Dorks (backward compat)
	dorksFile, err := s.generateDorks(target)
	if err == nil {
		result.DorksFile = dorksFile
	}

	result.Duration = time.Since(start)
	if !s.isSilent() {
		fmt.Printf("    [OSINT] Complete in %s\n", result.Duration.Round(time.Second))
	}

	return result, nil
}

// SetOutput sets the output directory for saving results
func (s *Scanner) SetOutput(dir string) {
	s.output = dir
}

// SaveResults saves OSINT results to JSON and markdown files
func (s *Scanner) SaveResults(result *Result, outputDir string) error {
	if result == nil {
		return nil
	}

	// Create osint subdirectory
	osintDir := filepath.Join(outputDir, "osint")
	if err := os.MkdirAll(osintDir, 0755); err != nil {
		return fmt.Errorf("create osint dir: %w", err)
	}

	// Save JSON
	jsonPath := filepath.Join(osintDir, "osint_results.json")
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal OSINT results: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("write OSINT JSON: %w", err)
	}

	// Save markdown summary
	mdPath := filepath.Join(osintDir, "osint_summary.md")
	md := s.generateMarkdown(result)
	if err := os.WriteFile(mdPath, []byte(md), 0644); err != nil {
		return fmt.Errorf("write OSINT markdown: %w", err)
	}

	return nil
}

func (s *Scanner) generateMarkdown(result *Result) string {
	mb := &markdownBuilder{}

	mb.writef("# OSINT Report for %s\n\n", result.Target)
	mb.writef("_Generated in %s_\n\n", result.Duration.Round(time.Second))

	// WHOIS
	if result.WHOIS != nil {
		mb.writef("## WHOIS Information\n\n")
		mb.writef("| Field | Value |\n|-------|-------|\n")
		mb.writef("| Registrar | %s |\n", result.WHOIS.Registrar)
		mb.writef("| Organization | %s |\n", result.WHOIS.OrgName)
		mb.writef("| Created | %s |\n", result.WHOIS.CreatedDate)
		mb.writef("| Expires | %s |\n", result.WHOIS.ExpiryDate)
		mb.writef("| Country | %s |\n", result.WHOIS.Country)
		if len(result.WHOIS.Emails) > 0 {
			mb.writef("| Emails | %s |\n", joinStrings(result.WHOIS.Emails))
		}
		if len(result.WHOIS.NameServers) > 0 {
			mb.writef("| Nameservers | %s |\n", joinStrings(result.WHOIS.NameServers))
		}
		mb.writef("\n")
	}

	// ASN
	if result.ASN != nil {
		mb.writef("## ASN Information\n\n")
		mb.writef("| Field | Value |\n|-------|-------|\n")
		mb.writef("| ASN | AS%d |\n", result.ASN.ASN)
		mb.writef("| Organization | %s |\n", result.ASN.OrgName)
		if result.ASN.Provider != "" {
			mb.writef("| Cloud Provider | %s |\n", result.ASN.Provider)
		}
		mb.writef("| Country | %s |\n", result.ASN.Country)
		mb.writef("| CIDRs | %d prefixes |\n", len(result.ASN.CIDRs))
		mb.writef("\n")
	}

	// CT Logs
	if len(result.CertTransparency) > 0 {
		mb.writef("## Certificate Transparency (%d entries)\n\n", len(result.CertTransparency))
		mb.writef("| Domain | Issuer | Valid From | Valid To |\n|--------|--------|-----------|----------|\n")
		limit := 30
		if len(result.CertTransparency) < limit {
			limit = len(result.CertTransparency)
		}
		for _, ct := range result.CertTransparency[:limit] {
			mb.writef("| %s | %s | %s | %s |\n", ct.Domain, truncate(ct.Issuer, 30), ct.NotBefore, ct.NotAfter)
		}
		if len(result.CertTransparency) > 30 {
			mb.writef("\n_...and %d more entries_\n", len(result.CertTransparency)-30)
		}
		mb.writef("\n")
	}

	// Related Domains
	if len(result.RelatedDomains) > 0 {
		mb.writef("## Related Domains (%d found)\n\n", len(result.RelatedDomains))
		mb.writef("| Domain | Relation | Confidence | Source |\n|--------|----------|-----------|--------|\n")
		for _, rd := range result.RelatedDomains {
			mb.writef("| %s | %s | %.0f%% | %s |\n", rd.Domain, rd.Relation, rd.Confidence*100, rd.Source)
		}
		mb.writef("\n")
	}

	// Breaches
	if len(result.BreachData) > 0 {
		mb.writef("## Known Breaches (%d found)\n\n", len(result.BreachData))
		for _, b := range result.BreachData {
			mb.writef("### %s\n", b.Name)
			mb.writef("- **Date:** %s\n", b.BreachDate)
			mb.writef("- **Records:** %d\n", b.RecordCount)
			if len(b.DataClasses) > 0 {
				mb.writef("- **Data:** %s\n", joinStrings(b.DataClasses))
			}
			mb.writef("\n")
		}
	}

	// DNS Records
	if result.DNSRecords != nil {
		dns := result.DNSRecords
		mb.writef("## DNS Records\n\n")

		mb.writef("### Email Security\n\n")
		if dns.SPF != "" {
			mb.writef("- **SPF:** `%s`\n", dns.SPF)
		} else {
			mb.writef("- **SPF:** ⚠ Not configured\n")
		}
		if dns.DMARC != "" {
			mb.writef("- **DMARC:** `%s`\n", dns.DMARC)
		} else {
			mb.writef("- **DMARC:** ⚠ Not configured\n")
		}
		if len(dns.DKIM) > 0 {
			mb.writef("- **DKIM:** %d selector(s) found\n", len(dns.DKIM))
			for _, d := range dns.DKIM {
				mb.writef("  - `%s`\n", d)
			}
		} else {
			mb.writef("- **DKIM:** No selectors found (checked common selectors)\n")
		}
		mb.writef("\n")

		if len(dns.MX) > 0 {
			mb.writef("### MX Records\n\n")
			for _, mx := range dns.MX {
				mb.writef("- %s\n", mx)
			}
			mb.writef("\n")
		}
		if len(dns.NS) > 0 {
			mb.writef("### NS Records\n\n")
			for _, ns := range dns.NS {
				mb.writef("- %s\n", ns)
			}
			mb.writef("\n")
		}
		if len(dns.TXT) > 0 {
			mb.writef("### All TXT Records\n\n")
			for _, txt := range dns.TXT {
				mb.writef("- `%s`\n", txt)
			}
			mb.writef("\n")
		}
	}

	return mb.String()
}

// generateDorks creates the Google Dorks markdown file (backward compat)
func (s *Scanner) generateDorks(domain string) (string, error) {
	dorks := []struct {
		Title string
		Query string
	}{
		{"Publicly Exposed Documents", "site:%s ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"},
		{"Directory Listing Vulnerabilities", "site:%s intitle:index.of"},
		{"Configuration Files", "site:%s ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini"},
		{"Database Files", "site:%s ext:sql | ext:dbf | ext:mdb"},
		{"Log Files", "site:%s ext:log"},
		{"Backup and Old Files", "site:%s ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"},
		{"Login Pages", "site:%s inurl:login | inurl:signin | intitle:Login | intitle:\"sign in\" | inurl:auth"},
		{"SQL Errors", "site:%s intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\""},
		{"PHP Errors", "site:%s \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\""},
		{"Wordpress", "site:%s inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download"},
		{"Project Management", "site:%s inurl:jira | inurl:confluence | inurl:trello | inurl:slack"},
		{"Git Folders", "site:%s inurl:\"/.git\" intitle:\"Index of /\""},
		{"Pastebin Leaks", "site:pastebin.com \"%s\""},
		{"Github Leaks", "site:github.com \"%s\""},
		{"StackOverflow Leaks", "site:stackoverflow.com \"%s\""},
	}

	if s.output == "" {
		s.output = s.cfg.OutputDir
	}

	filename := filepath.Join(s.output, "google_dorks.md")
	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	f.WriteString(fmt.Sprintf("# Google Dorks for %s\n\n", domain))
	f.WriteString("Click on the links to search Google:\n\n")

	for _, dork := range dorks {
		query := fmt.Sprintf(dork.Query, domain)
		encoded := url.QueryEscape(query)
		link := fmt.Sprintf("https://www.google.com/search?q=%s", encoded)
		f.WriteString(fmt.Sprintf("### %s\n[%s](%s)\n\n", dork.Title, query, link))
	}

	return filename, nil
}

// Helper types and functions

type markdownBuilder struct {
	content string
}

func (mb *markdownBuilder) writef(format string, args ...interface{}) {
	mb.content += fmt.Sprintf(format, args...)
}

func (mb *markdownBuilder) String() string {
	return mb.content
}

func joinStrings(s []string) string {
	result := ""
	for i, v := range s {
		if i > 0 {
			result += ", "
		}
		result += v
	}
	return result
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
