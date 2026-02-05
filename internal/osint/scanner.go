package osint

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	DorksFile   string   `json:"dorks_file"`
	NucleiOSINT []string `json:"nuclei_osint"`
}

type Scanner struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
}

func (s *Scanner) Scan(target string) (*Result, error) {
	if !s.cfg.EnableOSINT {
		return nil, nil
	}

	res := &Result{}

	// 1. Generate Google Dorks
	dorksFile, err := s.generateDorks(target)
	if err != nil {
		fmt.Printf("[-] Failed to generate dorks: %v\n", err)
	} else {
		res.DorksFile = dorksFile
	}

	// 2. Run Nuclei OSINT templates
	if s.c.IsInstalled("nuclei") {
		// Run headless for OSINT if possible, or just standard
		// Many OSINT templates in nuclei require APIs, but some scrape.
		// We'll try running with tags=osint
		// Note: Use with caution as this might be noisy or fail without keys.
		// We limit to specific safe categories or just let user configure keys in nuclei default config.

		// For now, we skip automated OSINT scan to strictly follow "without using any APIs" request reliability
		// as most effective Nuclei OSINT templates require keys (shodan, etc).
		// However, we can run 'tech-detect' style osint if available.

		// logic placeholder
	}

	return res, nil
}

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

	filename := filepath.Join(s.cfg.OutputDir, "google_dorks.md")
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
