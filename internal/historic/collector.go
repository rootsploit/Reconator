package historic

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	Domain              string            `json:"domain"`
	URLs                []string          `json:"urls"`
	ExtractedSubdomains []string          `json:"extracted_subdomains"` // Subdomains extracted from URLs
	Total               int               `json:"total"`
	Sources             map[string]int    `json:"sources"`
	Duration            time.Duration     `json:"duration"`
	// Categorized URLs for vulnerability scanning
	Categorized CategorizedURLs `json:"categorized,omitempty"`
}

// CategorizedURLs holds URLs filtered by potential vulnerability type
type CategorizedURLs struct {
	XSS       []string `json:"xss,omitempty"`
	SQLi      []string `json:"sqli,omitempty"`
	SSRF      []string `json:"ssrf,omitempty"`
	LFI       []string `json:"lfi,omitempty"`
	RCE       []string `json:"rce,omitempty"`
	SSTI      []string `json:"ssti,omitempty"`
	Redirect  []string `json:"redirect,omitempty"`
	Debug     []string `json:"debug,omitempty"`
	JSFiles   []string `json:"js_files,omitempty"`
	APIFiles  []string `json:"api_files,omitempty"`
	Sensitive []string `json:"sensitive,omitempty"` // admin, auth, api, etc.
}

type Collector struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewCollector(cfg *config.Config, checker *tools.Checker) *Collector {
	return &Collector{cfg: cfg, c: checker}
}

func (c *Collector) Collect(domain string, aliveHosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{Domain: domain, Sources: make(map[string]int)}

	var urls sync.Map
	var wg sync.WaitGroup
	var mu sync.Mutex

	tools := []struct {
		name string
		fn   func(string) []string
	}{
		{"waybackurls", c.waybackurls},
		{"gau", c.gau},
	}

	// urlfinder is passive (queries archives) - always use it
	if c.c.IsInstalled("urlfinder") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"urlfinder", c.urlfinder})
	}

	// katana is active (crawls websites) - skip in passive mode
	if !c.cfg.PassiveMode && len(aliveHosts) > 0 && c.c.IsInstalled("katana") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"katana", func(_ string) []string { return c.katana(aliveHosts) }})
	}

	// waymore is now included by default (not optional)
	if c.c.IsInstalled("waymore") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"waymore", c.waymore})
	}

	fmt.Println("    [*] Collecting historic URLs...")
	if c.cfg.PassiveMode {
		fmt.Println("    [PASSIVE] Using passive sources only (skipping katana)")
	}

	for _, t := range tools {
		wg.Add(1)
		go func(name string, fn func(string) []string) {
			defer wg.Done()
			res := fn(domain)
			mu.Lock()
			result.Sources[name] = len(res)
			mu.Unlock()
			for _, u := range res {
				urls.Store(u, true)
			}
			fmt.Printf("        %s: %d URLs\n", name, len(res))
		}(t.name, t.fn)
	}
	wg.Wait()

	var all []string
	urls.Range(func(k, _ interface{}) bool {
		if u := k.(string); strings.Contains(u, domain) {
			all = append(all, u)
		}
		return true
	})
	sort.Strings(all)

	// BB-7: Deduplicate similar URLs using uro (can reduce 84% duplicates)
	if c.c.IsInstalled("uro") && len(all) > 0 {
		originalCount := len(all)
		all = c.deduplicateWithUro(all)
		reduction := float64(originalCount-len(all)) / float64(originalCount) * 100
		fmt.Printf("        uro dedup: %d → %d URLs (%.1f%% reduction)\n", originalCount, len(all), reduction)
	}

	// Extract subdomains from collected URLs
	extractedSubs := extractSubdomainsFromURLs(domain, all)
	fmt.Printf("        extracted_subdomains: %d\n", len(extractedSubs))

	result.URLs = all
	result.ExtractedSubdomains = extractedSubs
	result.Total = len(all)

	// Categorize URLs for vulnerability scanning
	result.Categorized = c.CategorizeURLs(all)
	fmt.Printf("        categorized: XSS=%d SQLi=%d SSRF=%d LFI=%d JS=%d Sensitive=%d\n",
		len(result.Categorized.XSS), len(result.Categorized.SQLi),
		len(result.Categorized.SSRF), len(result.Categorized.LFI),
		len(result.Categorized.JSFiles), len(result.Categorized.Sensitive))

	result.Duration = time.Since(start)
	return result, nil
}

func (c *Collector) waybackurls(domain string) []string {
	if !c.c.IsInstalled("waybackurls") {
		return nil
	}
	r := exec.RunWithInput("waybackurls", nil, domain+"\n", &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return filterURLs(r.Stdout)
}

func (c *Collector) gau(domain string) []string {
	if !c.c.IsInstalled("gau") {
		return nil
	}
	// BB-2: Enhanced gau flags for better performance
	// --threads: Parallel fetching (2-3x faster)
	// --blacklist: Skip static files (reduces noise by ~40%)
	args := []string{
		"--subs",
		"--providers", "wayback,commoncrawl,otx,urlscan",
		"--threads", "20",
		"--blacklist", "png,jpg,jpeg,gif,css,woff,woff2,ttf,svg,ico,eot,mp4,mp3,webp,pdf",
		domain,
	}
	r := exec.Run("gau", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return filterURLs(r.Stdout)
}

func (c *Collector) urlfinder(domain string) []string {
	if !c.c.IsInstalled("urlfinder") {
		return nil
	}
	// urlfinder queries passive sources (wayback, commoncrawl, etc.) - no active crawling
	args := []string{"-d", domain, "-silent", "-all"}
	r := exec.Run("urlfinder", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return filterURLs(r.Stdout)
}

func (c *Collector) katana(hosts []string) []string {
	if !c.c.IsInstalled("katana") || len(hosts) == 0 {
		return nil
	}
	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), ".txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// BB-3: Enhanced katana flags for better coverage
	// -d 3: Increase depth (was 2) to find more endpoints
	// -f qurl: Filter to URLs with query params (valuable for vuln testing)
	// -em: Exclude wasteful paths like logout/reset
	args := []string{
		"-list", tmp,
		"-silent",
		"-jc",                                            // JavaScript crawling
		"-kf", "all",                                     // Known file extensions
		"-d", "3",                                        // BB-3: Increased depth
		"-ef", "logout,signout,reset,unsubscribe,delete", // BB-3: Exclude useless forms
	}

	if c.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", c.cfg.Threads))
	} else {
		args = append(args, "-c", "10")
	}

	r := exec.Run("katana", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return nil
	}
	return filterURLs(r.Stdout)
}

// RunKatana is a public method to run katana crawling on alive hosts
// Called separately after port scanning provides alive hosts
// NOTE: Since Historic now runs at Level 0 (parallel with Subdomain), katana is skipped there.
// This method allows VulnScan or other phases to run katana later when alive hosts are available.
func (c *Collector) RunKatana(aliveHosts []string) []string {
	if !c.c.IsInstalled("katana") || len(aliveHosts) == 0 {
		return nil
	}
	fmt.Println("    [*] Running katana (active crawling)...")
	return c.katana(aliveHosts)
}

// RunKatanaAndMerge runs katana on alive hosts and merges results with existing URLs
// Returns merged URLs, categorized URLs, and extracted subdomains
func (c *Collector) RunKatanaAndMerge(aliveHosts []string, existingURLs []string, domain string) ([]string, CategorizedURLs, []string) {
	// Run katana
	katanaURLs := c.RunKatana(aliveHosts)
	if len(katanaURLs) == 0 {
		return existingURLs, c.CategorizeURLs(existingURLs), extractSubdomainsFromURLs(domain, existingURLs)
	}

	fmt.Printf("        katana: %d URLs\n", len(katanaURLs))

	// Merge with existing
	urlSet := make(map[string]bool)
	for _, u := range existingURLs {
		urlSet[u] = true
	}
	for _, u := range katanaURLs {
		urlSet[u] = true
	}

	var merged []string
	for u := range urlSet {
		merged = append(merged, u)
	}

	// Deduplicate with uro if available
	if c.c.IsInstalled("uro") && len(merged) > 0 {
		originalCount := len(merged)
		merged = c.deduplicateWithUro(merged)
		reduction := float64(originalCount-len(merged)) / float64(originalCount) * 100
		fmt.Printf("        uro dedup (with katana): %d → %d URLs (%.1f%% reduction)\n", originalCount, len(merged), reduction)
	}

	categorized := c.CategorizeURLs(merged)
	extracted := extractSubdomainsFromURLs(domain, merged)

	return merged, categorized, extracted
}

func (c *Collector) waymore(domain string) []string {
	if !c.c.IsInstalled("waymore") {
		return nil
	}
	dir, err := os.MkdirTemp("", "waymore-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(dir)
	// Reduced timeout - waymore can be very slow
	exec.Run("waymore", []string{"-i", domain, "-mode", "U", "-oU", dir + "/urls.txt", "-n"}, &exec.Options{Timeout: 3 * time.Minute})
	urls, _ := exec.ReadLines(dir + "/urls.txt")
	return urls
}

// BB-7: deduplicateWithUro uses uro to remove similar/duplicate URL patterns
// uro removes URLs with same base but different parameter values, keeping unique patterns
// Example: /page?id=1, /page?id=2, /page?id=3 → /page?id=1 (one representative)
func (c *Collector) deduplicateWithUro(urls []string) []string {
	if len(urls) == 0 {
		return urls
	}

	// Create temp file with URLs
	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-urls-for-uro.txt")
	if err != nil {
		return urls // Return original on error
	}
	defer cleanup()

	// Run uro: cat urls.txt | uro
	r := exec.Run("sh", []string{"-c", fmt.Sprintf("cat %s | uro", tmp)}, &exec.Options{Timeout: 2 * time.Minute})
	if r.Error != nil {
		return urls // Return original on error
	}

	var deduped []string
	for _, line := range exec.Lines(r.Stdout) {
		if line != "" && strings.HasPrefix(line, "http") {
			deduped = append(deduped, line)
		}
	}

	// Safety check - if uro returned nothing, use original
	if len(deduped) == 0 {
		return urls
	}

	return deduped
}

func filterURLs(output string) []string {
	seen := make(map[string]bool)
	var urls []string
	for _, line := range exec.Lines(output) {
		if strings.HasPrefix(line, "http") && !seen[line] {
			seen[line] = true
			urls = append(urls, line)
		}
	}
	return urls
}

// extractSubdomainsFromURLs extracts unique subdomains from a list of URLs
func extractSubdomainsFromURLs(domain string, urls []string) []string {
	seen := make(map[string]bool)
	suffix := "." + domain

	for _, u := range urls {
		// Strip protocol
		u = strings.TrimPrefix(u, "http://")
		u = strings.TrimPrefix(u, "https://")
		// Get host part
		if idx := strings.Index(u, "/"); idx > 0 {
			u = u[:idx]
		}
		// Remove port
		if idx := strings.Index(u, ":"); idx > 0 {
			u = u[:idx]
		}
		u = strings.ToLower(strings.TrimSpace(u))
		// Validate it's a subdomain of target
		if (strings.HasSuffix(u, suffix) || u == domain) && !seen[u] {
			seen[u] = true
		}
	}

	var result []string
	for s := range seen {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

func FilterInteresting(urls []string) []string {
	patterns := []string{".json", ".xml", ".yaml", "/api/", "/v1/", "/v2/", "/admin", "/login", "/auth", "/graphql", ".env", ".git", "swagger", "?"}
	var out []string
	for _, u := range urls {
		lower := strings.ToLower(u)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				out = append(out, u)
				break
			}
		}
	}
	return out
}

func ExtractEndpoints(urls []string) []string {
	eps := make(map[string]bool)
	for _, u := range urls {
		if i := strings.Index(u, "?"); i != -1 {
			u = u[:i]
		}
		u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
		if i := strings.Index(u, "/"); i != -1 {
			eps[u[i:]] = true
		}
	}
	var out []string
	for e := range eps {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// CategorizeURLs categorizes URLs based on gf-like patterns for vulnerability scanning
func (c *Collector) CategorizeURLs(urls []string) CategorizedURLs {
	cat := CategorizedURLs{}

	// Check if gf is the REAL gf tool (not aliased to git fetch)
	// Test by running "gf -h" which should show gf help, not git fetch help
	gfWorks := false
	if c.c.IsInstalled("gf") {
		r := exec.Run("gf", []string{"-h"}, &exec.Options{Timeout: 5 * time.Second})
		// Real gf shows "Usage: gf" or pattern-related help
		// git fetch shows "usage: git fetch"
		gfWorks = r.Error == nil && !strings.Contains(r.Stdout, "git fetch") && !strings.Contains(r.Stderr, "git fetch")
		if !gfWorks {
			fmt.Println("        [Historic] gf tool not available (may be aliased), using built-in patterns")
		}
	}

	// Use gf tool if available AND working for better pattern matching
	useBuiltinPatterns := true
	if gfWorks && len(urls) > 0 {
		// Create single temp file for all gf patterns (efficiency optimization)
		tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-urls.txt")
		if err == nil {
			defer cleanup()

			// OPTIMIZATION: Run all gf patterns in parallel instead of sequential
			// This reduces 8 × 2-5s = 16-40s → ~5s (parallel execution)
			var wg sync.WaitGroup
			var mu sync.Mutex

			patterns := []struct {
				name    string
				pattern string
				dest    *[]string
			}{
				{"xss", "xss", &cat.XSS},
				{"sqli", "sqli", &cat.SQLi},
				{"ssrf", "ssrf", &cat.SSRF},
				{"lfi", "lfi", &cat.LFI},
				{"rce", "rce", &cat.RCE},
				{"ssti", "ssti", &cat.SSTI},
				{"redirect", "redirect", &cat.Redirect},
				{"debug", "debug_logic", &cat.Debug},
			}

			for _, p := range patterns {
				wg.Add(1)
				go func(pattern string, dest *[]string) {
					defer wg.Done()
					result := c.runGFWithFile(tmp, pattern)
					mu.Lock()
					*dest = result
					mu.Unlock()
				}(p.pattern, p.dest)
			}

			wg.Wait()

			// Check if gf returned any results - if ALL are empty, fall back to built-in
			totalFound := len(cat.XSS) + len(cat.SQLi) + len(cat.SSRF) + len(cat.LFI) +
				len(cat.RCE) + len(cat.SSTI) + len(cat.Redirect) + len(cat.Debug)
			if totalFound > 0 {
				useBuiltinPatterns = false
				fmt.Printf("        [Historic] gf categorized: XSS=%d SQLi=%d SSRF=%d LFI=%d RCE=%d SSTI=%d Redirect=%d Debug=%d\n",
					len(cat.XSS), len(cat.SQLi), len(cat.SSRF), len(cat.LFI),
					len(cat.RCE), len(cat.SSTI), len(cat.Redirect), len(cat.Debug))
			} else {
				fmt.Println("        [Historic] gf returned no results, falling back to built-in patterns")
			}
		}
	}

	// Use built-in pattern matching if gf isn't available or returned nothing
	if useBuiltinPatterns && len(urls) > 0 {
		cat.XSS = filterByPatterns(urls, xssPatterns)
		cat.SQLi = filterByPatterns(urls, sqliPatterns)
		cat.SSRF = filterByPatterns(urls, ssrfPatterns)
		cat.LFI = filterByPatterns(urls, lfiPatterns)
		cat.RCE = filterByPatterns(urls, rcePatterns)
		cat.SSTI = filterByPatterns(urls, sstiPatterns)
		cat.Redirect = filterByPatterns(urls, redirectPatterns)
		cat.Debug = filterByPatterns(urls, debugPatterns)
		fmt.Printf("        [Historic] built-in patterns: XSS=%d SQLi=%d SSRF=%d LFI=%d RCE=%d SSTI=%d Redirect=%d Debug=%d\n",
			len(cat.XSS), len(cat.SQLi), len(cat.SSRF), len(cat.LFI),
			len(cat.RCE), len(cat.SSTI), len(cat.Redirect), len(cat.Debug))
	}

	// These don't need gf - simple file extension/path matching
	cat.JSFiles = filterByExtensions(urls, []string{".js", ".mjs"})
	cat.APIFiles = filterByPatterns(urls, apiPatterns)
	cat.Sensitive = filterByPatterns(urls, sensitivePatterns)

	return cat
}

// runGFWithFile runs gf with a specific pattern using an existing temp file
func (c *Collector) runGFWithFile(tempFile, pattern string) []string {
	// cat urls.txt | gf pattern
	r := exec.Run("sh", []string{"-c", fmt.Sprintf("cat %s | gf %s", tempFile, pattern)}, &exec.Options{Timeout: 1 * time.Minute})
	if r.Error != nil {
		return nil
	}

	var results []string
	for _, line := range exec.Lines(r.Stdout) {
		if line != "" {
			results = append(results, line)
		}
	}
	return results
}

// Pattern definitions for built-in matching (fallback when gf not installed)
var xssPatterns = []string{
	"q=", "s=", "search=", "query=", "keyword=", "lang=", "id=",
	"page=", "view=", "name=", "content=", "message=", "comment=",
	"url=", "redirect=", "rurl=", "return=", "next=", "dest=",
	"callback=", "jsonp=", "html=", "text=", "body=", "title=",
}

var sqliPatterns = []string{
	"id=", "page=", "cat=", "category=", "item=", "product=",
	"pid=", "uid=", "user=", "order=", "sort=", "num=", "type=",
	"select=", "from=", "where=", "table=", "column=", "report=",
}

var ssrfPatterns = []string{
	"url=", "uri=", "path=", "dest=", "redirect=", "target=",
	"fetch=", "file=", "document=", "domain=", "host=", "site=",
	"proxy=", "remote=", "load=", "download=", "img=", "image=",
	"source=", "src=", "href=", "link=", "callback=", "return=",
}

var lfiPatterns = []string{
	"file=", "document=", "folder=", "root=", "path=", "pg=",
	"style=", "pdf=", "template=", "php_path=", "doc=", "page=",
	"name=", "cat=", "dir=", "action=", "board=", "date=",
	"detail=", "download=", "inc=", "include=", "locate=",
}

var rcePatterns = []string{
	"cmd=", "exec=", "command=", "execute=", "ping=", "query=",
	"code=", "reg=", "do=", "func=", "arg=", "option=", "load=",
	"process=", "step=", "read=", "function=", "req=", "feature=",
	"email=", "daemon=", "upload=", "dir=", "log=", "ip=", "cli=",
}

var sstiPatterns = []string{
	"template=", "page=", "id=", "name=", "content=", "view=",
	"msg=", "message=", "text=", "render=", "preview=", "email=",
}

var redirectPatterns = []string{
	"next=", "url=", "target=", "rurl=", "dest=", "destination=",
	"redir=", "redirect_uri=", "redirect_url=", "redirect=",
	"out=", "view=", "to=", "image_url=", "go=", "return=",
	"returnTo=", "return_to=", "checkout_url=", "continue=",
	"return_path=", "success=", "data=", "reference=", "site=",
}

var debugPatterns = []string{
	"debug=", "test=", "admin=", "mode=", "env=", "dev=",
	"trace=", "log=", "verbose=", "level=",
}

var apiPatterns = []string{
	"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
	".json", ".xml", "/swagger", "/openapi", "/oauth",
}

var sensitivePatterns = []string{
	"/admin", "/login", "/auth", "/config", "/debug", "/backup",
	"/db", "/database", "/phpmyadmin", "/wp-admin", "/dashboard",
	"/console", "/manage", "/management", "/api/", "/internal",
	".env", ".git", ".svn", ".htaccess", ".htpasswd", "web.config",
}

// filterByPatterns filters URLs containing any of the given patterns
func filterByPatterns(urls []string, patterns []string) []string {
	seen := make(map[string]bool)
	var results []string
	for _, u := range urls {
		lower := strings.ToLower(u)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				if !seen[u] {
					seen[u] = true
					results = append(results, u)
				}
				break
			}
		}
	}
	return results
}

// filterByExtensions filters URLs by file extension
func filterByExtensions(urls []string, extensions []string) []string {
	seen := make(map[string]bool)
	var results []string
	for _, u := range urls {
		// Remove query string
		path := u
		if idx := strings.Index(u, "?"); idx > 0 {
			path = u[:idx]
		}
		lower := strings.ToLower(path)
		for _, ext := range extensions {
			if strings.HasSuffix(lower, ext) {
				if !seen[u] {
					seen[u] = true
					results = append(results, u)
				}
				break
			}
		}
	}
	return results
}
