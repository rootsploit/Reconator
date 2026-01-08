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
	Domain              string         `json:"domain"`
	URLs                []string       `json:"urls"`
	ExtractedSubdomains []string       `json:"extracted_subdomains"` // Subdomains extracted from URLs
	Total               int            `json:"total"`
	Sources             map[string]int `json:"sources"`
	Duration            time.Duration  `json:"duration"`
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

	if len(aliveHosts) > 0 && c.c.IsInstalled("katana") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"katana", func(_ string) []string { return c.katana(aliveHosts) }})
	}

	if c.cfg.UseOptional && c.c.IsInstalled("waymore") {
		tools = append(tools, struct {
			name string
			fn   func(string) []string
		}{"waymore", c.waymore})
	}

	fmt.Println("    [*] Collecting historic URLs...")

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

	// Extract subdomains from collected URLs
	extractedSubs := extractSubdomainsFromURLs(domain, all)
	fmt.Printf("        extracted_subdomains: %d\n", len(extractedSubs))

	result.URLs = all
	result.ExtractedSubdomains = extractedSubs
	result.Total = len(all)
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
	r := exec.Run("gau", []string{"--subs", "--providers", "wayback,commoncrawl,otx,urlscan", domain}, &exec.Options{Timeout: 5 * time.Minute})
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
	args := []string{"-list", tmp, "-silent", "-jc", "-kf", "all", "-d", "2"}
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
		for _, p := range patterns {
			if strings.Contains(strings.ToLower(u), p) {
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
