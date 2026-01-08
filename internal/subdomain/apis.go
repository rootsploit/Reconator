package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// APIEnumerator handles 3rd party API subdomain enumeration
type APIEnumerator struct {
	client  *http.Client
	domain  string
	results sync.Map
	wg      sync.WaitGroup
}

// NewAPIEnumerator creates a new API enumerator
func NewAPIEnumerator(domain string) *APIEnumerator {
	return &APIEnumerator{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		domain: domain,
	}
}

// Enumerate runs all API sources in parallel and returns unique subdomains
func (a *APIEnumerator) Enumerate() ([]string, map[string]int) {
	sources := map[string]int{}

	// Run all API sources in parallel
	apis := []struct {
		name string
		fn   func() []string
	}{
		{"crtsh", a.crtsh},
		{"hackertarget", a.hackertarget},
		{"urlscan", a.urlscan},
		{"alienvault", a.alienvault},
		{"anubisdb", a.anubisdb},
		{"certspotter", a.certspotter},
		{"rapiddns", a.rapiddns},
		{"webarchive", a.webarchive},
		{"commoncrawl", a.commoncrawl},
		{"threatminer", a.threatminer},
	}

	var mu sync.Mutex
	for _, api := range apis {
		a.wg.Add(1)
		go func(name string, fn func() []string) {
			defer a.wg.Done()
			subs := fn()
			mu.Lock()
			sources[name] = len(subs)
			mu.Unlock()
			for _, s := range subs {
				a.results.Store(s, true)
			}
		}(api.name, api.fn)
	}

	a.wg.Wait()

	// Collect unique results
	var unique []string
	a.results.Range(func(k, _ interface{}) bool {
		if s, ok := k.(string); ok {
			if a.isValidSubdomain(s) {
				unique = append(unique, s)
			}
		}
		return true
	})

	return unique, sources
}

// isValidSubdomain checks if a string is a valid subdomain of the target
func (a *APIEnumerator) isValidSubdomain(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, "www.")

	if s == "" || s == a.domain {
		return false
	}

	// Must end with .domain
	if !strings.HasSuffix(s, "."+a.domain) && s != a.domain {
		return false
	}

	// No spaces or invalid chars
	if strings.ContainsAny(s, " \t\n\r") {
		return false
	}

	return true
}

// extractSubdomains extracts subdomains from text using regex
func (a *APIEnumerator) extractSubdomains(text string) []string {
	pattern := fmt.Sprintf(`[a-zA-Z0-9][-a-zA-Z0-9._]*\.%s`, regexp.QuoteMeta(a.domain))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(text, -1)

	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		m = strings.ToLower(m)
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}

// fetch makes HTTP GET request and returns body
func (a *APIEnumerator) fetch(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; reconator/1.0)")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// crtsh queries Certificate Transparency logs (levels 1-6 depth)
func (a *APIEnumerator) crtsh() []string {
	var all []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Query levels 1-6 in parallel for speed
	depths := []string{
		fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", a.domain),         // level 1: %.domain
		fmt.Sprintf("https://crt.sh/?q=%%.%%.%s&output=json", a.domain),      // level 2: %.%.domain
		fmt.Sprintf("https://crt.sh/?q=%%.%%.%%.%s&output=json", a.domain),   // level 3: %.%.%.domain
		fmt.Sprintf("https://crt.sh/?q=%%.%%.%%.%%.%s&output=json", a.domain), // level 4
		fmt.Sprintf("https://crt.sh/?q=%%.%%.%%.%%.%%.%s&output=json", a.domain), // level 5
		fmt.Sprintf("https://crt.sh/?q=%%.%%.%%.%%.%%.%%.%s&output=json", a.domain), // level 6
	}

	for _, url := range depths {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			body, err := a.fetch(u)
			if err != nil {
				return
			}

			var entries []struct {
				NameValue string `json:"name_value"`
			}
			if json.Unmarshal([]byte(body), &entries) == nil {
				mu.Lock()
				for _, e := range entries {
					for _, name := range strings.Split(e.NameValue, "\n") {
						name = strings.TrimPrefix(name, "*.")
						if a.isValidSubdomain(name) {
							all = append(all, name)
						}
					}
				}
				mu.Unlock()
			}
		}(url)
	}

	wg.Wait()
	return a.dedupe(all)
}

// hackertarget queries HackerTarget API
func (a *APIEnumerator) hackertarget() []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}

	var result []string
	for _, line := range strings.Split(body, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			sub := strings.TrimSpace(parts[0])
			if a.isValidSubdomain(sub) {
				result = append(result, sub)
			}
		}
	}
	return result
}

// urlscan queries URLScan.io API
func (a *APIEnumerator) urlscan() []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}
	return a.extractSubdomains(body)
}

// alienvault queries AlienVault OTX API
func (a *APIEnumerator) alienvault() []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}

	var response struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	if json.Unmarshal([]byte(body), &response) != nil {
		return a.extractSubdomains(body)
	}

	var result []string
	for _, entry := range response.PassiveDNS {
		if a.isValidSubdomain(entry.Hostname) {
			result = append(result, entry.Hostname)
		}
	}
	return result
}

// anubisdb queries AnubisDB API
func (a *APIEnumerator) anubisdb() []string {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}

	var subs []string
	if json.Unmarshal([]byte(body), &subs) != nil {
		return nil
	}

	var result []string
	for _, s := range subs {
		if a.isValidSubdomain(s) {
			result = append(result, s)
		}
	}
	return result
}

// certspotter queries CertSpotter API
func (a *APIEnumerator) certspotter() []string {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}

	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}

	if json.Unmarshal([]byte(body), &entries) != nil {
		return a.extractSubdomains(body)
	}

	var result []string
	for _, entry := range entries {
		for _, name := range entry.DNSNames {
			name = strings.TrimPrefix(name, "*.")
			if a.isValidSubdomain(name) {
				result = append(result, name)
			}
		}
	}
	return a.dedupe(result)
}

// rapiddns queries RapidDNS
func (a *APIEnumerator) rapiddns() []string {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}
	return a.extractSubdomains(body)
}

// webarchive queries Web Archive CDX API
func (a *APIEnumerator) webarchive() []string {
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=5000", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}

	var entries [][]string
	if json.Unmarshal([]byte(body), &entries) != nil {
		return nil
	}

	seen := make(map[string]bool)
	var result []string
	for _, entry := range entries {
		if len(entry) > 0 {
			// Extract domain from URL
			urlStr := entry[0]
			urlStr = strings.TrimPrefix(urlStr, "http://")
			urlStr = strings.TrimPrefix(urlStr, "https://")
			parts := strings.Split(urlStr, "/")
			if len(parts) > 0 {
				host := strings.Split(parts[0], ":")[0] // Remove port
				if a.isValidSubdomain(host) && !seen[host] {
					seen[host] = true
					result = append(result, host)
				}
			}
		}
	}
	return result
}

// commoncrawl queries CommonCrawl index
func (a *APIEnumerator) commoncrawl() []string {
	// Query CommonCrawl index API
	url := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.%s&output=json&limit=5000", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}
	return a.extractSubdomains(body)
}

// threatminer queries ThreatMiner API
func (a *APIEnumerator) threatminer() []string {
	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", a.domain)
	body, err := a.fetch(url)
	if err != nil {
		return nil
	}

	var response struct {
		Results []string `json:"results"`
	}
	if json.Unmarshal([]byte(body), &response) != nil {
		return a.extractSubdomains(body)
	}

	var result []string
	for _, s := range response.Results {
		if a.isValidSubdomain(s) {
			result = append(result, s)
		}
	}
	return result
}

// dedupe removes duplicates from slice
func (a *APIEnumerator) dedupe(subs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range subs {
		s = strings.ToLower(s)
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
