package iprange

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	Target            string              `json:"target"`
	IPs               []string            `json:"ips"`
	Domains           []string            `json:"domains"`
	BaseDomains       []string            `json:"base_domains"` // Unique TLDs for subdomain enumeration
	Sources           map[string]int      `json:"sources"`
	IPToDomains       map[string][]string `json:"ip_to_domains"`
	Duration          time.Duration       `json:"duration"`
}

type Discoverer struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewDiscoverer(cfg *config.Config, checker *tools.Checker) *Discoverer {
	return &Discoverer{cfg: cfg, c: checker}
}

// IsIPTarget checks if the target is an IP address or CIDR range
func IsIPTarget(target string) bool {
	// Check for CIDR notation (e.g., 192.168.1.0/24)
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		return err == nil
	}
	// Check for single IP
	return net.ParseIP(target) != nil
}

// IsCIDR checks if target is specifically a CIDR range
func IsCIDR(target string) bool {
	if !strings.Contains(target, "/") {
		return false
	}
	_, _, err := net.ParseCIDR(target)
	return err == nil
}

// IsASN checks if target is an ASN (e.g., AS13335, AS15169, 13335)
func IsASN(target string) bool {
	target = strings.ToUpper(strings.TrimSpace(target))
	// Remove "AS" prefix if present
	if strings.HasPrefix(target, "AS") {
		target = target[2:]
	}
	// Check if remaining is a number
	if target == "" {
		return false
	}
	for _, c := range target {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// DiscoverFromASN finds domains and IP ranges associated with an ASN
// Uses asnmap if installed, otherwise falls back to free APIs (RIPEstat, HackerTarget, BGPView)
func (d *Discoverer) DiscoverFromASN(asn string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:      asn,
		Sources:     make(map[string]int),
		IPToDomains: make(map[string][]string),
	}

	// Normalize ASN format (ensure AS prefix)
	normalizedASN := strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(normalizedASN, "AS") {
		normalizedASN = "AS" + normalizedASN
	}
	// Also get numeric-only version for some APIs
	asnNumber := strings.TrimPrefix(normalizedASN, "AS")

	fmt.Printf("    [*] Querying ASN: %s\n", normalizedASN)

	var cidrs []string
	var source string

	// Try asnmap first if installed
	if d.c.IsInstalled("asnmap") {
		fmt.Println("    [*] Discovering CIDR ranges via asnmap...")
		args := []string{"-a", normalizedASN, "-silent"}
		r := exec.Run("asnmap", args, &exec.Options{Timeout: 2 * time.Minute})
		if r.Error == nil && r.Stdout != "" {
			cidrs = exec.Lines(r.Stdout)
			source = "asnmap"
		}
	}

	// Fallback to free APIs if asnmap failed or not installed
	// Run all APIs in parallel and use first successful result
	if len(cidrs) == 0 {
		fmt.Println("    [*] Querying free APIs in parallel...")
		cidrs, source = d.queryASNAPIsParallel(asnNumber, normalizedASN)
	}

	if len(cidrs) == 0 {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("no CIDR ranges found for %s (all sources failed)", normalizedASN)
	}

	result.Sources[source+"_cidrs"] = len(cidrs)

	// Note: queryASNAPIsParallel already prints the source, no duplicate needed

	// Expand CIDRs to get all IPs (with limit for large ranges)
	var allIPs []string
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		ips := d.expandTarget(cidr)
		// Limit to first 1000 IPs per CIDR for performance
		if len(ips) > 1000 {
			ips = ips[:1000]
		}
		allIPs = append(allIPs, ips...)
	}

	// Limit total IPs
	if len(allIPs) > 10000 {
		fmt.Printf("    [*] Limiting to first 10000 IPs (total: %d)\n", len(allIPs))
		allIPs = allIPs[:10000]
	}

	result.IPs = allIPs
	fmt.Printf("    [*] Expanded to %d IPs from %d CIDR ranges\n", len(allIPs), len(cidrs))

	// Now discover domains from these IPs
	if len(allIPs) > 0 {
		fmt.Println("    [*] Discovering domains from IPs...")
		ipResult, err := d.discoverDomainsFromIPs(allIPs)
		if err == nil {
			result.Domains = ipResult.Domains
			for k, v := range ipResult.Sources {
				result.Sources[k] = v
			}
		}
	}

	// Extract unique TLDs (base domains) for subdomain enumeration
	if len(result.Domains) > 0 {
		result.BaseDomains = ExtractTLDs(result.Domains)
		fmt.Printf("    [*] Extracted %d unique TLDs for subdomain enumeration\n", len(result.BaseDomains))
	}

	result.Duration = time.Since(start)
	return result, nil
}

// discoverDomainsFromIPs runs domain discovery tools on a list of IPs
func (d *Discoverer) discoverDomainsFromIPs(ips []string) (*Result, error) {
	result := &Result{
		Sources:     make(map[string]int),
		IPToDomains: make(map[string][]string),
	}

	var domains sync.Map
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run discovery tools in parallel
	discoveryTools := []struct {
		name    string
		fn      func([]string) []string
		toolCmd string // command to check for installation
	}{
		{"hakrevdns", d.hakrevdns, "hakrevdns"},
		{"hakip2host", d.hakip2host, "hakip2host"},
		{"cero", d.cero, "cero"},
		{"CloudRecon", d.cloudRecon, "CloudRecon"},
		{"dnsx_ptr", d.dnsxPTR, "dnsx"},
	}

	for _, t := range discoveryTools {
		if !d.c.IsInstalled(t.toolCmd) {
			continue
		}

		wg.Add(1)
		go func(name string, fn func([]string) []string) {
			defer wg.Done()
			res := fn(ips)
			mu.Lock()
			result.Sources[name] = len(res)
			mu.Unlock()
			for _, domain := range res {
				domains.Store(domain, true)
			}
			fmt.Printf("        %s: %d domains\n", name, len(res))
		}(t.name, t.fn)
	}

	wg.Wait()

	// Collect unique domains
	var domainList []string
	domains.Range(func(k, _ interface{}) bool {
		domain := k.(string)
		if domain != "" && isValidDomain(domain) {
			domainList = append(domainList, domain)
		}
		return true
	})

	sort.Strings(domainList)
	result.Domains = domainList

	return result, nil
}

// Discover finds domains associated with IP addresses or CIDR ranges
func (d *Discoverer) Discover(target string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:      target,
		Sources:     make(map[string]int),
		IPToDomains: make(map[string][]string),
	}

	// Expand CIDR to individual IPs if needed
	ips := d.expandTarget(target)
	result.IPs = ips
	if len(ips) == 0 {
		return result, fmt.Errorf("no valid IPs in target")
	}

	fmt.Printf("    [*] Target has %d IP(s)\n", len(ips))

	var domains sync.Map
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run discovery tools in parallel
	discoveryTools := []struct {
		name    string
		fn      func([]string) []string
		toolCmd string // command to check for installation
	}{
		{"hakrevdns", d.hakrevdns, "hakrevdns"},
		{"hakip2host", d.hakip2host, "hakip2host"},
		{"cero", d.cero, "cero"},
		{"CloudRecon", d.cloudRecon, "CloudRecon"},
		{"dnsx_ptr", d.dnsxPTR, "dnsx"},
	}

	for _, t := range discoveryTools {
		if !d.c.IsInstalled(t.toolCmd) {
			continue
		}

		wg.Add(1)
		go func(name string, fn func([]string) []string) {
			defer wg.Done()
			res := fn(ips)
			mu.Lock()
			result.Sources[name] = len(res)
			mu.Unlock()
			for _, domain := range res {
				domains.Store(domain, true)
			}
			fmt.Printf("        %s: %d domains\n", name, len(res))
		}(t.name, t.fn)
	}

	wg.Wait()

	// Collect unique domains
	var domainList []string
	domains.Range(func(k, _ interface{}) bool {
		domain := k.(string)
		if domain != "" && isValidDomain(domain) {
			domainList = append(domainList, domain)
		}
		return true
	})

	sort.Strings(domainList)
	result.Domains = domainList
	result.Duration = time.Since(start)

	return result, nil
}

// expandTarget expands CIDR to individual IPs or returns single IP
func (d *Discoverer) expandTarget(target string) []string {
	// Single IP
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}
	}

	// CIDR range - use mapcidr if available for large ranges
	if d.c.IsInstalled("mapcidr") {
		r := exec.RunWithInput("mapcidr", []string{"-silent"}, target, &exec.Options{Timeout: 2 * time.Minute})
		if r.Error == nil && r.Stdout != "" {
			return exec.Lines(r.Stdout)
		}
	}

	// Fallback: expand CIDR in Go
	return expandCIDR(target)
}

// expandCIDR expands a CIDR notation to individual IPs
func expandCIDR(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
		// Limit to /16 at most (65536 IPs)
		if len(ips) > 65536 {
			break
		}
	}

	// Remove network and broadcast addresses for /24 and smaller
	if len(ips) > 2 {
		ones, _ := ipnet.Mask.Size()
		if ones >= 24 {
			ips = ips[1 : len(ips)-1]
		}
	}

	return ips
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// hakrevdns performs reverse DNS lookups using hakrevdns
func (d *Discoverer) hakrevdns(ips []string) []string {
	if !d.c.IsInstalled("hakrevdns") {
		return nil
	}

	// Use temp file for input (more reliable than stdin for some tools)
	input := strings.Join(ips, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-ips.txt")
	if err != nil {
		// Fallback to stdin
		args := []string{"-d"}
		if d.cfg.DNSThreads > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", d.cfg.DNSThreads))
		}
		r := exec.RunWithInput("hakrevdns", args, input, &exec.Options{Timeout: 3 * time.Minute})
		if r.Error != nil {
			return nil
		}
		return extractDomains(exec.Lines(r.Stdout))
	}
	defer cleanup()

	// hakrevdns reads from file via stdin redirection: cat file | hakrevdns
	// But some versions support -l flag for file input
	args := []string{"-d"}
	if d.cfg.DNSThreads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", d.cfg.DNSThreads))
	}

	// Try with file input via stdin using shell
	r := exec.Run("sh", []string{"-c", fmt.Sprintf("cat %s | hakrevdns %s", tmpFile, strings.Join(args, " "))}, &exec.Options{Timeout: 3 * time.Minute})
	if r.Error != nil {
		return nil
	}

	return extractDomains(exec.Lines(r.Stdout))
}

// hakip2host uses multiple methods to find hostnames for IPs
func (d *Discoverer) hakip2host(ips []string) []string {
	if !d.c.IsInstalled("hakip2host") {
		return nil
	}

	// Use temp file and shell pipe (more reliable)
	input := strings.Join(ips, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-ips.txt")
	if err != nil {
		// Fallback to stdin
		r := exec.RunWithInput("hakip2host", nil, input, &exec.Options{Timeout: 3 * time.Minute})
		if r.Error != nil {
			return nil
		}
		return parseHakip2hostOutput(r.Stdout)
	}
	defer cleanup()

	// Use shell pipe: cat file | hakip2host
	r := exec.Run("sh", []string{"-c", fmt.Sprintf("cat %s | hakip2host", tmpFile)}, &exec.Options{Timeout: 3 * time.Minute})
	if r.Error != nil {
		return nil
	}

	return parseHakip2hostOutput(r.Stdout)
}

// parseHakip2hostOutput parses hakip2host output format: [method] IP domain
func parseHakip2hostOutput(output string) []string {
	var domains []string
	for _, line := range exec.Lines(output) {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			domain := strings.TrimSuffix(parts[2], ".")
			if isValidDomain(domain) {
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

// cloudRecon uses CloudRecon for SSL certificate reconnaissance
// CloudRecon scans IPs for SSL certificates and extracts CNs/SANs
func (d *Discoverer) cloudRecon(ips []string) []string {
	if !d.c.IsInstalled("CloudRecon") {
		return nil
	}

	// Use temp file for input
	input := strings.Join(ips, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-ips.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// CloudRecon scrape mode: CloudRecon scrape -i file.txt -j
	args := []string{"scrape", "-i", tmpFile, "-j"}

	// Add concurrency based on config
	if d.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", d.cfg.Threads))
	}

	// Add custom ports if scanning web services
	args = append(args, "-p", "443,8443,8080,9443")

	// Timeout for TLS connections
	args = append(args, "-t", "5")

	r := exec.Run("CloudRecon", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}

	return parseCloudReconOutput(r.Stdout)
}

// parseCloudReconOutput parses JSON output from CloudRecon
// Format: {"ip":"1.2.3.4","port":443,"org":"Example Inc","cn":"example.com","san":["www.example.com","api.example.com"]}
func parseCloudReconOutput(output string) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, line := range exec.Lines(output) {
		if line == "" {
			continue
		}

		// Parse JSON line
		var result struct {
			IP   string   `json:"ip"`
			Port int      `json:"port"`
			Org  string   `json:"org"`
			CN   string   `json:"cn"`
			SAN  []string `json:"san"`
		}

		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		// Extract CN
		if result.CN != "" && !seen[result.CN] && isValidDomain(result.CN) {
			seen[result.CN] = true
			domains = append(domains, result.CN)
		}

		// Extract SANs
		for _, san := range result.SAN {
			san = strings.TrimPrefix(san, "*.")
			if san != "" && !seen[san] && isValidDomain(san) {
				seen[san] = true
				domains = append(domains, san)
			}
		}
	}

	return domains
}

// cero uses certificate transparency to find domains for IPs
func (d *Discoverer) cero(ips []string) []string {
	if !d.c.IsInstalled("cero") {
		return nil
	}

	// Use temp file and shell pipe
	input := strings.Join(ips, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-ips.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// Build args
	args := "-p 443"
	if d.cfg.Threads > 0 {
		args += fmt.Sprintf(" -c %d", d.cfg.Threads)
	}

	// Use shell pipe: cat file | cero (cero is fast - 2 min timeout)
	r := exec.Run("sh", []string{"-c", fmt.Sprintf("cat %s | cero %s", tmpFile, args)}, &exec.Options{Timeout: 2 * time.Minute})
	if r.Error != nil {
		return nil
	}

	return extractDomains(exec.Lines(r.Stdout))
}

// dnsxPTR uses dnsx for PTR record lookups
func (d *Discoverer) dnsxPTR(ips []string) []string {
	if !d.c.IsInstalled("dnsx") {
		return nil
	}

	// Use temp file and shell pipe
	input := strings.Join(ips, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, "-ips.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	// Build args
	args := "-ptr -resp-only -silent"
	if d.cfg.DNSThreads > 0 {
		args += fmt.Sprintf(" -t %d", d.cfg.DNSThreads)
	}

	// Use shell pipe: cat file | dnsx
	r := exec.Run("sh", []string{"-c", fmt.Sprintf("cat %s | dnsx %s", tmpFile, args)}, &exec.Options{Timeout: 3 * time.Minute})
	if r.Error != nil {
		return nil
	}

	return extractDomains(exec.Lines(r.Stdout))
}

// extractDomains cleans and validates domain names from output
func extractDomains(lines []string) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, line := range lines {
		// Remove trailing dots
		domain := strings.TrimSuffix(strings.TrimSpace(line), ".")
		if domain == "" {
			continue
		}

		// Some tools output "IP domain" format
		if parts := strings.Fields(domain); len(parts) > 1 {
			domain = strings.TrimSuffix(parts[len(parts)-1], ".")
		}

		if isValidDomain(domain) && !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}

	return domains
}

// Internal/invalid TLDs to filter out
var internalTLDs = map[string]bool{
	"local":     true,
	"localhost": true,
	"internal":  true,
	"cluster":   true,
	"svc":       true,
	"default":   true,
	"lan":       true,
	"home":      true,
	"localdomain": true,
	"intranet":  true,
	"private":   true,
	"corp":      true,
	"invalid":   true,
	"test":      true,
	"example":   true,
	"onion":     true, // Tor, skip
}

// Common internal domain patterns
var internalPatterns = []string{
	"kubernetes",
	"k8s",
	"kube-",
	"svc.cluster",
	".internal.",
	".local.",
	".lan.",
	".home.",
}

// isValidDomain checks if a string is a valid PUBLIC domain name
func isValidDomain(s string) bool {
	s = strings.ToLower(s)

	// Basic validation - must have at least one dot
	if !strings.Contains(s, ".") {
		return false
	}
	// Check it's not an IP address
	if net.ParseIP(s) != nil {
		return false
	}

	// Check for internal patterns
	for _, pattern := range internalPatterns {
		if strings.Contains(s, pattern) {
			return false
		}
	}

	// Get TLD (last part after dot)
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	tld := parts[len(parts)-1]

	// Check against internal TLDs blocklist
	if internalTLDs[tld] {
		return false
	}

	// Check second-level for patterns like "default.svc"
	if len(parts) >= 2 {
		secondLevel := parts[len(parts)-2]
		if internalTLDs[secondLevel] {
			return false
		}
	}

	// Basic domain regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	if !domainRegex.MatchString(s) {
		return false
	}

	// Validate TLD is likely public (2-63 chars, alphabetic)
	if len(tld) < 2 || len(tld) > 63 {
		return false
	}

	return true
}

// ExtractTLDs extracts unique top-level domains (base domains) from discovered domains
// Only returns valid public domains, filtering out internal/private ones
func ExtractTLDs(domains []string) []string {
	seen := make(map[string]bool)
	var tlds []string

	for _, domain := range domains {
		// Skip invalid domains
		if !isValidDomain(domain) {
			continue
		}

		tld := extractBaseDomain(domain)
		if tld == "" || seen[tld] {
			continue
		}

		// Validate the extracted base domain is also valid
		if !isValidDomain(tld) {
			continue
		}

		seen[tld] = true
		tlds = append(tlds, tld)
	}

	sort.Strings(tlds)
	return tlds
}

// extractBaseDomain extracts the base domain (e.g., "example.com" from "sub.example.com")
func extractBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}

	// Handle common multi-part TLDs
	multiPartTLDs := map[string]bool{
		"co.uk": true, "com.au": true, "co.nz": true, "co.jp": true,
		"com.br": true, "co.in": true, "org.uk": true, "net.au": true,
	}

	if len(parts) >= 3 {
		possibleMultiTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if multiPartTLDs[possibleMultiTLD] {
			if len(parts) >= 3 {
				return parts[len(parts)-3] + "." + possibleMultiTLD
			}
		}
	}

	// Standard TLD (last two parts)
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// queryASNAPIsParallel queries all free ASN APIs in parallel and merges results
// Uses timeout to skip slow/unreachable APIs
func (d *Discoverer) queryASNAPIsParallel(asnNumber, normalizedASN string) ([]string, string) {
	type apiResult struct {
		cidrs  []string
		source string
	}

	resultChan := make(chan apiResult, 3)
	timeout := 15 * time.Second // Skip slow APIs after 15s

	// Query all APIs in parallel
	go func() {
		cidrs, err := fetchASNPrefixesFromRIPEstat(asnNumber)
		if err != nil {
			resultChan <- apiResult{source: "ripestat"} // Empty result with source for logging
		} else {
			resultChan <- apiResult{cidrs, "ripestat"}
		}
	}()

	go func() {
		cidrs, err := fetchASNPrefixesFromHackerTarget(normalizedASN)
		if err != nil {
			resultChan <- apiResult{source: "hackertarget"}
		} else {
			resultChan <- apiResult{cidrs, "hackertarget"}
		}
	}()

	go func() {
		cidrs, err := fetchASNPrefixesFromBGPView(asnNumber)
		if err != nil {
			resultChan <- apiResult{source: "bgpview"}
		} else {
			resultChan <- apiResult{cidrs, "bgpview"}
		}
	}()

	// Collect results with timeout - merge all successful ones
	cidrSet := make(map[string]bool)
	var sources []string
	received := 0
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for received < 3 {
		select {
		case r := <-resultChan:
			received++
			if len(r.cidrs) > 0 {
				fmt.Printf("        %s: %d CIDR ranges\n", r.source, len(r.cidrs))
				sources = append(sources, r.source)
				for _, cidr := range r.cidrs {
					cidrSet[cidr] = true
				}
			} else if r.source != "" {
				fmt.Printf("        %s: 0 (failed/empty)\n", r.source)
			}
		case <-timer.C:
			fmt.Printf("        [!] Timeout waiting for remaining APIs (%d/%d responded)\n", received, 3)
			goto done
		}
	}

done:
	// Convert set to slice
	var mergedCIDRs []string
	for cidr := range cidrSet {
		mergedCIDRs = append(mergedCIDRs, cidr)
	}

	// Build source string
	var sourceStr string
	if len(sources) > 0 {
		sourceStr = strings.Join(sources, "+")
	}

	if len(mergedCIDRs) > 0 {
		fmt.Printf("        [*] Merged: %d unique CIDR ranges from %d sources\n", len(mergedCIDRs), len(sources))
	}

	return mergedCIDRs, sourceStr
}

// ============================================================================
// Free ASN Lookup APIs (no API key required)
// ============================================================================

// fetchASNPrefixesFromRIPEstat fetches IP prefixes from RIPEstat API (free, no limit)
// API docs: https://stat.ripe.net/docs/data_api
func fetchASNPrefixesFromRIPEstat(asnNumber string) ([]string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asnNumber)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse RIPEstat response
	var result struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
		Status string `json:"status"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Status != "ok" {
		return nil, fmt.Errorf("RIPEstat status: %s", result.Status)
	}

	var prefixes []string
	for _, p := range result.Data.Prefixes {
		if p.Prefix != "" {
			prefixes = append(prefixes, p.Prefix)
		}
	}

	return prefixes, nil
}

// fetchASNPrefixesFromHackerTarget fetches IP prefixes from HackerTarget API (free, 50/day)
// API docs: https://hackertarget.com/as-ip-lookup/
func fetchASNPrefixesFromHackerTarget(asn string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", asn)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HackerTarget API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check for error response
	bodyStr := string(body)
	if strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "API count exceeded") {
		return nil, fmt.Errorf("HackerTarget: %s", bodyStr)
	}

	// Parse line-by-line response (format: "IP/CIDR, ASN, Description")
	var prefixes []string
	for _, line := range strings.Split(bodyStr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Extract CIDR from first field
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			cidr := strings.TrimSpace(parts[0])
			// Validate it's a CIDR
			if strings.Contains(cidr, "/") {
				prefixes = append(prefixes, cidr)
			}
		}
	}

	return prefixes, nil
}

// fetchASNPrefixesFromBGPView fetches IP prefixes from BGPView API (free)
// API docs: https://bgpview.io/
func fetchASNPrefixesFromBGPView(asnNumber string) ([]string, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asnNumber)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Reconator/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("BGPView API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse BGPView response
	var result struct {
		Data struct {
			IPv4Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
			IPv6Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
		Status string `json:"status"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Status != "ok" {
		return nil, fmt.Errorf("BGPView status: %s", result.Status)
	}

	var prefixes []string
	for _, p := range result.Data.IPv4Prefixes {
		if p.Prefix != "" {
			prefixes = append(prefixes, p.Prefix)
		}
	}
	// Optionally include IPv6
	for _, p := range result.Data.IPv6Prefixes {
		if p.Prefix != "" {
			prefixes = append(prefixes, p.Prefix)
		}
	}

	return prefixes, nil
}

// LookupASNForIP finds the ASN for an IP address using free APIs
func LookupASNForIP(ip string) (string, string, error) {
	// Try RIPEstat first
	url := fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", ip)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var result struct {
		Data struct {
			ASNs   []string `json:"asns"`
			Prefix string   `json:"prefix"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}

	if len(result.Data.ASNs) > 0 {
		return result.Data.ASNs[0], result.Data.Prefix, nil
	}

	return "", "", fmt.Errorf("no ASN found for %s", ip)
}
