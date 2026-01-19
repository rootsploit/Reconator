package vhost

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// Result contains all VHost discovery results
type Result struct {
	Target        string        `json:"target"`
	VHosts        []VHost       `json:"vhosts"`
	CertSANs      []string      `json:"cert_sans,omitempty"`
	ReverseDNS    []string      `json:"reverse_dns,omitempty"`
	TotalFound    int           `json:"total_found"`
	UniqueVHosts  int           `json:"unique_vhosts"`
	Duration      time.Duration `json:"duration"`
}

// VHost represents a discovered virtual host
type VHost struct {
	Host       string `json:"host"`
	Target     string `json:"target"` // IP or original hostname
	StatusCode int    `json:"status_code,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Words      int    `json:"words,omitempty"`
	Source     string `json:"source"` // "ffuf", "cert_san", "reverse_dns", "combined"
	Verified   bool   `json:"verified"`
}

// Discoverer handles VHost discovery
type Discoverer struct {
	cfg *config.Config
	c   *tools.Checker
}

// NewDiscoverer creates a new VHost discoverer
func NewDiscoverer(cfg *config.Config, checker *tools.Checker) *Discoverer {
	return &Discoverer{cfg: cfg, c: checker}
}

// Discover performs VHost discovery on the given targets
func (d *Discoverer) Discover(targets []string, baseDomain string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:   baseDomain,
		VHosts:   []VHost{},
		CertSANs: []string{},
	}

	if len(targets) == 0 {
		return result, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Extract unique IPs from targets for VHost fuzzing
	ips := d.extractIPs(targets)

	// Phase 1: Certificate SAN extraction (passive, fast)
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("        Extracting SANs from TLS certificates...")
		sans := d.extractCertSANs(targets)
		mu.Lock()
		result.CertSANs = sans
		for _, san := range sans {
			result.VHosts = append(result.VHosts, VHost{
				Host:     san,
				Source:   "cert_san",
				Verified: false,
			})
		}
		mu.Unlock()
		fmt.Printf("        Certificate SANs: %d unique names\n", len(sans))
	}()

	// Phase 2: Reverse DNS lookup
	if len(ips) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running reverse DNS lookups...")
			rdns := d.reverseDNS(ips)
			mu.Lock()
			result.ReverseDNS = rdns
			for _, name := range rdns {
				result.VHosts = append(result.VHosts, VHost{
					Host:     name,
					Source:   "reverse_dns",
					Verified: false,
				})
			}
			mu.Unlock()
			fmt.Printf("        Reverse DNS: %d names\n", len(rdns))
		}()
	}

	// Phase 3: Host header fuzzing with ffuf (active)
	if d.c.IsInstalled("ffuf") && len(ips) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        Running VHost fuzzing with ffuf...")
			vhosts := d.ffufVHostFuzz(ips, baseDomain)
			mu.Lock()
			result.VHosts = append(result.VHosts, vhosts...)
			mu.Unlock()
			fmt.Printf("        ffuf VHost: %d potential vhosts\n", len(vhosts))
		}()
	}

	wg.Wait()

	// Deduplicate and verify VHosts
	result.VHosts = d.deduplicateVHosts(result.VHosts)
	result.TotalFound = len(result.VHosts)

	// Verify discovered vhosts
	if !d.cfg.PassiveMode && len(result.VHosts) > 0 && len(ips) > 0 {
		fmt.Println("        Verifying discovered vhosts...")
		result.VHosts = d.verifyVHosts(result.VHosts, ips[0])
	}

	result.UniqueVHosts = countVerified(result.VHosts)
	result.Duration = time.Since(start)

	return result, nil
}

// extractIPs gets unique IPs from targets (resolves hostnames to IPs)
func (d *Discoverer) extractIPs(targets []string) []string {
	ipSet := make(map[string]bool)

	for _, target := range targets {
		// Extract hostname from URL if needed
		host := extractHost(target)

		// Check if already an IP
		if ip := net.ParseIP(host); ip != nil {
			ipSet[ip.String()] = true
			continue
		}

		// Resolve hostname to IP
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				ipSet[ip4.String()] = true
			}
		}
	}

	var result []string
	for ip := range ipSet {
		result = append(result, ip)
	}
	return result
}

// extractCertSANs extracts Subject Alternative Names from TLS certificates
func (d *Discoverer) extractCertSANs(targets []string) []string {
	sanSet := make(map[string]bool)

	// Use tlsx if available (faster, handles more edge cases)
	if d.c.IsInstalled("tlsx") {
		sans := d.extractSANsWithTLSX(targets)
		for _, san := range sans {
			sanSet[san] = true
		}
	} else {
		// Fallback to native Go TLS
		for _, target := range targets {
			host := extractHost(target)
			port := extractPort(target)
			if port == "" {
				port = "443"
			}

			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp",
				host+":"+port,
				&tls.Config{InsecureSkipVerify: true},
			)
			if err != nil {
				continue
			}

			for _, cert := range conn.ConnectionState().PeerCertificates {
				// Subject CN
				if cert.Subject.CommonName != "" {
					sanSet[cert.Subject.CommonName] = true
				}
				// SANs
				for _, dns := range cert.DNSNames {
					sanSet[dns] = true
				}
			}
			conn.Close()
		}
	}

	var result []string
	for san := range sanSet {
		// Filter out wildcards and internal names
		if !strings.HasPrefix(san, "*") && strings.Contains(san, ".") {
			result = append(result, san)
		}
	}
	sort.Strings(result)
	return result
}

// extractSANsWithTLSX uses tlsx for efficient certificate extraction
func (d *Discoverer) extractSANsWithTLSX(targets []string) []string {
	var sans []string

	tmp, cleanup, err := exec.TempFile(strings.Join(targets, "\n"), "-tlsx-targets.txt")
	if err != nil {
		return sans
	}
	defer cleanup()

	args := []string{
		"-l", tmp,
		"-san", "-cn",
		"-silent",
		"-json",
	}

	if d.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", d.cfg.Threads))
	}

	r := exec.Run("tlsx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return sans
	}

	sanSet := make(map[string]bool)
	for _, line := range exec.Lines(r.Stdout) {
		var entry struct {
			SAN        []string `json:"san"`
			CN         string   `json:"subject_cn"`
			DNSNames   []string `json:"dns_names"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}

		if entry.CN != "" {
			sanSet[entry.CN] = true
		}
		for _, s := range entry.SAN {
			sanSet[s] = true
		}
		for _, s := range entry.DNSNames {
			sanSet[s] = true
		}
	}

	for san := range sanSet {
		sans = append(sans, san)
	}
	return sans
}

// reverseDNS performs reverse DNS lookups on IPs
func (d *Discoverer) reverseDNS(ips []string) []string {
	nameSet := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use hakrevdns if available (faster, concurrent)
	if d.c.IsInstalled("hakrevdns") {
		names := d.reverseDNSWithHakrevdns(ips)
		for _, name := range names {
			nameSet[name] = true
		}
	} else {
		// Fallback to native Go
		sem := make(chan struct{}, 20) // Limit concurrency
		for _, ip := range ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				names, err := net.LookupAddr(ip)
				if err != nil {
					return
				}
				mu.Lock()
				for _, name := range names {
					name = strings.TrimSuffix(name, ".")
					nameSet[name] = true
				}
				mu.Unlock()
			}(ip)
		}
		wg.Wait()
	}

	var result []string
	for name := range nameSet {
		if strings.Contains(name, ".") {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

// reverseDNSWithHakrevdns uses hakrevdns for faster reverse DNS
func (d *Discoverer) reverseDNSWithHakrevdns(ips []string) []string {
	var names []string

	input := strings.Join(ips, "\n")
	args := []string{"-d"}

	if d.cfg.DNSThreads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", d.cfg.DNSThreads))
	}

	r := exec.RunWithInput("hakrevdns", args, input, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return names
	}

	// Parse output: IP\tPTR
	for _, line := range exec.Lines(r.Stdout) {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := strings.TrimSuffix(parts[1], ".")
			names = append(names, name)
		}
	}
	return names
}

// ffufVHostFuzz uses ffuf for host header fuzzing
func (d *Discoverer) ffufVHostFuzz(ips []string, baseDomain string) []VHost {
	var vhosts []VHost

	// Get vhost wordlist
	wordlist := d.findVHostWordlist()
	if wordlist == "" {
		// Generate a basic wordlist with common vhost patterns
		wordlist = d.generateBasicWordlist(baseDomain)
		if wordlist == "" {
			return vhosts
		}
		defer os.Remove(wordlist)
	}

	// Fuzz each IP
	for _, ip := range ips {
		found := d.ffufSingleHost(ip, wordlist, baseDomain)
		vhosts = append(vhosts, found...)

		// Limit to first few IPs to avoid excessive scanning
		if len(vhosts) > 100 {
			break
		}
	}

	return vhosts
}

// ffufSingleHost fuzzes a single host with vhost wordlist
func (d *Discoverer) ffufSingleHost(ip, wordlist, baseDomain string) []VHost {
	var vhosts []VHost

	// Try both HTTP and HTTPS
	protocols := []string{"http", "https"}

	for _, proto := range protocols {
		url := fmt.Sprintf("%s://%s/", proto, ip)

		args := []string{
			"-u", url,
			"-H", "Host: FUZZ." + baseDomain,
			"-w", wordlist,
			"-mc", "200,201,202,203,204,301,302,307,308,401,403",
			"-fs", "0", // Filter zero-length responses
			"-o", "/dev/stdout",
			"-of", "json",
			"-t", "50",
			"-timeout", "10",
			"-s", // Silent mode
		}

		if d.cfg.RateLimit > 0 {
			args = append(args, "-rate", fmt.Sprintf("%d", d.cfg.RateLimit))
		}

		r := exec.Run("ffuf", args, &exec.Options{Timeout: 10 * time.Minute})
		if r.Error != nil {
			continue
		}

		// Parse ffuf JSON output
		var ffufResult struct {
			Results []struct {
				Input struct {
					FUZZ string `json:"FUZZ"`
				} `json:"input"`
				Status int   `json:"status"`
				Length int64 `json:"length"`
				Words  int   `json:"words"`
			} `json:"results"`
		}

		if json.Unmarshal([]byte(r.Stdout), &ffufResult) == nil {
			for _, res := range ffufResult.Results {
				host := res.Input.FUZZ + "." + baseDomain
				vhosts = append(vhosts, VHost{
					Host:       host,
					Target:     ip,
					StatusCode: res.Status,
					Size:       res.Length,
					Words:      res.Words,
					Source:     "ffuf",
					Verified:   true, // ffuf already verified it responds
				})
			}
		}
	}

	return vhosts
}

// findVHostWordlist finds or generates a VHost wordlist
func (d *Discoverer) findVHostWordlist() string {
	home, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(tools.WordlistDir(), "vhosts.txt"),
		"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		"/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
		filepath.Join(home, "SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Try to use the subdomain wordlist
	return tools.FindWordlist()
}

// generateBasicWordlist creates a minimal wordlist for vhost fuzzing
func (d *Discoverer) generateBasicWordlist(baseDomain string) string {
	common := []string{
		"admin", "api", "app", "apps", "auth", "backend", "beta", "blog",
		"cdn", "cms", "console", "dashboard", "db", "dev", "developer",
		"docs", "email", "files", "ftp", "git", "gitlab", "grafana",
		"help", "internal", "intranet", "jenkins", "jira", "kibana",
		"login", "mail", "manage", "management", "monitor", "mx",
		"mysql", "ns", "ns1", "ns2", "office", "ops", "panel", "portal",
		"prod", "production", "proxy", "qa", "redis", "remote", "repo",
		"reports", "secure", "server", "smtp", "sql", "ssh", "ssl",
		"staging", "static", "status", "storage", "support", "test",
		"testing", "tools", "vpn", "webmail", "wiki", "www", "www2",
	}

	// Extract parts from base domain for additional patterns
	parts := strings.Split(baseDomain, ".")
	if len(parts) > 0 {
		base := parts[0]
		common = append(common,
			base+"-admin", base+"-api", base+"-dev", base+"-staging",
			"admin-"+base, "api-"+base, "dev-"+base,
		)
	}

	content := strings.Join(common, "\n")
	path, err := exec.WriteTempFile(content, "-vhost-wordlist.txt")
	if err != nil {
		return ""
	}
	return path
}

// deduplicateVHosts removes duplicate vhosts, preferring verified ones
func (d *Discoverer) deduplicateVHosts(vhosts []VHost) []VHost {
	seen := make(map[string]VHost)

	for _, vh := range vhosts {
		host := strings.ToLower(vh.Host)
		existing, exists := seen[host]
		if !exists {
			seen[host] = vh
		} else if vh.Verified && !existing.Verified {
			// Prefer verified entries
			vh.Source = "combined"
			seen[host] = vh
		}
	}

	var result []VHost
	for _, vh := range seen {
		result = append(result, vh)
	}

	// Sort by host
	sort.Slice(result, func(i, j int) bool {
		return result[i].Host < result[j].Host
	})

	return result
}

// verifyVHosts verifies discovered vhosts by making HTTP requests
func (d *Discoverer) verifyVHosts(vhosts []VHost, targetIP string) []VHost {
	var verified []VHost
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // Limit concurrency

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	for _, vh := range vhosts {
		if vh.Verified {
			verified = append(verified, vh)
			continue
		}

		wg.Add(1)
		go func(vh VHost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Try HTTPS first, then HTTP
			for _, proto := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s/", proto, targetIP)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					continue
				}
				req.Host = vh.Host

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				vh.StatusCode = resp.StatusCode
				vh.Target = targetIP
				vh.Verified = true
				resp.Body.Close()

				mu.Lock()
				verified = append(verified, vh)
				mu.Unlock()
				return
			}
		}(vh)
	}

	wg.Wait()
	return verified
}

// Helper functions

func extractHost(target string) string {
	// Remove protocol
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// Remove path
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	// Remove port
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		// Make sure it's a port, not IPv6
		if !strings.Contains(target[idx:], "]") {
			target = target[:idx]
		}
	}

	return target
}

func extractPort(target string) string {
	// Remove protocol
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// Remove path
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	// Extract port
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		port := target[idx+1:]
		// Validate it looks like a port number
		if matched, _ := regexp.MatchString(`^\d+$`, port); matched {
			return port
		}
	}

	return ""
}

func countVerified(vhosts []VHost) int {
	count := 0
	for _, vh := range vhosts {
		if vh.Verified {
			count++
		}
	}
	return count
}
