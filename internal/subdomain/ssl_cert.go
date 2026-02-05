package subdomain

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// SSLCertRecon performs SSL certificate reconnaissance on cloud provider IP ranges
// to discover subdomains from CN and SAN fields
type SSLCertRecon struct {
	cfg     *config.Config
	checker *tools.Checker
}

// SSLCertResult holds results from SSL certificate reconnaissance
type SSLCertResult struct {
	Subdomains   []string          `json:"subdomains"`
	Sources      map[string]int    `json:"sources"`
	Certificates []CertificateHit  `json:"certificates"`
	Duration     time.Duration     `json:"duration"`
}

// CertificateHit represents a certificate that matched the target domain
type CertificateHit struct {
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	CommonName   string   `json:"cn"`
	SANs         []string `json:"san"`
	Provider     string   `json:"provider"`
}

// Cloud provider IP range sources (kaeferjaeger.gay / lord-alfred/ipranges)
var cloudRangeSources = map[string]string{
	"aws":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv4_merged.txt",
	"azure":        "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv4_merged.txt",
	"gcp":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv4_merged.txt",
	"oracle":       "https://raw.githubusercontent.com/lord-alfred/ipranges/main/oracle/ipv4_merged.txt",
	"digitalocean": "https://raw.githubusercontent.com/lord-alfred/ipranges/main/digitalocean/ipv4_merged.txt",
}

// CDN provider IP range sources
var cdnRangeSources = map[string]string{
	"cloudflare": "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/cloudflare/ipv4.txt",
	"akamai":     "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/akamai/ipv4.txt",
	"fastly":     "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/fastly/ipv4.txt",
}

// NewSSLCertRecon creates a new SSL certificate reconnaissance instance
func NewSSLCertRecon(cfg *config.Config, checker *tools.Checker) *SSLCertRecon {
	return &SSLCertRecon{cfg: cfg, checker: checker}
}

// Discover scans cloud provider IP ranges for SSL certificates matching the target domain
// Returns discovered subdomains from certificate CN and SAN fields
//
// Primary tool: tlsx (ProjectDiscovery)
//   Command: cat <ranges.txt> | tlsx -cn -san -silent -j -c <threads>
//
// Fallback: CloudRecon
//   Command: CloudRecon scrape -i <ranges.txt> -j -p 443,8443 -c <threads> -t 5
//
// IP Ranges fetched from:
//   - Cloud: github.com/lord-alfred/ipranges (AWS, Azure, GCP, Oracle, DigitalOcean)
//   - CDN: github.com/schniggie/cdn-ranges (Cloudflare, Akamai, Fastly)
func (s *SSLCertRecon) Discover(domain string, resolvedIPs []string) (*SSLCertResult, error) {
	start := time.Now()
	result := &SSLCertResult{
		Sources: make(map[string]int),
	}

	// Check for available tools
	hasTLSX := s.checker.IsInstalled("tlsx")
	hasCloudRecon := s.checker.IsInstalled("CloudRecon")

	if !hasTLSX && !hasCloudRecon {
		return result, nil
	}

	fmt.Println("    [*] SSL Certificate reconnaissance (cloud IP ranges)...")

	var allSubdomains sync.Map
	var allCerts []CertificateHit
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Strategy 1: Scan resolved subdomain IPs for additional certs
	if len(resolvedIPs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var subs []string
			var certs []CertificateHit
			if hasTLSX {
				subs, certs = s.tlsxScan(resolvedIPs, domain, "resolved")
			} else {
				subs, certs = s.cloudReconScan(resolvedIPs, domain, "resolved")
			}
			mu.Lock()
			result.Sources["resolved_ips"] = len(subs)
			allCerts = append(allCerts, certs...)
			mu.Unlock()
			for _, sub := range subs {
				allSubdomains.Store(sub, true)
			}
			if len(subs) > 0 {
				fmt.Printf("        resolved_ips: %d subdomains\n", len(subs))
			}
		}()
	}

	// NOTE: Cloud provider range sampling REMOVED
	// Reasoning:
	// 1. CT logs (crt.sh, certspotter in apis.go) already capture certs when issued
	// 2. Cloud ranges are massive (AWS has millions of IPs) - random sampling has near-zero hit rate
	// 3. The resolved_ips scan above is valuable (scans actual target infrastructure)
	// 4. Time cost (even 1 min) not justified for speculative cloud scanning
	//
	// If you need deep cloud recon, use dedicated tools like:
	// - CloudRecon with known target ASNs
	// - Shodan/Censys for cert search
	// - favirecon for favicon-based discovery

	wg.Wait()

	// Collect unique subdomains
	var subdomains []string
	allSubdomains.Range(func(k, _ interface{}) bool {
		sub := k.(string)
		if s.isValidSubdomain(sub, domain) {
			subdomains = append(subdomains, sub)
		}
		return true
	})

	result.Subdomains = subdomains
	result.Certificates = allCerts
	result.Duration = time.Since(start)

	return result, nil
}

// tlsxScan uses tlsx to scan IPs/CIDRs for SSL certificates
// Command: cat <input> | tlsx -cn -san -silent -j -c <threads>
func (s *SSLCertRecon) tlsxScan(targets []string, domain, provider string) ([]string, []CertificateHit) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Write targets to temp file
	tmpFile, cleanup, err := exec.TempFile(strings.Join(targets, "\n"), "-tlsx-input.txt")
	if err != nil {
		return nil, nil
	}
	defer cleanup()

	// tlsx command: tlsx -l <file> -cn -san -silent -j -c <threads>
	args := []string{"-l", tmpFile, "-cn", "-san", "-silent", "-j"}
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}
	// Add per-connection timeout (2 seconds for faster scanning)
	args = append(args, "-timeout", "2")

	// Use 1 minute timeout - passive CT APIs already cover most certs
	// Active cloud scanning is supplementary, not worth waiting long
	r := exec.Run("tlsx", args, &exec.Options{Timeout: 1 * time.Minute})

	// Parse whatever results we got (even partial on timeout/error)
	// This ensures we don't lose discovered subdomains just because
	// the full scan didn't complete
	if r.Stdout == "" {
		return nil, nil
	}

	return s.parseTLSXOutput(r.Stdout, domain, provider)
}

// parseTLSXOutput parses tlsx JSON output
// Format: {"host":"1.2.3.4:443","cn":"example.com","san":["www.example.com"]}
func (s *SSLCertRecon) parseTLSXOutput(output, targetDomain, provider string) ([]string, []CertificateHit) {
	seen := make(map[string]bool)
	var subdomains []string
	var certs []CertificateHit
	targetLower := strings.ToLower(targetDomain)

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}

		var result struct {
			Host string   `json:"host"`
			IP   string   `json:"ip"`
			Port string   `json:"port"`
			CN   string   `json:"cn"`
			SAN  []string `json:"san"`
		}

		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		var matchedDomains []string

		// Check CN
		if s.matchesDomain(strings.ToLower(result.CN), targetLower) {
			cleanCN := strings.TrimPrefix(result.CN, "*.")
			if !seen[cleanCN] {
				seen[cleanCN] = true
				matchedDomains = append(matchedDomains, cleanCN)
			}
		}

		// Check SANs
		for _, san := range result.SAN {
			if s.matchesDomain(strings.ToLower(san), targetLower) {
				cleanSAN := strings.TrimPrefix(san, "*.")
				if !seen[cleanSAN] {
					seen[cleanSAN] = true
					matchedDomains = append(matchedDomains, cleanSAN)
				}
			}
		}

		if len(matchedDomains) > 0 {
			subdomains = append(subdomains, matchedDomains...)
			port := 443
			if result.Port != "" {
				fmt.Sscanf(result.Port, "%d", &port)
			}
			certs = append(certs, CertificateHit{
				IP:         result.IP,
				Port:       port,
				CommonName: result.CN,
				SANs:       result.SAN,
				Provider:   provider,
			})
		}
	}

	return subdomains, certs
}

// cloudReconScan uses CloudRecon to scan IPs for SSL certificates (fallback)
// Command: CloudRecon scrape -i <file> -j -p 443,8443 -c <threads> -t 5
func (s *SSLCertRecon) cloudReconScan(targets []string, domain, provider string) ([]string, []CertificateHit) {
	if len(targets) == 0 {
		return nil, nil
	}

	tmpFile, cleanup, err := exec.TempFile(strings.Join(targets, "\n"), "-cloudrecon-input.txt")
	if err != nil {
		return nil, nil
	}
	defer cleanup()

	args := []string{"scrape", "-i", tmpFile, "-j", "-p", "443,8443"}
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}
	args = append(args, "-t", "5")

	r := exec.Run("CloudRecon", args, &exec.Options{Timeout: 1 * time.Minute})
	if r.Error != nil {
		return nil, nil
	}

	return s.parseCloudReconOutput(r.Stdout, domain, provider)
}

// parseCloudReconOutput parses CloudRecon JSON output
func (s *SSLCertRecon) parseCloudReconOutput(output, targetDomain, provider string) ([]string, []CertificateHit) {
	seen := make(map[string]bool)
	var subdomains []string
	var certs []CertificateHit
	targetLower := strings.ToLower(targetDomain)

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}

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

		var matchedDomains []string

		if s.matchesDomain(strings.ToLower(result.CN), targetLower) {
			cleanCN := strings.TrimPrefix(result.CN, "*.")
			if !seen[cleanCN] {
				seen[cleanCN] = true
				matchedDomains = append(matchedDomains, cleanCN)
			}
		}

		for _, san := range result.SAN {
			if s.matchesDomain(strings.ToLower(san), targetLower) {
				cleanSAN := strings.TrimPrefix(san, "*.")
				if !seen[cleanSAN] {
					seen[cleanSAN] = true
					matchedDomains = append(matchedDomains, cleanSAN)
				}
			}
		}

		if len(matchedDomains) > 0 {
			subdomains = append(subdomains, matchedDomains...)
			certs = append(certs, CertificateHit{
				IP:         result.IP,
				Port:       result.Port,
				CommonName: result.CN,
				SANs:       result.SAN,
				Provider:   provider,
			})
		}
	}

	return subdomains, certs
}

// fetchIPRanges fetches IP ranges for a cloud provider with caching
func (s *SSLCertRecon) fetchIPRanges(provider string) ([]string, error) {
	url, ok := cloudRangeSources[provider]
	if !ok {
		url, ok = cdnRangeSources[provider]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", provider)
		}
	}

	// Check cache first (24hr TTL)
	cacheDir := filepath.Join(os.TempDir(), "reconator", "ipranges")
	os.MkdirAll(cacheDir, 0755)
	cacheFile := filepath.Join(cacheDir, provider+".txt")

	if info, err := os.Stat(cacheFile); err == nil {
		if time.Since(info.ModTime()) < 24*time.Hour {
			if data, err := os.ReadFile(cacheFile); err == nil {
				var ranges []string
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						ranges = append(ranges, line)
					}
				}
				if len(ranges) > 0 {
					return ranges, nil
				}
			}
		}
	}

	// Fetch from URL
	var output string
	if r := exec.Run("curl", []string{"-s", "-L", "--max-time", "30", url}, &exec.Options{Timeout: 35 * time.Second}); r.Error == nil {
		output = r.Stdout
	} else if r := exec.Run("wget", []string{"-q", "-O", "-", "--timeout=30", url}, &exec.Options{Timeout: 35 * time.Second}); r.Error == nil {
		output = r.Stdout
	} else {
		return nil, fmt.Errorf("failed to fetch %s ranges", provider)
	}

	var ranges []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ranges = append(ranges, line)
		}
	}

	// Cache results
	if len(ranges) > 0 {
		os.WriteFile(cacheFile, []byte(output), 0644)
	}

	return ranges, nil
}

// matchesDomain checks if a certificate domain matches the target domain
func (s *SSLCertRecon) matchesDomain(certDomain, targetDomain string) bool {
	certDomain = strings.TrimPrefix(certDomain, "*.")
	if certDomain == targetDomain {
		return true
	}
	if strings.HasSuffix(certDomain, "."+targetDomain) {
		return true
	}
	return false
}

// isValidSubdomain checks if the discovered domain is a valid subdomain of the target
func (s *SSLCertRecon) isValidSubdomain(subdomain, targetDomain string) bool {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	targetDomain = strings.ToLower(targetDomain)

	if subdomain == targetDomain || strings.HasSuffix(subdomain, "."+targetDomain) {
		if net.ParseIP(subdomain) == nil && strings.Contains(subdomain, ".") {
			return true
		}
	}
	return false
}

// ResolveSubdomainIPs resolves subdomains to IPs using dnsx
// Command: dnsx -l <file> -a -resp-only -silent -t <threads>
func (s *SSLCertRecon) ResolveSubdomainIPs(subdomains []string) []string {
	if len(subdomains) == 0 || !s.checker.IsInstalled("dnsx") {
		return nil
	}

	tmpFile, cleanup, err := exec.TempFile(strings.Join(subdomains, "\n"), "-subdomains.txt")
	if err != nil {
		return nil
	}
	defer cleanup()

	args := []string{"-l", tmpFile, "-a", "-resp-only", "-silent"}
	if s.cfg.DNSThreads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", s.cfg.DNSThreads))
	}

	r := exec.Run("dnsx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		return nil
	}

	seen := make(map[string]bool)
	var ips []string
	for _, line := range strings.Split(r.Stdout, "\n") {
		ip := strings.TrimSpace(line)
		if ip != "" && net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	return ips
}
