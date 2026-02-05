package iprange

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
)

// CloudProvider represents a cloud/CDN provider
type CloudProvider struct {
	Name     string `json:"name"`
	IPRanges []string `json:"ip_ranges"`
	Source   string `json:"source"`
}

// CloudReconResult holds results from CloudRecon scanning
type CloudReconResult struct {
	Provider       string            `json:"provider"`
	Target         string            `json:"target"`
	DomainsFound   []string          `json:"domains_found"`
	Certificates   []CertificateInfo `json:"certificates"`
	TotalScanned   int               `json:"total_scanned"`
	TotalHits      int               `json:"total_hits"`
	Duration       time.Duration     `json:"duration"`
}

// CertificateInfo holds SSL certificate data from CloudRecon
type CertificateInfo struct {
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	Organization string   `json:"org"`
	CommonName   string   `json:"cn"`
	SANs         []string `json:"san"`
}

// Cloud provider IP range sources from kaeferjaeger.gay / lord-alfred/ipranges
var cloudProviderSources = map[string]string{
	"aws":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv4_merged.txt",
	"azure":        "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv4_merged.txt",
	"gcp":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv4_merged.txt",
	"oracle":       "https://raw.githubusercontent.com/lord-alfred/ipranges/main/oracle/ipv4_merged.txt",
	"digitalocean": "https://raw.githubusercontent.com/lord-alfred/ipranges/main/digitalocean/ipv4_merged.txt",
	"linode":       "https://raw.githubusercontent.com/lord-alfred/ipranges/main/linode/ipv4_merged.txt",
	"vultr":        "https://raw.githubusercontent.com/lord-alfred/ipranges/main/vultr/ipv4_merged.txt",
}

// CDN IP range sources from schniggie/cdn-ranges
// Note: CloudFront uses AWS official JSON API (handled specially in FetchCloudProviderRanges)
var cdnProviderSources = map[string]string{
	"cloudflare":  "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/cloudflare/ipv4.txt",
	"cloudfront":  "",                                                                              // Special: Uses AWS JSON API
	"akamai":      "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/akamai/ipv4.txt",
	"fastly":      "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/fastly/ipv4.txt",
	"incapsula":   "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/incapsula/ipv4.txt",
	"stackpath":   "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/stackpath/ipv4.txt",
	"sucuri":      "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/sucuri/ipv4.txt",
	"keycdn":      "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/keycdn/ipv4.txt",
	"bunnycdn":    "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/bunnycdn/ipv4.txt",
	"gcore":       "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/gcore/ipv4.txt",
	"cdn77":       "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/cdn77/ipv4.txt",
	"cachefly":    "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/cachefly/ipv4.txt",
	"edgecast":    "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/edgecast/ipv4.txt",
	"leaseweb":    "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/leaseweb/ipv4.txt",
	"quantil":     "https://raw.githubusercontent.com/schniggie/cdn-ranges/main/quantil/ipv4.txt",
}

// FetchCloudProviderRanges fetches IP ranges for a specific cloud provider
func FetchCloudProviderRanges(provider string) ([]string, error) {
	providerLower := strings.ToLower(provider)

	// Special case: CloudFront uses AWS JSON API
	if providerLower == "cloudfront" {
		return fetchCloudFrontRanges()
	}

	url, ok := cloudProviderSources[providerLower]
	if !ok {
		// Check CDN sources
		url, ok = cdnProviderSources[providerLower]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", provider)
		}
	}

	return fetchIPRangesFromURL(url)
}

// fetchCloudFrontRanges fetches CloudFront IP ranges from AWS official API
func fetchCloudFrontRanges() ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse AWS IP ranges JSON
	var awsRanges struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(body, &awsRanges); err != nil {
		return nil, err
	}

	// Filter for CLOUDFRONT service
	var ranges []string
	for _, prefix := range awsRanges.Prefixes {
		if prefix.Service == "CLOUDFRONT" {
			ranges = append(ranges, prefix.IPPrefix)
		}
	}

	return ranges, nil
}

// FetchAllCloudRanges fetches IP ranges for all major cloud providers
func FetchAllCloudRanges() (map[string][]string, error) {
	results := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fetch cloud providers
	for provider, url := range cloudProviderSources {
		wg.Add(1)
		go func(p, u string) {
			defer wg.Done()
			ranges, err := fetchIPRangesFromURL(u)
			if err != nil {
				fmt.Printf("        [CloudRanges] Failed to fetch %s: %v\n", p, err)
				return
			}
			mu.Lock()
			results[p] = ranges
			mu.Unlock()
			fmt.Printf("        [CloudRanges] %s: %d ranges\n", p, len(ranges))
		}(provider, url)
	}

	wg.Wait()
	return results, nil
}

// FetchAllCDNRanges fetches IP ranges for all CDN providers
func FetchAllCDNRanges() (map[string][]string, error) {
	results := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for provider, url := range cdnProviderSources {
		wg.Add(1)
		go func(p, u string) {
			defer wg.Done()
			ranges, err := fetchIPRangesFromURL(u)
			if err != nil {
				fmt.Printf("        [CDNRanges] Failed to fetch %s: %v\n", p, err)
				return
			}
			mu.Lock()
			results[p] = ranges
			mu.Unlock()
			fmt.Printf("        [CDNRanges] %s: %d ranges\n", p, len(ranges))
		}(provider, url)
	}

	wg.Wait()
	return results, nil
}

// fetchIPRangesFromURL fetches IP ranges from a URL (one CIDR per line)
func fetchIPRangesFromURL(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var ranges []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ranges = append(ranges, line)
		}
	}

	return ranges, scanner.Err()
}

// CloudReconScanner performs CloudRecon scanning on cloud provider IP ranges
type CloudReconScanner struct {
	cfg        interface{} // Config
	checker    interface{} // Tools checker
	outputDir  string
	cacheDir   string
	threads    int
}

// NewCloudReconScanner creates a new CloudRecon scanner
func NewCloudReconScanner(outputDir string, threads int) *CloudReconScanner {
	cacheDir := filepath.Join(outputDir, ".cache", "ipranges")
	os.MkdirAll(cacheDir, 0755)

	return &CloudReconScanner{
		outputDir: outputDir,
		cacheDir:  cacheDir,
		threads:   threads,
	}
}

// ScanProvider scans a specific cloud provider's IP ranges for the target domain
func (s *CloudReconScanner) ScanProvider(provider, targetDomain string, sampleSize int) (*CloudReconResult, error) {
	start := time.Now()

	result := &CloudReconResult{
		Provider: provider,
		Target:   targetDomain,
	}

	// Fetch IP ranges
	fmt.Printf("        [CloudRecon] Fetching %s IP ranges...\n", provider)
	ranges, err := FetchCloudProviderRanges(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s ranges: %w", provider, err)
	}

	// Sample if too many ranges
	if sampleSize > 0 && len(ranges) > sampleSize {
		fmt.Printf("        [CloudRecon] Sampling %d of %d ranges\n", sampleSize, len(ranges))
		ranges = ranges[:sampleSize]
	}

	result.TotalScanned = len(ranges)

	// Save ranges to temp file
	tmpFile, cleanup, err := s.saveToTempFile(ranges)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Run CloudRecon
	fmt.Printf("        [CloudRecon] Scanning %d CIDR ranges for %s certificates...\n", len(ranges), targetDomain)
	domains, certs, err := s.runCloudRecon(tmpFile, targetDomain)
	if err != nil {
		return nil, err
	}

	result.DomainsFound = domains
	result.Certificates = certs
	result.TotalHits = len(certs)
	result.Duration = time.Since(start)

	return result, nil
}

// ScanAllProviders scans all cloud providers for certificates matching the target domain
func (s *CloudReconScanner) ScanAllProviders(targetDomain string, samplePerProvider int) ([]*CloudReconResult, error) {
	var results []*CloudReconResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	providers := []string{"aws", "azure", "gcp", "oracle", "digitalocean", "linode", "vultr"}

	for _, provider := range providers {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			result, err := s.ScanProvider(p, targetDomain, samplePerProvider)
			if err != nil {
				fmt.Printf("        [CloudRecon] %s scan failed: %v\n", p, err)
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(provider)
	}

	wg.Wait()
	return results, nil
}

// saveToTempFile saves IP ranges to a temp file
func (s *CloudReconScanner) saveToTempFile(ranges []string) (string, func(), error) {
	tmpFile := filepath.Join(s.cacheDir, fmt.Sprintf("ipranges-%d.txt", time.Now().UnixNano()))
	f, err := os.Create(tmpFile)
	if err != nil {
		return "", nil, err
	}

	for _, r := range ranges {
		f.WriteString(r + "\n")
	}
	f.Close()

	cleanup := func() {
		os.Remove(tmpFile)
	}

	return tmpFile, cleanup, nil
}

// runCloudRecon executes CloudRecon and parses results
func (s *CloudReconScanner) runCloudRecon(inputFile, targetDomain string) ([]string, []CertificateInfo, error) {
	// CloudRecon scrape mode: CloudRecon scrape -i file.txt -j
	args := []string{"scrape", "-i", inputFile, "-j", "-p", "443,8443"}

	if s.threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.threads))
	}

	// Timeout for TLS connections
	args = append(args, "-t", "4")

	r := exec.Run("CloudRecon", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return nil, nil, r.Error
	}

	return parseCloudReconForDomain(r.Stdout, targetDomain)
}

// parseCloudReconForDomain parses CloudRecon output and filters for target domain
func parseCloudReconForDomain(output, targetDomain string) ([]string, []CertificateInfo, error) {
	seen := make(map[string]bool)
	var domains []string
	var certs []CertificateInfo

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

		// Check if CN or any SAN matches target domain
		matches := false

		if strings.Contains(strings.ToLower(result.CN), targetLower) {
			matches = true
			if !seen[result.CN] {
				seen[result.CN] = true
				domains = append(domains, result.CN)
			}
		}

		for _, san := range result.SAN {
			sanClean := strings.TrimPrefix(san, "*.")
			if strings.Contains(strings.ToLower(sanClean), targetLower) {
				matches = true
				if !seen[sanClean] {
					seen[sanClean] = true
					domains = append(domains, sanClean)
				}
			}
		}

		if matches {
			certs = append(certs, CertificateInfo{
				IP:           result.IP,
				Port:         result.Port,
				Organization: result.Org,
				CommonName:   result.CN,
				SANs:         result.SAN,
			})
		}
	}

	return domains, certs, nil
}

// SaveCloudRangesToCache downloads and caches cloud provider IP ranges
func SaveCloudRangesToCache(cacheDir string) error {
	os.MkdirAll(cacheDir, 0755)

	var wg sync.WaitGroup
	var errors []error
	var mu sync.Mutex

	allSources := make(map[string]string)
	for k, v := range cloudProviderSources {
		allSources[k] = v
	}
	for k, v := range cdnProviderSources {
		allSources[k] = v
	}

	for provider, url := range allSources {
		wg.Add(1)
		go func(p, u string) {
			defer wg.Done()

			ranges, err := fetchIPRangesFromURL(u)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", p, err))
				mu.Unlock()
				return
			}

			// Save to file
			outFile := filepath.Join(cacheDir, p+".txt")
			f, err := os.Create(outFile)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", p, err))
				mu.Unlock()
				return
			}

			for _, r := range ranges {
				f.WriteString(r + "\n")
			}
			f.Close()

			fmt.Printf("        [Cache] %s: %d ranges saved\n", p, len(ranges))
		}(provider, url)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("some downloads failed: %v", errors)
	}

	return nil
}

// LoadCachedRanges loads IP ranges from cache
func LoadCachedRanges(cacheDir, provider string) ([]string, error) {
	filePath := filepath.Join(cacheDir, provider+".txt")
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ranges []string
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ranges = append(ranges, line)
		}
	}

	return ranges, nil
}

// GetAvailableProviders returns list of available cloud providers
func GetAvailableProviders() []string {
	providers := make([]string, 0)
	for p := range cloudProviderSources {
		providers = append(providers, p)
	}
	return providers
}

// GetAvailableCDNs returns list of available CDN providers
func GetAvailableCDNs() []string {
	cdns := make([]string, 0)
	for c := range cdnProviderSources {
		cdns = append(cdns, c)
	}
	return cdns
}
