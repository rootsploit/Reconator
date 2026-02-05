package subdomain

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ChaosProgram represents a program entry in the Chaos index
type ChaosProgram struct {
	Name        string   `json:"name"`
	URL         string   `json:"URL"`         // chaos-data index field
	ProgramURL  string   `json:"url"`         // bugbounty-list field
	Domains     []string `json:"domains"`     // bugbounty-list field
	Count       int      `json:"count"`       // chaos-data index field
	Platform    string   `json:"platform"`    // chaos-data index field
	Bounty      bool     `json:"bounty"`      // both sources
	Swag        bool     `json:"swag"`        // bugbounty-list field
	LastUpdated string   `json:"last_updated"` // chaos-data index field
}

// ChaosBugBountyList represents the structure of chaos-bugbounty-list.json
type ChaosBugBountyList struct {
	Programs []ChaosProgram `json:"programs"`
}

// ChaosClient provides subdomain enumeration from Chaos ProjectDiscovery
// without requiring an API key by downloading public zip files
type ChaosClient struct {
	cacheDir   string
	httpClient *http.Client
	index      []ChaosProgram
	indexTime  time.Time
}

// NewChaosClient creates a new Chaos client with caching
func NewChaosClient(cacheDir string) *ChaosClient {
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".reconator", "chaos-cache")
	}

	os.MkdirAll(cacheDir, 0755)

	return &ChaosClient{
		cacheDir: cacheDir,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

// FetchSubdomains fetches subdomains for a given domain from Chaos
// Uses index.json for smart program matching to avoid false positives
// Returns: subdomains, source ("chaos-public"), error
func (c *ChaosClient) FetchSubdomains(domain string) ([]string, string, error) {
	// Load index.json for smart matching
	if err := c.loadIndex(); err != nil {
		// Fallback to legacy blind search if index fails
		return c.legacyFetch(domain)
	}

	// Search index for best matching program
	program := c.findBestMatch(domain)
	if program == nil {
		return nil, "", fmt.Errorf("no chaos data found for %s", domain)
	}

	// Download subdomains from matched program
	subdomains, err := c.fetchFromProgram(program)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch %s: %w", program.Name, err)
	}

	// CRITICAL: Validate that downloaded subdomains actually belong to target domain
	// This prevents false positives from multi-domain programs
	filtered := filterByDomain(subdomains, domain)
	if len(filtered) == 0 {
		return nil, "", fmt.Errorf("program %s has no subdomains for %s", program.Name, domain)
	}

	// Additional validation: check that at least 1% of subdomains match (avoid noise)
	matchRatio := float64(len(filtered)) / float64(len(subdomains))
	if matchRatio < 0.01 && len(subdomains) > 100 {
		return nil, "", fmt.Errorf("program %s: only %.1f%% match %s (likely wrong program)",
			program.Name, matchRatio*100, domain)
	}

	return filtered, "chaos-public", nil
}

// legacyFetch is the old blind search method (fallback)
func (c *ChaosClient) legacyFetch(domain string) ([]string, string, error) {
	// Strategy 1: Try direct domain match
	subdomains, err := c.fetchFromZip(domain)
	if err == nil && len(subdomains) > 0 {
		filtered := filterByDomain(subdomains, domain)
		if len(filtered) > 0 {
			return filtered, "chaos-public", nil
		}
	}

	// Strategy 2: Try program name
	programName := extractProgramName(domain)
	if programName != domain {
		subdomains, err = c.fetchFromZip(programName)
		if err == nil && len(subdomains) > 0 {
			filtered := filterByDomain(subdomains, domain)
			if len(filtered) > 0 {
				return filtered, "chaos-public", nil
			}
		}
	}

	return nil, "", fmt.Errorf("no chaos data found for %s", domain)
}

// fetchFromZip downloads and extracts subdomains from Chaos zip file
func (c *ChaosClient) fetchFromZip(programOrDomain string) ([]string, error) {
	// Check cache first
	cacheFile := filepath.Join(c.cacheDir, programOrDomain+".txt")
	if subdomains, err := c.readCache(cacheFile); err == nil {
		return subdomains, nil
	}

	// Download from Chaos
	// URL format: https://chaos-data.projectdiscovery.io/programname.zip
	url := fmt.Sprintf("https://chaos-data.projectdiscovery.io/%s.zip", programOrDomain)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("program not found in chaos: %s", programOrDomain)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chaos returned HTTP %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Extract zip file from memory
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to read zip: %w", err)
	}

	// Find and read the .txt file inside zip
	// Chaos zips typically contain a single .txt file with subdomains
	var subdomains []string
	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, ".txt") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					subdomains = append(subdomains, line)
				}
			}

			// Found subdomains, cache them
			if len(subdomains) > 0 {
				c.writeCache(cacheFile, subdomains)
			}

			return subdomains, nil
		}
	}

	return nil, fmt.Errorf("no subdomains file found in zip")
}

// readCache reads cached subdomains
func (c *ChaosClient) readCache(filePath string) ([]string, error) {
	// Check if cache is recent (less than 7 days old)
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	if time.Since(info.ModTime()) > 7*24*time.Hour {
		// Cache expired
		return nil, fmt.Errorf("cache expired")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

// writeCache writes subdomains to cache
func (c *ChaosClient) writeCache(filePath string, subdomains []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, subdomain := range subdomains {
		if _, err := file.WriteString(subdomain + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// extractProgramName extracts the program/company name from a domain
// Examples:
//   - apple.com -> apple
//   - hackerone.com -> hackerone
//   - example.co.uk -> example
func extractProgramName(domain string) string {
	// Remove common TLDs
	parts := strings.Split(domain, ".")

	if len(parts) >= 2 {
		// Handle cases like example.co.uk (return "example")
		if len(parts) > 2 && isCommonSecondLevelTLD(parts[len(parts)-2]) {
			return parts[len(parts)-3]
		}
		// Handle cases like example.com (return "example")
		return parts[len(parts)-2]
	}

	return domain
}

// isCommonSecondLevelTLD checks if a string is a common second-level TLD
func isCommonSecondLevelTLD(s string) bool {
	secondLevelTLDs := map[string]bool{
		"co":  true,
		"com": true,
		"net": true,
		"org": true,
		"gov": true,
		"edu": true,
		"ac":  true,
	}
	return secondLevelTLDs[s]
}

// filterByDomain filters subdomains to only include those matching the target domain
// Example: If target is "apple.com" and results include both "apple.com" and "applemusic.com",
// only return subdomains ending with ".apple.com" or exactly "apple.com"
func filterByDomain(subdomains []string, targetDomain string) []string {
	var filtered []string
	suffix := "." + targetDomain

	for _, subdomain := range subdomains {
		if subdomain == targetDomain || strings.HasSuffix(subdomain, suffix) {
			filtered = append(filtered, subdomain)
		}
	}

	return filtered
}

// loadIndex downloads and caches the Chaos index
// Uses chaos-bugbounty-list.json as primary (has explicit domain mappings)
// Falls back to chaos-data index.json if needed
func (c *ChaosClient) loadIndex() error {
	// Check if index is already loaded and fresh (less than 24 hours old)
	if len(c.index) > 0 && time.Since(c.indexTime) < 24*time.Hour {
		return nil
	}

	// Try primary source: chaos-bugbounty-list.json (has explicit domains)
	if err := c.loadBugBountyList(); err == nil {
		return nil
	}

	// Fallback to secondary source: chaos-data index.json
	return c.loadChaosDataIndex()
}

// loadBugBountyList loads chaos-bugbounty-list.json (PRIMARY SOURCE)
// This has explicit domain mappings which makes matching 100% accurate
func (c *ChaosClient) loadBugBountyList() error {
	indexCache := filepath.Join(c.cacheDir, "bugbounty-list.json")

	// Check cache first
	if data, err := os.ReadFile(indexCache); err == nil {
		if info, err := os.Stat(indexCache); err == nil {
			if time.Since(info.ModTime()) < 24*time.Hour {
				var list ChaosBugBountyList
				if json.Unmarshal(data, &list) == nil && len(list.Programs) > 0 {
					c.index = list.Programs
					c.indexTime = time.Now()
					return nil
				}
			}
		}
	}

	// Download from GitHub
	url := "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json"
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download bugbounty list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bugbounty list returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read bugbounty list: %w", err)
	}

	// Parse
	var list ChaosBugBountyList
	if err := json.Unmarshal(body, &list); err != nil {
		return fmt.Errorf("failed to parse bugbounty list: %w", err)
	}

	if len(list.Programs) == 0 {
		return fmt.Errorf("bugbounty list is empty")
	}

	c.index = list.Programs
	c.indexTime = time.Now()

	// Cache
	os.WriteFile(indexCache, body, 0644)

	return nil
}

// loadChaosDataIndex loads chaos-data.projectdiscovery.io/index.json (FALLBACK)
func (c *ChaosClient) loadChaosDataIndex() error {
	indexCache := filepath.Join(c.cacheDir, "index.json")

	// Check cache
	if data, err := os.ReadFile(indexCache); err == nil {
		if info, err := os.Stat(indexCache); err == nil {
			if time.Since(info.ModTime()) < 24*time.Hour {
				if json.Unmarshal(data, &c.index) == nil && len(c.index) > 0 {
					c.indexTime = time.Now()
					return nil
				}
			}
		}
	}

	// Download
	resp, err := c.httpClient.Get("https://chaos-data.projectdiscovery.io/index.json")
	if err != nil {
		return fmt.Errorf("failed to download index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("index returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read index: %w", err)
	}

	// Parse
	if err := json.Unmarshal(body, &c.index); err != nil {
		return fmt.Errorf("failed to parse index: %w", err)
	}

	c.indexTime = time.Now()
	os.WriteFile(indexCache, body, 0644)

	return nil
}

// findBestMatch finds the best matching program in Chaos index for a domain
// If program has explicit domains list (from bugbounty-list.json), uses exact matching
// Otherwise falls back to fuzzy scoring
func (c *ChaosClient) findBestMatch(domain string) *ChaosProgram {
	if len(c.index) == 0 {
		return nil
	}

	baseName := extractProgramName(domain) // e.g., "apple" from "apple.com"

	// Phase 1: Try exact domain match from explicit domains list
	// This is 100% accurate (from chaos-bugbounty-list.json)
	for i := range c.index {
		prog := &c.index[i]
		if len(prog.Domains) > 0 {
			for _, d := range prog.Domains {
				if d == domain || d == baseName+".com" || d == baseName+"."+strings.Join(strings.Split(domain, ".")[1:], ".") {
					return prog
				}
			}
		}
	}

	// Phase 2: Fuzzy scoring for programs without explicit domains
	type match struct {
		program *ChaosProgram
		score   int
	}
	var matches []match

	for i := range c.index {
		prog := &c.index[i]
		score := 0

		// Skip if program has explicit domains but didn't match (already checked above)
		if len(prog.Domains) > 0 {
			continue
		}

		// Exact domain match (highest priority)
		if prog.Name == domain {
			score += 1000
		}

		// Base name exact match (e.g., "apple" matches "apple.com")
		if prog.Name == baseName {
			score += 500
		}

		// Program name contains domain (e.g., "apple-bugbounty" for "apple.com")
		if strings.Contains(prog.Name, baseName) {
			score += 250
		}

		// Domain contains program name (e.g., program "classic-fm" for "classicfm.com")
		normalizedDomain := strings.ReplaceAll(domain, ".", "")
		normalizedProg := strings.ReplaceAll(prog.Name, "-", "")
		if strings.Contains(normalizedDomain, normalizedProg) {
			score += 200
		}

		// Bonus: programs with large counts are more likely to be correct
		if prog.Count > 1000 {
			score += 10
		}

		// Bonus: bounty programs are more likely to be production/real companies
		if prog.Bounty {
			score += 5
		}

		if score > 0 {
			matches = append(matches, match{prog, score})
		}
	}

	if len(matches) == 0 {
		return nil
	}

	// Find best match
	bestMatch := matches[0]
	for _, m := range matches {
		if m.score > bestMatch.score {
			bestMatch = m
		}
	}

	// Only return if score is reasonable (avoid very weak matches)
	if bestMatch.score < 50 {
		return nil
	}

	return bestMatch.program
}

// fetchFromProgram downloads subdomains from a specific Chaos program
func (c *ChaosClient) fetchFromProgram(program *ChaosProgram) ([]string, error) {
	// Check cache first
	cacheFile := filepath.Join(c.cacheDir, program.Name+".txt")
	if subdomains, err := c.readCache(cacheFile); err == nil {
		return subdomains, nil
	}

	// Determine download URL (multiple sources)
	url := ""
	if program.URL != "" {
		// chaos-data index has direct URL
		url = program.URL
	} else {
		// Construct URL from program name
		url = fmt.Sprintf("https://chaos-data.projectdiscovery.io/%s.zip", program.Name)
	}

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	// Extract zip
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to read zip: %w", err)
	}

	var subdomains []string
	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, ".txt") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					subdomains = append(subdomains, line)
				}
			}

			// Cache results
			if len(subdomains) > 0 {
				c.writeCache(cacheFile, subdomains)
			}

			return subdomains, nil
		}
	}

	return nil, fmt.Errorf("no subdomains file found in zip")
}

// GetProgramNames searches for program names in Chaos that might match a domain
// This can be used to help users find the right program name for a domain
// Returns a list of potential program names to try
func (c *ChaosClient) GetProgramNames(domain string) []string {
	var names []string

	// Strategy 1: Direct domain
	names = append(names, domain)

	// Strategy 2: Base name (e.g., "apple" from "apple.com")
	baseName := extractProgramName(domain)
	if baseName != domain {
		names = append(names, baseName)
	}

	// Strategy 3: Common variations
	// e.g., for "apple.com": try "apple", "apple-bounty", "apple-vdp"
	if baseName != domain {
		names = append(names, baseName+"-bounty")
		names = append(names, baseName+"-vdp")
		names = append(names, baseName+"security")
	}

	return names
}
