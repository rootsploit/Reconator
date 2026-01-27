package vulnscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CVECacheEntry represents a cached CVE lookup result
type CVECacheEntry struct {
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	CVEs      []CVEInfo       `json:"cves"`
	Source    string          `json:"source"` // "vulnx", "nvd", "hardcoded"
	CachedAt  time.Time       `json:"cached_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// CVEInfo contains detailed CVE information
type CVEInfo struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss,omitempty"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
	Published   string   `json:"published,omitempty"`
}

// CVECache manages local caching of CVE lookup results
type CVECache struct {
	cacheDir  string
	cacheTTL  time.Duration
	mu        sync.RWMutex
	memory    map[string]*CVECacheEntry // In-memory cache for session
}

// NewCVECache creates a new CVE cache
func NewCVECache() *CVECache {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".reconator", "cve-cache")
	os.MkdirAll(cacheDir, 0755)

	return &CVECache{
		cacheDir: cacheDir,
		cacheTTL: 24 * time.Hour, // Cache for 24 hours
		memory:   make(map[string]*CVECacheEntry),
	}
}

// cacheKey generates a unique key for product+version
func (c *CVECache) cacheKey(product, version string) string {
	return strings.ToLower(fmt.Sprintf("%s_%s",
		strings.ReplaceAll(product, " ", "-"),
		strings.ReplaceAll(version, ".", "_")))
}

// Get retrieves a cached CVE entry
func (c *CVECache) Get(product, version string) (*CVECacheEntry, bool) {
	key := c.cacheKey(product, version)

	// Check memory cache first
	c.mu.RLock()
	if entry, ok := c.memory[key]; ok {
		c.mu.RUnlock()
		if time.Now().Before(entry.ExpiresAt) {
			return entry, true
		}
	} else {
		c.mu.RUnlock()
	}

	// Check disk cache
	cachePath := filepath.Join(c.cacheDir, key+".json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}

	var entry CVECacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		os.Remove(cachePath) // Clean up expired entry
		return nil, false
	}

	// Update memory cache
	c.mu.Lock()
	c.memory[key] = &entry
	c.mu.Unlock()

	return &entry, true
}

// Set stores a CVE entry in cache
func (c *CVECache) Set(product, version string, cves []CVEInfo, source string) {
	key := c.cacheKey(product, version)
	entry := &CVECacheEntry{
		Product:   product,
		Version:   version,
		CVEs:      cves,
		Source:    source,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(c.cacheTTL),
	}

	// Update memory cache
	c.mu.Lock()
	c.memory[key] = entry
	c.mu.Unlock()

	// Write to disk cache
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}

	cachePath := filepath.Join(c.cacheDir, key+".json")
	os.WriteFile(cachePath, data, 0644)
}

// Clear removes all cached entries
func (c *CVECache) Clear() error {
	c.mu.Lock()
	c.memory = make(map[string]*CVECacheEntry)
	c.mu.Unlock()

	// Clear disk cache
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			os.Remove(filepath.Join(c.cacheDir, entry.Name()))
		}
	}

	return nil
}

// Stats returns cache statistics
func (c *CVECache) Stats() (total int, expired int, sources map[string]int) {
	sources = make(map[string]int)

	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return 0, 0, sources
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		total++
		cachePath := filepath.Join(c.cacheDir, entry.Name())
		data, err := os.ReadFile(cachePath)
		if err != nil {
			continue
		}

		var cacheEntry CVECacheEntry
		if err := json.Unmarshal(data, &cacheEntry); err != nil {
			continue
		}

		if time.Now().After(cacheEntry.ExpiresAt) {
			expired++
		}

		sources[cacheEntry.Source]++
	}

	return total, expired, sources
}
