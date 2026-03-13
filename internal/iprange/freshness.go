package iprange

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CacheMetadata stores freshness information for cached IP ranges
type CacheMetadata struct {
	CloudCommitSHA string    `json:"cloud_commit_sha"`
	CDNCommitSHA   string    `json:"cdn_commit_sha"`
	FetchedAt      time.Time `json:"fetched_at"`
}

// FreshnessChecker manages IP range cache freshness using GitHub API
type FreshnessChecker struct {
	cacheDir   string
	httpClient *http.Client
}

// NewFreshnessChecker creates a FreshnessChecker for the given cache directory
func NewFreshnessChecker(cacheDir string) *FreshnessChecker {
	os.MkdirAll(cacheDir, 0755)
	return &FreshnessChecker{
		cacheDir:   cacheDir,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// CheckRepoUpdated checks if a GitHub repo has new commits since our cached SHA
func (f *FreshnessChecker) CheckRepoUpdated(repo, cachedSHA string) (latestSHA string, updated bool, err error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits?per_page=1&sha=main", repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return "", false, fmt.Errorf("GitHub API rate limited (403)")
	}
	if resp.StatusCode != 200 {
		return "", false, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	var commits []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return "", false, fmt.Errorf("failed to parse GitHub response: %w", err)
	}
	if len(commits) == 0 {
		return "", false, fmt.Errorf("no commits found for %s", repo)
	}

	latestSHA = commits[0].SHA
	updated = cachedSHA == "" || latestSHA != cachedSHA
	return latestSHA, updated, nil
}

// LoadMetadata reads cache metadata from disk
func (f *FreshnessChecker) LoadMetadata() (*CacheMetadata, error) {
	data, err := os.ReadFile(filepath.Join(f.cacheDir, "metadata.json"))
	if err != nil {
		return nil, err
	}
	var meta CacheMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// SaveMetadata writes cache metadata to disk
func (f *FreshnessChecker) SaveMetadata(meta *CacheMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(f.cacheDir, "metadata.json"), data, 0644)
}

// IsCacheStale returns true if the cache is older than maxAge or doesn't exist
func (f *FreshnessChecker) IsCacheStale(maxAge time.Duration) bool {
	meta, err := f.LoadMetadata()
	if err != nil {
		return true
	}
	return time.Since(meta.FetchedAt) > maxAge
}

// CheckAndRefresh checks both upstream repos and re-downloads if needed
// Returns true if data was refreshed, false if cache was fresh
func (f *FreshnessChecker) CheckAndRefresh(forceRefresh bool) (bool, error) {
	meta, _ := f.LoadMetadata()
	if meta == nil {
		meta = &CacheMetadata{}
	}

	if forceRefresh {
		fmt.Println("        [Freshness] Force refresh requested")
		if err := SaveCloudRangesToCache(f.cacheDir); err != nil {
			return false, fmt.Errorf("download failed: %w", err)
		}
		meta.FetchedAt = time.Now()
		f.SaveMetadata(meta)
		return true, nil
	}

	// Check both repos in parallel
	type repoCheck struct {
		repo      string
		cachedSHA string
		newSHA    string
		updated   bool
		err       error
	}

	checks := []repoCheck{
		{repo: "lord-alfred/ipranges", cachedSHA: meta.CloudCommitSHA},
		{repo: "schniggie/cdn-ranges", cachedSHA: meta.CDNCommitSHA},
	}

	var wg sync.WaitGroup
	for i := range checks {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sha, updated, err := f.CheckRepoUpdated(checks[idx].repo, checks[idx].cachedSHA)
			checks[idx].newSHA = sha
			checks[idx].updated = updated
			checks[idx].err = err
		}(i)
	}
	wg.Wait()

	// Determine if we need to refresh
	needRefresh := false
	apiAvailable := false

	for _, c := range checks {
		if c.err == nil {
			apiAvailable = true
			if c.updated {
				needRefresh = true
				fmt.Printf("        [Freshness] %s: new commit detected\n", c.repo)
			}
		} else {
			fmt.Printf("        [Freshness] %s: API check failed: %v\n", c.repo, c.err)
		}
	}

	// Fallback: if API unavailable, use age-based check (6 hour TTL)
	if !apiAvailable {
		if f.IsCacheStale(6 * time.Hour) {
			needRefresh = true
			fmt.Println("        [Freshness] GitHub API unavailable, cache >6h old, refreshing")
		} else {
			fmt.Println("        [Freshness] GitHub API unavailable, using cached data (<6h old)")
			return false, nil
		}
	}

	if !needRefresh {
		fmt.Printf("        [Freshness] Cache is fresh (last updated: %s)\n",
			meta.FetchedAt.Format("2006-01-02 15:04"))
		return false, nil
	}

	// Download fresh data
	fmt.Println("        [Freshness] Downloading fresh IP ranges...")
	if err := SaveCloudRangesToCache(f.cacheDir); err != nil {
		// If download fails but we have cached data, use it
		if !meta.FetchedAt.IsZero() {
			fmt.Printf("        [Freshness] Download failed: %v (using cached data)\n", err)
			return false, nil
		}
		return false, fmt.Errorf("download failed and no cache exists: %w", err)
	}

	// Update metadata with new SHAs
	for _, c := range checks {
		if c.err == nil && c.newSHA != "" {
			switch c.repo {
			case "lord-alfred/ipranges":
				meta.CloudCommitSHA = c.newSHA
			case "schniggie/cdn-ranges":
				meta.CDNCommitSHA = c.newSHA
			}
		}
	}
	meta.FetchedAt = time.Now()
	f.SaveMetadata(meta)

	fmt.Println("        [Freshness] IP ranges updated successfully")
	return true, nil
}

// FetchWithFreshness is the main entry point for getting IP ranges with freshness checking.
// It checks GitHub API for updates, only re-downloads when data has changed.
// Falls back gracefully when API unavailable or no internet.
func FetchWithFreshness(cacheDir string, forceRefresh bool) (map[string][]string, error) {
	checker := NewFreshnessChecker(cacheDir)

	updated, err := checker.CheckAndRefresh(forceRefresh)
	if err != nil {
		return nil, err
	}

	if updated {
		fmt.Println("        [Freshness] Loading freshly downloaded ranges")
	}

	// Load all cached ranges
	result := make(map[string][]string)

	// Load cloud providers
	for provider := range cloudProviderSources {
		ranges, err := LoadCachedRanges(cacheDir, provider)
		if err != nil {
			continue // Some providers may not have been downloaded
		}
		result[provider] = ranges
	}

	// Load CDN providers
	for provider := range cdnProviderSources {
		ranges, err := LoadCachedRanges(cacheDir, provider)
		if err != nil {
			continue
		}
		result[provider] = ranges
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no IP ranges available in cache at %s", cacheDir)
	}

	return result, nil
}
