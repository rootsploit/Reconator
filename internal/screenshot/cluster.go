package screenshot

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/corona10/goimagehash"
)

// Result represents screenshot capture and clustering results
type Result struct {
	TotalCaptures  int              `json:"total_captures"`
	TotalClustered int              `json:"total_clustered"`
	Clusters       []Cluster        `json:"clusters"`
	Screenshots    []ScreenshotMeta `json:"screenshots"`
	ClusterSummary map[string]int   `json:"cluster_summary"` // cluster_name -> count
	Duration       time.Duration    `json:"duration"`
	Skipped        bool             `json:"skipped,omitempty"`
	SkipReason     string           `json:"skip_reason,omitempty"`
}

// Cluster represents a group of visually similar screenshots
type Cluster struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"` // e.g., "404 Pages", "Login Forms", "Default Pages"
	Count       int      `json:"count"`
	Screenshots []string `json:"screenshots"` // file paths
	SampleHash  string   `json:"sample_hash"` // representative hash
}

// ScreenshotMeta contains metadata for a single screenshot
type ScreenshotMeta struct {
	URL       string    `json:"url"`
	Host      string    `json:"host"`
	FilePath  string    `json:"file_path"`
	Hash      string    `json:"hash"`      // perceptual hash for clustering
	FileHash  string    `json:"file_hash"` // MD5 for exact duplicate detection
	Size      int64     `json:"size"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	ClusterID string    `json:"cluster_id"`
	Captured  time.Time `json:"captured"`
}

// ClusterConfig defines clustering parameters
type ClusterConfig struct {
	// Similarity threshold (0-64, lower = more similar)
	// 0 = exact match, 5 = very similar, 10 = somewhat similar
	Threshold int
	// Minimum cluster size to report
	MinClusterSize int
}

// DefaultClusterConfig returns sensible defaults
func DefaultClusterConfig() ClusterConfig {
	return ClusterConfig{
		Threshold:      8, // Allow 8-bit difference in perceptual hash
		MinClusterSize: 2, // At least 2 images to form a cluster
	}
}

// ClusterScreenshots groups screenshots by visual similarity
func ClusterScreenshots(screenshotDir string, config ClusterConfig) (*Result, error) {
	start := time.Now()
	result := &Result{
		Clusters:       []Cluster{},
		Screenshots:    []ScreenshotMeta{},
		ClusterSummary: make(map[string]int),
	}

	// Find all screenshot files
	var files []string
	err := filepath.Walk(screenshotDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() && isImageFile(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk screenshot directory: %w", err)
	}

	if len(files) == 0 {
		result.Duration = time.Since(start)
		return result, nil
	}

	// Process each screenshot and deduplicate by file hash (exact duplicates)
	seenFileHash := make(map[string]bool)
	for _, filePath := range files {
		meta, err := processScreenshot(filePath)
		if err != nil {
			continue // Skip problematic files
		}
		// Skip exact duplicates (same image content)
		if seenFileHash[meta.FileHash] {
			continue
		}
		seenFileHash[meta.FileHash] = true
		result.Screenshots = append(result.Screenshots, *meta)
	}
	result.TotalCaptures = len(result.Screenshots)

	// Cluster by perceptual hash similarity
	clusters := clusterByHash(result.Screenshots, config)
	result.Clusters = clusters
	result.TotalClustered = len(clusters)

	// Build cluster summary
	for _, cluster := range clusters {
		result.ClusterSummary[cluster.Name] = cluster.Count
	}

	// Update screenshot metadata with cluster IDs
	clusterMap := make(map[string]string) // file_path -> cluster_id
	for _, cluster := range clusters {
		for _, path := range cluster.Screenshots {
			clusterMap[path] = cluster.ID
		}
	}
	for i := range result.Screenshots {
		if clusterID, ok := clusterMap[result.Screenshots[i].FilePath]; ok {
			result.Screenshots[i].ClusterID = clusterID
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// processScreenshot extracts metadata from a screenshot file
func processScreenshot(filePath string) (*ScreenshotMeta, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file info
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// Decode image to get dimensions
	img, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()

	// Reset file for hash calculation
	file.Seek(0, 0)

	// Calculate MD5 hash for exact duplicate detection
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	md5Hash := md5.Sum(content)
	fileHash := hex.EncodeToString(md5Hash[:])

	// Calculate perceptual hash using goimagehash
	// We use PerceptionHash (pHash) which is robust against transformations
	pHashStr := "0000000000000000"
	pHash, err := goimagehash.PerceptionHash(img)
	if err == nil {
		// GetHash returns the uint64 hash
		pHashStr = fmt.Sprintf("%016x", pHash.GetHash())
	}

	// Extract URL/host from filename (gowitness naming convention)
	url, host := parseGoWitnessFilename(filePath)

	return &ScreenshotMeta{
		URL:      url,
		Host:     host,
		FilePath: filePath,
		Hash:     pHashStr,
		FileHash: fileHash,
		Size:     info.Size(),
		Width:    bounds.Dx(),
		Height:   bounds.Dy(),
		Captured: info.ModTime(),
	}, nil
}

// hammingDistance calculates the number of differing bits between two hashes
func hammingDistance(hash1, hash2 string) int {
	if len(hash1) != 16 || len(hash2) != 16 {
		return 64 // Max distance
	}

	var h1, h2 uint64
	fmt.Sscanf(hash1, "%x", &h1)
	fmt.Sscanf(hash2, "%x", &h2)

	xor := h1 ^ h2
	distance := 0
	for xor != 0 {
		distance++
		xor &= xor - 1
	}
	return distance
}

// clusterByHash groups screenshots by perceptual hash similarity
func clusterByHash(screenshots []ScreenshotMeta, config ClusterConfig) []Cluster {
	if len(screenshots) == 0 {
		return nil
	}

	// Union-Find for clustering
	parent := make([]int, len(screenshots))
	for i := range parent {
		parent[i] = i
	}

	var find func(i int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}

	union := func(i, j int) {
		pi, pj := find(i), find(j)
		if pi != pj {
			parent[pi] = pj
		}
	}

	// Compare all pairs and union similar ones
	for i := 0; i < len(screenshots); i++ {
		for j := i + 1; j < len(screenshots); j++ {
			distance := hammingDistance(screenshots[i].Hash, screenshots[j].Hash)
			if distance <= config.Threshold {
				union(i, j)
			}
		}
	}

	// Group by cluster
	clusterMembers := make(map[int][]int)
	for i := range screenshots {
		root := find(i)
		clusterMembers[root] = append(clusterMembers[root], i)
	}

	// Build clusters
	var clusters []Cluster
	clusterID := 0
	for root, members := range clusterMembers {
		if len(members) < config.MinClusterSize {
			continue
		}

		var paths []string
		for _, idx := range members {
			paths = append(paths, screenshots[idx].FilePath)
		}

		// Determine cluster name based on common patterns
		clusterName := determineClusterName(screenshots, members)

		clusters = append(clusters, Cluster{
			ID:          fmt.Sprintf("cluster_%d", clusterID),
			Name:        clusterName,
			Count:       len(members),
			Screenshots: paths,
			SampleHash:  screenshots[root].Hash,
		})
		clusterID++
	}

	// Sort by size (largest first)
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].Count > clusters[j].Count
	})

	return clusters
}

// determineClusterName attempts to identify the type of pages in a cluster
func determineClusterName(screenshots []ScreenshotMeta, members []int) string {
	// Analyze URLs and filenames for common patterns
	var urls []string
	for _, idx := range members {
		urls = append(urls, strings.ToLower(screenshots[idx].URL))
	}

	// Check for common patterns
	patterns := map[string][]string{
		"404 Pages":     {"404", "not-found", "notfound", "page-not-found"},
		"Login Pages":   {"login", "signin", "sign-in", "auth", "sso"},
		"Admin Panels":  {"admin", "dashboard", "panel", "console", "cms"},
		"API Docs":      {"swagger", "api-docs", "openapi", "redoc"},
		"Default Pages": {"welcome", "default", "index", "home"},
		"Error Pages":   {"error", "500", "403", "forbidden", "unauthorized"},
		"WordPress":     {"wp-admin", "wp-login", "wordpress"},
		"Blank/Empty":   {},
	}

	for name, keywords := range patterns {
		if name == "Blank/Empty" {
			continue
		}
		matchCount := 0
		for _, url := range urls {
			for _, keyword := range keywords {
				if strings.Contains(url, keyword) {
					matchCount++
					break
				}
			}
		}
		// If more than 30% of URLs match, use this name
		if float64(matchCount)/float64(len(urls)) > 0.3 {
			return name
		}
	}

	// Check for blank/similar size (small file = likely blank)
	smallCount := 0
	for _, idx := range members {
		if screenshots[idx].Size < 10000 { // Less than 10KB likely blank
			smallCount++
		}
	}
	if float64(smallCount)/float64(len(members)) > 0.5 {
		return "Blank/Empty Pages"
	}

	return fmt.Sprintf("Similar Group (%d pages)", len(members))
}

// parseGoWitnessFilename extracts URL and host from gowitness filename
func parseGoWitnessFilename(filePath string) (url, host string) {
	// gowitness v3 saves files as: http---example.com-80.jpeg or https---example.com-443.jpeg
	// Note: scheme is separated by "---" (triple dash), port by single "-"
	base := filepath.Base(filePath)
	base = strings.TrimSuffix(base, filepath.Ext(base))

	// gowitness v3 uses "---" to separate scheme from host
	if strings.Contains(base, "---") {
		parts := strings.SplitN(base, "---", 2)
		if len(parts) == 2 {
			scheme := parts[0]
			hostPort := parts[1]

			// Find the last dash which separates host from port
			lastDash := strings.LastIndex(hostPort, "-")
			if lastDash > 0 {
				host = hostPort[:lastDash]
				port := hostPort[lastDash+1:]

				// Construct clean URL
				if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
					url = fmt.Sprintf("%s://%s", scheme, host)
				} else {
					url = fmt.Sprintf("%s://%s:%s", scheme, host, port)
				}
				return url, host
			}
		}
	}

	// Fallback for gowitness v2 or other formats: scheme-host-port
	parts := strings.Split(base, "-")
	if len(parts) >= 3 {
		scheme := parts[0]
		if scheme == "https" || scheme == "http" {
			// Port is the last part
			port := parts[len(parts)-1]
			// Host is everything between scheme and port
			host = strings.Join(parts[1:len(parts)-1], "-")

			if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
				url = fmt.Sprintf("%s://%s", scheme, host)
			} else {
				url = fmt.Sprintf("%s://%s:%s", scheme, host, port)
			}
			return url, host
		}
	}

	// Fallback: use base as both
	return base, base
}

// isImageFile checks if a file is a supported image format
func isImageFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".png" || ext == ".jpg" || ext == ".jpeg"
}

// SaveResult saves the clustering result to a JSON file
func (r *Result) SaveResult(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(outputDir, "screenshot_clusters.json"))
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// OrganizeIntoFolders creates subdirectories for each cluster
func (r *Result) OrganizeIntoFolders(baseDir string) error {
	clusteredDir := filepath.Join(baseDir, "clustered")
	if err := os.MkdirAll(clusteredDir, 0755); err != nil {
		return err
	}

	for _, cluster := range r.Clusters {
		// Create folder for cluster
		clusterDir := filepath.Join(clusteredDir, sanitizeFolderName(cluster.Name))
		if err := os.MkdirAll(clusterDir, 0755); err != nil {
			continue
		}

		// Create symlinks to original files
		for _, srcPath := range cluster.Screenshots {
			dstPath := filepath.Join(clusterDir, filepath.Base(srcPath))
			// Use symlink to avoid duplicating data
			os.Symlink(srcPath, dstPath)
		}
	}

	return nil
}

// sanitizeFolderName makes a string safe for use as a folder name
func sanitizeFolderName(name string) string {
	// Replace problematic characters
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}
