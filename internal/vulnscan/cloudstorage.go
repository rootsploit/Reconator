package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
)

// CloudBucket represents a discovered cloud storage bucket
type CloudBucket struct {
	Name        string `json:"name"`
	Provider    string `json:"provider"` // s3, gcs, azure
	URL         string `json:"url"`
	Status      string `json:"status"` // open, authenticated, private, not_found
	Listable    bool   `json:"listable"`
	Writable    bool   `json:"writable"`
	FileCount   int    `json:"file_count,omitempty"`
	SampleFiles []string `json:"sample_files,omitempty"`
}

// CloudStorageResult contains all discovered buckets
type CloudStorageResult struct {
	Buckets   []CloudBucket  `json:"buckets"`
	ByStatus  map[string]int `json:"by_status"`
	ByProvider map[string]int `json:"by_provider"`
	Duration  time.Duration  `json:"duration"`
}

// CloudStorageScanner discovers misconfigured cloud storage
type CloudStorageScanner struct {
	cfg    *config.Config
	client *http.Client
}

// NewCloudStorageScanner creates a new cloud storage scanner
func NewCloudStorageScanner(cfg *config.Config) *CloudStorageScanner {
	return &CloudStorageScanner{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ScanCloudStorage discovers and tests cloud storage buckets for a domain
func (s *CloudStorageScanner) ScanCloudStorage(ctx context.Context, domain string, subdomains []string) (*CloudStorageResult, error) {
	start := time.Now()
	result := &CloudStorageResult{
		Buckets:    []CloudBucket{},
		ByStatus:   make(map[string]int),
		ByProvider: make(map[string]int),
	}

	// Generate bucket name permutations
	bucketNames := s.generateBucketNames(domain, subdomains)
	fmt.Printf("    [*] Testing %d potential bucket names...\n", len(bucketNames))

	// Use reasonable concurrency for cloud storage scanning (default 15 if Threads is 0)
	threads := s.cfg.Threads
	if threads == 0 {
		threads = 15
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, name := range bucketNames {
		wg.Add(3) // Test S3, GCS, and Azure

		// AWS S3
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bucket := s.testS3Bucket(ctx, n)
			if bucket != nil {
				mu.Lock()
				result.Buckets = append(result.Buckets, *bucket)
				result.ByStatus[bucket.Status]++
				result.ByProvider["s3"]++
				mu.Unlock()
			}
		}(name)

		// Google Cloud Storage
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bucket := s.testGCSBucket(ctx, n)
			if bucket != nil {
				mu.Lock()
				result.Buckets = append(result.Buckets, *bucket)
				result.ByStatus[bucket.Status]++
				result.ByProvider["gcs"]++
				mu.Unlock()
			}
		}(name)

		// Azure Blob Storage
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bucket := s.testAzureBucket(ctx, n)
			if bucket != nil {
				mu.Lock()
				result.Buckets = append(result.Buckets, *bucket)
				result.ByStatus[bucket.Status]++
				result.ByProvider["azure"]++
				mu.Unlock()
			}
		}(name)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	// Print summary
	open := result.ByStatus["open"]
	if open > 0 {
		fmt.Printf("    [!] Found %d open buckets!\n", open)
	} else {
		fmt.Printf("    [*] Found %d buckets (none open)\n", len(result.Buckets))
	}

	return result, nil
}

func (s *CloudStorageScanner) generateBucketNames(domain string, subdomains []string) []string {
	seen := make(map[string]bool)
	var names []string

	// Base domain variations
	baseName := strings.ReplaceAll(domain, ".", "-")
	baseNameDot := strings.ReplaceAll(domain, ".", "")

	bases := []string{
		domain,
		baseName,
		baseNameDot,
		strings.Split(domain, ".")[0], // Just the company name
	}

	suffixes := []string{
		"", "-dev", "-staging", "-prod", "-production", "-test", "-backup",
		"-assets", "-static", "-media", "-uploads", "-data", "-files",
		"-public", "-private", "-internal", "-www", "-cdn", "-images",
		"-logs", "-backups", "-archive", "-temp", "-tmp", "-config",
	}

	prefixes := []string{
		"", "dev-", "staging-", "prod-", "production-", "test-", "backup-",
		"assets-", "static-", "media-", "uploads-", "data-", "files-",
	}

	for _, base := range bases {
		for _, suffix := range suffixes {
			name := base + suffix
			if !seen[name] && len(name) >= 3 && len(name) <= 63 {
				seen[name] = true
				names = append(names, name)
			}
		}
		for _, prefix := range prefixes {
			name := prefix + base
			if !seen[name] && len(name) >= 3 && len(name) <= 63 {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	// Add subdomain-based names (limit to first 10)
	count := 0
	for _, sub := range subdomains {
		if count >= 10 {
			break
		}
		subBase := strings.Split(sub, ".")[0]
		if !seen[subBase] && len(subBase) >= 3 {
			seen[subBase] = true
			names = append(names, subBase)
			count++
		}
	}

	return names
}

func (s *CloudStorageScanner) testS3Bucket(ctx context.Context, name string) *CloudBucket {
	// Test multiple S3 regions
	regions := []string{"us-east-1", "us-west-2", "eu-west-1"}

	for _, region := range regions {
		url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", name, region)
		status, listable, files := s.testBucketURL(ctx, url)

		if status != "not_found" {
			bucket := &CloudBucket{
				Name:     name,
				Provider: "s3",
				URL:      url,
				Status:   status,
				Listable: listable,
			}
			if len(files) > 0 {
				bucket.FileCount = len(files)
				bucket.SampleFiles = files[:min(5, len(files))]
			}
			return bucket
		}
	}
	return nil
}

func (s *CloudStorageScanner) testGCSBucket(ctx context.Context, name string) *CloudBucket {
	url := fmt.Sprintf("https://storage.googleapis.com/%s/", name)
	status, listable, files := s.testBucketURL(ctx, url)

	if status != "not_found" {
		bucket := &CloudBucket{
			Name:     name,
			Provider: "gcs",
			URL:      url,
			Status:   status,
			Listable: listable,
		}
		if len(files) > 0 {
			bucket.FileCount = len(files)
			bucket.SampleFiles = files[:min(5, len(files))]
		}
		return bucket
	}
	return nil
}

func (s *CloudStorageScanner) testAzureBucket(ctx context.Context, name string) *CloudBucket {
	// Azure uses account.blob.core.windows.net/container format
	url := fmt.Sprintf("https://%s.blob.core.windows.net/$web/", name)
	status, listable, files := s.testBucketURL(ctx, url)

	if status != "not_found" {
		bucket := &CloudBucket{
			Name:     name,
			Provider: "azure",
			URL:      url,
			Status:   status,
			Listable: listable,
		}
		if len(files) > 0 {
			bucket.FileCount = len(files)
			bucket.SampleFiles = files[:min(5, len(files))]
		}
		return bucket
	}
	return nil
}

func (s *CloudStorageScanner) testBucketURL(ctx context.Context, url string) (status string, listable bool, files []string) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return "not_found", false, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)

	switch resp.StatusCode {
	case 200:
		// Check if directory listing is enabled
		if strings.Contains(bodyStr, "<ListBucketResult") ||
			strings.Contains(bodyStr, "<EnumerationResults") ||
			strings.Contains(bodyStr, "<Contents>") {
			files = extractBucketFiles(bodyStr)
			return "open", true, files
		}
		return "open", false, nil
	case 403:
		// Bucket exists but access denied
		if strings.Contains(bodyStr, "AccessDenied") ||
			strings.Contains(bodyStr, "AuthorizationRequired") {
			return "private", false, nil
		}
		return "authenticated", false, nil
	case 404:
		return "not_found", false, nil
	default:
		return "unknown", false, nil
	}
}

func extractBucketFiles(xml string) []string {
	var files []string
	// Simple extraction - look for <Key> tags
	parts := strings.Split(xml, "<Key>")
	for i := 1; i < len(parts) && i <= 10; i++ {
		if idx := strings.Index(parts[i], "</Key>"); idx > 0 {
			files = append(files, parts[i][:idx])
		}
	}
	return files
}

// SaveCloudStorageResults saves results to JSON and text files
func (r *CloudStorageResult) SaveCloudStorageResults(dir string) error {
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(dir, "cloud_storage.json"), data, 0644)

	// Save open buckets to separate file
	f, err := os.Create(filepath.Join(dir, "open_buckets.txt"))
	if err != nil {
		return err
	}
	defer f.Close()
	for _, b := range r.Buckets {
		if b.Status == "open" {
			fmt.Fprintf(f, "[%s] %s - %s (listable: %v, files: %d)\n",
				b.Provider, b.Name, b.URL, b.Listable, b.FileCount)
		}
	}
	return nil
}
