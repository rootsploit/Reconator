package trufflehog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// Secret represents a discovered secret by TruffleHog
type Secret struct {
	DetectorName string `json:"detector_name"`
	DetectorType string `json:"detector_type"`
	DecoderName  string `json:"decoder_name"`
	Verified     bool   `json:"verified"`
	Raw          string `json:"raw"`
	Redacted     string `json:"redacted"`
	SourceType   string `json:"source_type"` // web, js, html
	SourceURL    string `json:"source_url"`
	Line         int    `json:"line"`
}

// Result holds TruffleHog scan results
type Result struct {
	Secrets       []Secret          `json:"secrets"`
	TotalFound    int               `json:"total_found"`
	Verified      int               `json:"verified"`
	ByDetector    map[string]int    `json:"by_detector"`
	BySource      map[string]int    `json:"by_source"`
	Duration      time.Duration     `json:"duration"`
	FilesScanned  int               `json:"files_scanned"`
}

// Scanner performs secret scanning using TruffleHog
type Scanner struct {
	checker *tools.Checker
	client  *http.Client
}

// NewScanner creates a new TruffleHog scanner
func NewScanner(checker *tools.Checker) *Scanner {
	return &Scanner{
		checker: checker,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ScanWebTarget scans a web target and its JavaScript files for secrets
// Works without GitHub key - scans downloaded web content
func (s *Scanner) ScanWebTarget(ctx context.Context, targetURL string, jsURLs []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		ByDetector: make(map[string]int),
		BySource:   make(map[string]int),
	}

	if !s.checker.IsInstalled("trufflehog") {
		return nil, fmt.Errorf("trufflehog not installed")
	}

	fmt.Println("    [*] Scanning web content and JS files for secrets...")

	// Create temp directory for downloaded content
	tmpDir, err := os.MkdirTemp("", "trufflehog-web-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download main page HTML
	mainHTML, err := s.downloadContent(ctx, targetURL)
	if err == nil && len(mainHTML) > 0 {
		htmlFile := filepath.Join(tmpDir, "index.html")
		os.WriteFile(htmlFile, []byte(mainHTML), 0644)
		result.FilesScanned++
	}

	// Download JS files (limit to 50 for performance)
	maxJSFiles := 50
	if len(jsURLs) > maxJSFiles {
		jsURLs = jsURLs[:maxJSFiles]
		fmt.Printf("        Limiting to first %d JS files\n", maxJSFiles)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Concurrent downloads

	for _, jsURL := range jsURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, err := s.downloadContent(ctx, url)
			if err != nil || len(content) == 0 {
				return
			}

			// Create filename from URL
			filename := filepath.Base(url)
			if filename == "" || filename == "/" {
				filename = "script.js"
			}
			if !strings.HasSuffix(filename, ".js") {
				filename += ".js"
			}

			jsFile := filepath.Join(tmpDir, filename)
			os.WriteFile(jsFile, []byte(content), 0644)
			result.FilesScanned++
		}(jsURL)
	}
	wg.Wait()

	fmt.Printf("        Downloaded %d files to scan\n", result.FilesScanned)

	// Run TruffleHog on the temp directory
	secrets, err := s.runTruffleHog(tmpDir)
	if err != nil {
		return nil, err
	}

	// Process results
	for _, secret := range secrets {
		result.Secrets = append(result.Secrets, secret)
		result.ByDetector[secret.DetectorName]++
		result.BySource[secret.SourceType]++
		if secret.Verified {
			result.Verified++
		}
	}

	result.TotalFound = len(result.Secrets)
	result.Duration = time.Since(start)

	fmt.Printf("        Found %d secrets (%d verified)\n", result.TotalFound, result.Verified)
	if len(result.ByDetector) > 0 {
		fmt.Print("        By detector: ")
		for detector, count := range result.ByDetector {
			fmt.Printf("%s=%d ", detector, count)
		}
		fmt.Println()
	}

	return result, nil
}

// downloadContent fetches content from a URL
func (s *Scanner) downloadContent(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconator/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	// Read up to 10MB
	buf := make([]byte, 10*1024*1024)
	n, _ := resp.Body.Read(buf)

	return string(buf[:n]), nil
}

// runTruffleHog executes TruffleHog on a directory
func (s *Scanner) runTruffleHog(targetDir string) ([]Secret, error) {
	// TruffleHog v3+ command: trufflehog filesystem --directory=<dir> --json
	args := []string{
		"filesystem",
		"--directory=" + targetDir,
		"--json",
		"--no-update", // Don't check for updates
		"--fail",      // Exit with error code if secrets found (we'll ignore this)
	}

	r := exec.Run("trufflehog", args, &exec.Options{
		Timeout: 5 * time.Minute,
	})

	// TruffleHog exits with non-zero if secrets found, which is expected
	// Only fail if actual execution error (not secret-found error)
	if r.Error != nil && !strings.Contains(r.Error.Error(), "exit status") {
		return nil, fmt.Errorf("trufflehog execution failed: %w", r.Error)
	}

	// Parse JSON output
	var secrets []Secret
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var finding struct {
			DetectorName string `json:"DetectorName"`
			DetectorType string `json:"DetectorType"`
			DecoderName  string `json:"DecoderName"`
			Verified     bool   `json:"Verified"`
			Raw          string `json:"Raw"`
			Redacted     string `json:"Redacted"`
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int64  `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}

		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}

		// Determine source type from file extension
		sourceType := "web"
		filename := finding.SourceMetadata.Data.Filesystem.File
		if strings.HasSuffix(filename, ".js") {
			sourceType = "js"
		} else if strings.HasSuffix(filename, ".html") {
			sourceType = "html"
		}

		secrets = append(secrets, Secret{
			DetectorName: finding.DetectorName,
			DetectorType: finding.DetectorType,
			DecoderName:  finding.DecoderName,
			Verified:     finding.Verified,
			Raw:          maskSecret(finding.Raw),
			Redacted:     finding.Redacted,
			SourceType:   sourceType,
			SourceURL:    filename,
			Line:         int(finding.SourceMetadata.Data.Filesystem.Line),
		})
	}

	return secrets, nil
}

// maskSecret masks sensitive parts of the secret
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	if len(secret) <= 20 {
		return secret[:4] + "***"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

// SaveResults saves TruffleHog results to files
func (r *Result) SaveResults(dir string) error {
	os.MkdirAll(dir, 0755)

	// Save JSON
	data, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(dir, "trufflehog_secrets.json"), data, 0644)

	// Save text summary
	f, err := os.Create(filepath.Join(dir, "trufflehog_secrets.txt"))
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "TruffleHog Secret Scan Results\n")
	fmt.Fprintf(f, "==============================\n\n")
	fmt.Fprintf(f, "Total secrets found: %d\n", r.TotalFound)
	fmt.Fprintf(f, "Verified secrets: %d\n", r.Verified)
	fmt.Fprintf(f, "Files scanned: %d\n\n", r.FilesScanned)

	if len(r.Secrets) > 0 {
		fmt.Fprintf(f, "Discovered Secrets:\n")
		fmt.Fprintf(f, "-------------------\n\n")
		for i, secret := range r.Secrets {
			fmt.Fprintf(f, "%d. [%s] %s\n", i+1, secret.DetectorName, secret.SourceType)
			fmt.Fprintf(f, "   File: %s (line %d)\n", secret.SourceURL, secret.Line)
			fmt.Fprintf(f, "   Raw: %s\n", secret.Raw)
			if secret.Verified {
				fmt.Fprintf(f, "   ⚠️  VERIFIED - This secret is valid!\n")
			}
			if secret.Redacted != "" {
				fmt.Fprintf(f, "   Redacted: %s\n", secret.Redacted)
			}
			fmt.Fprintf(f, "\n")
		}
	}

	return nil
}
