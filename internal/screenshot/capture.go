package screenshot

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// Common Chrome paths by OS
var chromePaths = map[string][]string{
	"darwin": {
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	},
	"linux": {
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
	},
	"windows": {
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	},
}

// findChromePath finds an installed Chrome/Chromium browser
func findChromePath() string {
	paths, ok := chromePaths[runtime.GOOS]
	if !ok {
		return ""
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

type Capturer struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewCapturer(cfg *config.Config, checker *tools.Checker) *Capturer {
	return &Capturer{cfg: cfg, c: checker}
}

// Capture runs gowitness on a list of URLs (legacy method for backward compatibility)
func (c *Capturer) Capture(urls []string) error {
	_, err := c.CaptureWithResult(urls)
	return err
}

// CaptureWithResult runs gowitness and returns clustering results
// Uses c.cfg.OutputDir as the base directory for screenshots
func (c *Capturer) CaptureWithResult(urls []string) (*Result, error) {
	return c.CaptureWithResultInDir(urls, c.cfg.OutputDir)
}

// CaptureWithResultInDir runs gowitness in a specific output directory
// This allows the pipeline to specify the target-specific output directory
func (c *Capturer) CaptureWithResultInDir(urls []string, outputDir string) (*Result, error) {
	start := time.Now()

	if !c.cfg.EnableScreenshots {
		return &Result{Duration: time.Since(start), Skipped: true, SkipReason: "disabled"}, nil
	}

	if !c.c.IsInstalled("gowitness") {
		fmt.Println("        [gowitness] Not installed - skipping screenshots")
		fmt.Println("        Install with: go install github.com/sensepost/gowitness@latest")
		return &Result{Duration: time.Since(start), Skipped: true, SkipReason: "gowitness not installed"}, nil
	}

	// Screenshots stored in 9-screenshots/screenshots/ directory
	screenshotDir := filepath.Join(outputDir, "9-screenshots", "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create screenshot directory: %w", err)
	}

	// Create temp file for URLs
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("gowitness-%d.txt", time.Now().UnixNano()))
	f, err := os.Create(tmpFile)
	if err != nil {
		return nil, err
	}
	for _, u := range urls {
		f.WriteString(u + "\n")
	}
	f.Close()
	defer os.Remove(tmpFile)

	fmt.Printf("        Capturing %d URLs...\n", len(urls))

	// Find Chrome path for gowitness v3 (required on macOS where Chrome isn't in PATH)
	chromePath := findChromePath()
	if chromePath != "" {
		fmt.Printf("        [gowitness] Using Chrome: %s\n", chromePath)
	} else {
		fmt.Println("        [gowitness] Warning: Chrome not found at common paths")
		fmt.Println("        [gowitness] gowitness v3 requires Chrome/Chromium to be installed")
	}

	// Try gowitness v3 syntax first, fall back to v2
	// v3: gowitness scan file -f urls.txt --screenshot-path output/
	// v2: gowitness file -f urls.txt -P output/ --no-http
	var r *exec.Result

	// Try v3 syntax first
	args := []string{"scan", "file", "-f", tmpFile, "--screenshot-path", screenshotDir, "--write-jsonl"}
	if chromePath != "" {
		args = append(args, "--chrome-path", chromePath)
	}
	if c.cfg.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", c.cfg.Threads))
	}

	r = exec.Run("gowitness", args, &exec.Options{Timeout: 30 * time.Minute})
	if r.Error != nil {
		// Try v2 syntax as fallback
		fmt.Println("        [gowitness] Trying v2 syntax...")
		args = []string{"file", "-f", tmpFile, "-P", screenshotDir, "--no-http"}
		if c.cfg.Threads > 0 {
			args = append(args, "--threads", fmt.Sprintf("%d", c.cfg.Threads))
		}
		r = exec.Run("gowitness", args, &exec.Options{Timeout: 30 * time.Minute})
	}

	if r.Error != nil {
		errMsg := fmt.Sprintf("gowitness failed: %v", r.Error)
		if r.Stderr != "" {
			// Check for Chrome-related errors
			if strings.Contains(r.Stderr, "chrome") || strings.Contains(r.Stderr, "executable file not found") {
				errMsg += "\nChrome/Chromium is required for gowitness v3."
				if runtime.GOOS == "darwin" {
					errMsg += "\nInstall with: brew install --cask google-chrome"
				} else if runtime.GOOS == "linux" {
					errMsg += "\nInstall with: apt install chromium-browser"
				}
			} else {
				errMsg += fmt.Sprintf("\nStderr: %s", r.Stderr)
			}
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Cluster screenshots by visual similarity
	fmt.Println("        Clustering similar screenshots...")
	result, err := ClusterScreenshots(screenshotDir, DefaultClusterConfig())
	if err != nil {
		// Return partial result if clustering fails
		return &Result{
			TotalCaptures: len(urls),
			Duration:      time.Since(start),
		}, nil
	}

	// Organize into folders by cluster
	if len(result.Clusters) > 0 {
		result.OrganizeIntoFolders(screenshotDir)
	}

	// Save clustering result
	result.SaveResult(screenshotDir)

	result.Duration = time.Since(start)
	return result, nil
}

// GetScreenshotDir returns the screenshot output directory
func (c *Capturer) GetScreenshotDir() string {
	return filepath.Join(c.cfg.OutputDir, "9-screenshots", "screenshots")
}

// CaptureWithPorts generates URLs for all open ports and captures screenshots
// This runs in parallel batches for efficiency
func (c *Capturer) CaptureWithPorts(aliveHosts []string, openPorts map[string][]int, outputDir string) (*Result, error) {
	start := time.Now()

	if !c.cfg.EnableScreenshots {
		return &Result{Duration: time.Since(start), Skipped: true, SkipReason: "disabled"}, nil
	}

	if !c.c.IsInstalled("gowitness") {
		fmt.Println("        [gowitness] Not installed - skipping screenshots")
		return &Result{Duration: time.Since(start), Skipped: true, SkipReason: "gowitness not installed"}, nil
	}

	// Generate URLs for all ports
	urls := generatePortURLs(aliveHosts, openPorts)
	if len(urls) == 0 {
		return &Result{Duration: time.Since(start), Skipped: true, SkipReason: "no URLs to capture"}, nil
	}

	fmt.Printf("        Generating screenshots for %d URLs (%d hosts, multiple ports)...\n", len(urls), len(aliveHosts))

	// Run gowitness with parallel workers
	return c.CaptureWithResultInDir(urls, outputDir)
}

// CaptureParallel captures screenshots in parallel batches for large URL sets
func (c *Capturer) CaptureParallel(urls []string, outputDir string, workers int) (*Result, error) {
	start := time.Now()

	if !c.cfg.EnableScreenshots {
		return &Result{Duration: time.Since(start), Skipped: true, SkipReason: "disabled"}, nil
	}

	if workers <= 0 {
		workers = 4 // Default parallel batches
	}

	// For small URL sets, use regular capture
	if len(urls) < workers*10 {
		return c.CaptureWithResultInDir(urls, outputDir)
	}

	// Screenshots stored in 9-screenshots/screenshots/ directory
	screenshotDir := filepath.Join(outputDir, "9-screenshots", "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create screenshot directory: %w", err)
	}

	// Split URLs into batches
	batchSize := (len(urls) + workers - 1) / workers
	var batches [][]string
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batches = append(batches, urls[i:end])
	}

	fmt.Printf("        Running %d parallel capture batches...\n", len(batches))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allResults []*Result
	var errors []error

	// Run batches in parallel
	for i, batch := range batches {
		wg.Add(1)
		go func(batchNum int, batchURLs []string) {
			defer wg.Done()

			// Create batch-specific temp file
			tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("gowitness-batch-%d-%d.txt", time.Now().UnixNano(), batchNum))
			f, err := os.Create(tmpFile)
			if err != nil {
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
				return
			}
			for _, u := range batchURLs {
				f.WriteString(u + "\n")
			}
			f.Close()
			defer os.Remove(tmpFile)

			// Run gowitness for this batch
			chromePath := findChromePath()
			args := []string{"scan", "file", "-f", tmpFile, "--screenshot-path", screenshotDir, "--write-jsonl"}
			if chromePath != "" {
				args = append(args, "--chrome-path", chromePath)
			}
			if c.cfg.Threads > 0 {
				args = append(args, "-t", fmt.Sprintf("%d", c.cfg.Threads/workers))
			}

			r := exec.Run("gowitness", args, &exec.Options{Timeout: 15 * time.Minute})
			if r.Error != nil {
				// Try v2 syntax
				args = []string{"file", "-f", tmpFile, "-P", screenshotDir, "--no-http"}
				r = exec.Run("gowitness", args, &exec.Options{Timeout: 15 * time.Minute})
			}

			mu.Lock()
			if r.Error != nil {
				errors = append(errors, r.Error)
			} else {
				allResults = append(allResults, &Result{TotalCaptures: len(batchURLs)})
			}
			mu.Unlock()
		}(i, batch)
	}

	wg.Wait()

	// Cluster all screenshots after parallel capture
	fmt.Println("        Clustering similar screenshots...")
	result, err := ClusterScreenshots(screenshotDir, DefaultClusterConfig())
	if err != nil {
		// Return partial result
		totalCaptured := 0
		for _, r := range allResults {
			totalCaptured += r.TotalCaptures
		}
		return &Result{
			TotalCaptures: totalCaptured,
			Duration:      time.Since(start),
		}, nil
	}

	if len(result.Clusters) > 0 {
		result.OrganizeIntoFolders(screenshotDir)
	}
	result.SaveResult(screenshotDir)
	result.Duration = time.Since(start)

	return result, nil
}

// generatePortURLs creates URLs for each host+port combination
func generatePortURLs(aliveHosts []string, openPorts map[string][]int) []string {
	seen := make(map[string]bool)
	var urls []string

	// First, add all alive hosts (these already have proper URLs)
	for _, host := range aliveHosts {
		if !seen[host] {
			seen[host] = true
			urls = append(urls, host)
		}
	}

	// Then add port-specific URLs for each host with open ports
	httpsCapablePorts := map[int]bool{443: true, 8443: true, 9443: true, 4443: true}
	httpPorts := map[int]bool{80: true, 8080: true, 8000: true, 8888: true, 3000: true, 5000: true}

	for host, ports := range openPorts {
		// Clean hostname (remove protocol if present)
		cleanHost := host
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			cleanHost = u.Host
		}
		// Remove port from host if present
		if idx := strings.LastIndex(cleanHost, ":"); idx > 0 && idx < len(cleanHost)-1 {
			cleanHost = cleanHost[:idx]
		}

		for _, port := range ports {
			var portURL string
			if httpsCapablePorts[port] || port > 1000 {
				// Try HTTPS for common HTTPS ports and high ports
				portURL = fmt.Sprintf("https://%s:%d", cleanHost, port)
			} else if httpPorts[port] {
				portURL = fmt.Sprintf("http://%s:%d", cleanHost, port)
			} else {
				// Default to HTTPS for unknown ports
				portURL = fmt.Sprintf("https://%s:%d", cleanHost, port)
			}

			if !seen[portURL] {
				seen[portURL] = true
				urls = append(urls, portURL)
			}
		}
	}

	return urls
}
