package screenshot

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	screenshotDir := filepath.Join(outputDir, "screenshots")
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
	return filepath.Join(c.cfg.OutputDir, "screenshots")
}
