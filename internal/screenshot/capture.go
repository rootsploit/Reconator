package screenshot

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Capturer struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewCapturer(cfg *config.Config, checker *tools.Checker) *Capturer {
	return &Capturer{cfg: cfg, c: checker}
}

// Capture runs gowitness on a list of URLs
func (c *Capturer) Capture(urls []string) error {
	if !c.cfg.EnableScreenshots {
		return nil
	}

	if !c.c.IsInstalled("gowitness") {
		return fmt.Errorf("gowitness is not installed")
	}

	screenshotDir := filepath.Join(c.cfg.OutputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return fmt.Errorf("failed to create screenshot directory: %w", err)
	}

	// Create temp file for URLs
	// We handle file creation manually to separate lines properly
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("gowitness-%d.txt", time.Now().UnixNano()))
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	for _, u := range urls {
		f.WriteString(u + "\n")
	}
	f.Close()
	defer os.Remove(tmpFile)

	// gowitness file -f urls.txt -P results/screenshots/ --no-http
	args := []string{"file", "-f", tmpFile, "-P", screenshotDir, "--no-http"}

	// Add concurrency
	if c.cfg.Threads > 0 {
		args = append(args, "--threads", fmt.Sprintf("%d", c.cfg.Threads))
	}

	fmt.Printf("[*] Capturing screenshots for %d URLs...\n", len(urls))
	r := exec.Run("gowitness", args, &exec.Options{Timeout: 30 * time.Minute})
	if r.Error != nil {
		return fmt.Errorf("gowitness failed: %v", r.Error)
	}

	return nil
}
