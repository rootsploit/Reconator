package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
)

// Phase directories in order
var PhaseDirs = []string{
	"0-iprange",
	"1-subdomains",
	"2-waf",
	"3-ports",
	"4-vhost",
	"4-takeover",
	"5-historic",
	"6-tech",
	"6b-secheaders",
	"7-dirbrute",
	"7b-jsanalysis",
	"8-vulnscan",
	"9-aiguided",
	"10-aiguided",
	"screenshots",
	"osint",
}

// WatchEvent represents a file system event during watch mode
type WatchEvent struct {
	Type      string                 `json:"type"` // "new_file", "updated_file"
	Phase     string                 `json:"phase"`
	File      string                 `json:"file"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp string                 `json:"timestamp"`
}

// Watcher watches an output directory for new files
type Watcher struct {
	config     *config.Config
	outputDir  string
	knownFiles map[string]time.Time
	mu         sync.Mutex
	stopChan   chan bool
}

// NewWatcher creates a new directory watcher
func NewWatcher(cfg *config.Config, outputDir string) *Watcher {
	return &Watcher{
		config:     cfg,
		outputDir:  outputDir,
		knownFiles: make(map[string]time.Time),
		stopChan:   make(chan bool),
	}
}

// Start starts watching the output directory
func (w *Watcher) Start(callback func(WatchEvent)) error {
	// First, scan existing files
	w.scanExisting()

	// Start polling loop
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.checkForChanges(callback)
		case <-w.stopChan:
			return nil
		}
	}
}

// Stop stops the watcher
func (w *Watcher) Stop() {
	close(w.stopChan)
}

// scanExisting scans existing files and marks them as known
func (w *Watcher) scanExisting() {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, phaseDir := range PhaseDirs {
		dirPath := filepath.Join(w.outputDir, phaseDir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				w.knownFiles[path] = info.ModTime()
			}
			return nil
		})
	}
}

// checkForChanges checks for new or updated files
func (w *Watcher) checkForChanges(callback func(WatchEvent)) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, phaseDir := range PhaseDirs {
		dirPath := filepath.Join(w.outputDir, phaseDir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Check if file is new or modified
			knownTime, known := w.knownFiles[path]
			isNew := !known
			isModified := known && info.ModTime().After(knownTime)

			if isNew || isModified {
				w.knownFiles[path] = info.ModTime()

				// Try to parse as JSON
				var data map[string]interface{}
				if content, err := os.ReadFile(path); err == nil {
					json.Unmarshal(content, &data)
				}

				event := WatchEvent{
					Type:      "new_file",
					Phase:     phaseDir,
					File:      filepath.Base(path),
					Data:      data,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}

				if isModified {
					event.Type = "updated_file"
				}

				// Emit the event
				callback(event)

				// Also output as JSON if JSONProgress is enabled
				if w.config.JSONProgress {
					jsonBytes, _ := json.Marshal(event)
					fmt.Println(string(jsonBytes))
				}
			}

			return nil
		})
	}
}

// WatchMode runs watch mode and blocks until stopped
func WatchMode(cfg *config.Config, outputDir string, callback func(WatchEvent)) error {
	watcher := NewWatcher(cfg, outputDir)

	// Ensure output directory exists
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return fmt.Errorf("output directory does not exist: %s", outputDir)
	}

	fmt.Printf("[+] Watching %s for changes...\n", outputDir)

	// Start watching
	err := watcher.Start(callback)
	if err != nil {
		return err
	}

	return nil
}

// GetPhaseFromPath determines the phase from a file path
func GetPhaseFromPath(path string) string {
	for _, phase := range PhaseDirs {
		if strings.Contains(path, phase) {
			return phase
		}
	}
	return "unknown"
}
