package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Storage defines the interface for phase output storage
// Implementations must be efficient - no blocking operations during phase execution
type Storage interface {
	// Write stores data at the given path
	Write(ctx context.Context, path string, data []byte) error

	// WriteJSON stores data as formatted JSON
	WriteJSON(ctx context.Context, path string, data interface{}) error

	// Read retrieves data from the given path
	Read(ctx context.Context, path string) ([]byte, error)

	// Exists checks if a path exists
	Exists(ctx context.Context, path string) (bool, error)

	// List returns all files under a prefix
	List(ctx context.Context, prefix string) ([]string, error)

	// BaseDir returns the root storage directory
	BaseDir() string
}

// LocalStorage implements Storage for local filesystem
// Zero-overhead design: direct file I/O with no buffering layers
type LocalStorage struct {
	baseDir string
}

// NewLocalStorage creates a new local storage instance
func NewLocalStorage(baseDir string) *LocalStorage {
	return &LocalStorage{baseDir: baseDir}
}

// BaseDir returns the root storage directory
func (s *LocalStorage) BaseDir() string {
	return s.baseDir
}

// Write stores data at the given path
func (s *LocalStorage) Write(ctx context.Context, path string, data []byte) error {
	fullPath := filepath.Join(s.baseDir, path)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}

	// Direct write - no buffering overhead
	return os.WriteFile(fullPath, data, 0644)
}

// WriteJSON stores data as formatted JSON
func (s *LocalStorage) WriteJSON(ctx context.Context, path string, data interface{}) error {
	fullPath := filepath.Join(s.baseDir, path)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}

	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// Read retrieves data from the given path
func (s *LocalStorage) Read(ctx context.Context, path string) ([]byte, error) {
	fullPath := filepath.Join(s.baseDir, path)
	return os.ReadFile(fullPath)
}

// Exists checks if a path exists
func (s *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	fullPath := filepath.Join(s.baseDir, path)
	_, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// List returns all files under a prefix
func (s *LocalStorage) List(ctx context.Context, prefix string) ([]string, error) {
	fullPath := filepath.Join(s.baseDir, prefix)
	var files []string

	err := filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(s.baseDir, path)
			files = append(files, relPath)
		}
		return nil
	})

	return files, err
}

// WriteLines writes a slice of strings to a file (one per line)
// Efficient: single allocation for content
func (s *LocalStorage) WriteLines(ctx context.Context, path string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}

	content := strings.Join(lines, "\n") + "\n"
	return s.Write(ctx, path, []byte(content))
}

// PhaseOutput is the standardized output format for all phases
// Metadata is computed AFTER phase completion - zero overhead during execution
type PhaseOutput struct {
	Meta   PhaseMeta   `json:"meta"`
	Stats  PhaseStats  `json:"stats"`
	Data   interface{} `json:"data"`
	Errors []string    `json:"errors,omitempty"`
}

// PhaseMeta contains phase execution metadata
type PhaseMeta struct {
	Phase     string    `json:"phase"`
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`
	Status    string    `json:"status"` // "completed", "failed", "partial"
	Version   string    `json:"version"`
}

// PhaseStats contains phase statistics
type PhaseStats struct {
	Total    int            `json:"total"`
	BySource map[string]int `json:"by_source,omitempty"`
	ByStatus map[string]int `json:"by_status,omitempty"`
}

// ScanMeta contains overall scan metadata
type ScanMeta struct {
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Status    string    `json:"status"` // "running", "completed", "failed"
	Version   string    `json:"version"`
	Phases    []string  `json:"phases"`
	Config    ScanConfig `json:"config"`
}

// ScanConfig captures scan configuration for reproducibility
type ScanConfig struct {
	Threads     int  `json:"threads"`
	DNSThreads  int  `json:"dns_threads"`
	RateLimit   int  `json:"rate_limit"`
	PassiveMode bool `json:"passive_mode"`
}

// NewPhaseOutput creates a new phase output with metadata
// Called AFTER phase completion - no overhead during execution
func NewPhaseOutput(phase, scanID, target, version string, startTime time.Time, data interface{}, total int) *PhaseOutput {
	endTime := time.Now()
	return &PhaseOutput{
		Meta: PhaseMeta{
			Phase:     phase,
			ScanID:    scanID,
			Target:    target,
			StartTime: startTime,
			EndTime:   endTime,
			Duration:  endTime.Sub(startTime).String(),
			Status:    "completed",
			Version:   version,
		},
		Stats: PhaseStats{
			Total: total,
		},
		Data: data,
	}
}

// WithBySource adds source breakdown to stats
func (p *PhaseOutput) WithBySource(sources map[string]int) *PhaseOutput {
	p.Stats.BySource = sources
	return p
}

// WithErrors adds error messages
func (p *PhaseOutput) WithErrors(errors []string) *PhaseOutput {
	p.Errors = errors
	if len(errors) > 0 {
		p.Meta.Status = "partial"
	}
	return p
}

// GenerateScanID creates a unique scan identifier
// Format: short UUID (e.g., "a1b2c3d4")
// Uses 8 hex characters (4 bytes) for short, readable IDs
func GenerateScanID() string {
	// 4 random bytes = 8 hex chars
	// Probability of collision: ~1 in 4 billion
	b := make([]byte, 4)
	rand.Read(b)

	return hex.EncodeToString(b)
}
