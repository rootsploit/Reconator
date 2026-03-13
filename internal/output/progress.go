package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
)

// ProgressMessage represents a structured progress message
type ProgressMessage struct {
	Type          string                 `json:"type"`          // "progress", "result", "complete", "error"
	Phase         string                 `json:"phase,omitempty"`
	PhaseNumber   int                    `json:"phase_number,omitempty"`
	TotalPhases   int                    `json:"total_phases,omitempty"`
	Progress      float64                `json:"progress"`      // 0.0 - 1.0
	Message       string                 `json:"message,omitempty"`
	Timestamp     string                 `json:"timestamp"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Count         int                    `json:"count,omitempty"`
	PhasesCompleted []string             `json:"phases_completed,omitempty"`
	TotalResults  map[string]int        `json:"total_results,omitempty"`
}

// ProgressWriter handles structured JSON progress output
type ProgressWriter struct {
	mu           sync.Mutex
	config       *config.Config
	phaseIndex   int
	totalPhases  int
	phases       []string
	outputFile   *os.File
}

// NewProgressWriter creates a new progress writer
func NewProgressWriter(cfg *config.Config, totalPhases int, phases []string) *ProgressWriter {
	p := &ProgressWriter{
		config:      cfg,
		totalPhases: totalPhases,
		phases:      phases,
		phaseIndex:  0,
	}

	// Open progress file if specified
	if cfg.ProgressFile != "" {
		f, err := os.Create(cfg.ProgressFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not create progress file: %v\n", err)
		} else {
			p.outputFile = f
		}
	}

	return p
}

// EmitProgress emits a progress update
func (p *ProgressWriter) EmitProgress(phase string, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	msg := ProgressMessage{
		Type:        "progress",
		Phase:       phase,
		PhaseNumber: p.phaseIndex + 1,
		TotalPhases: p.totalPhases,
		Progress:    float64(p.phaseIndex) / float64(p.totalPhases),
		Message:     message,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	p.emit(msg)
}

// EmitPhaseStart marks the start of a new phase
func (p *ProgressWriter) EmitPhaseStart(phase string) {
	p.mu.Lock()
	p.phaseIndex++
	phaseName := phase
	if p.phaseIndex < len(p.phases) {
		phaseName = p.phases[p.phaseIndex]
	}
	p.mu.Unlock()

	msg := ProgressMessage{
		Type:        "progress",
		Phase:       phaseName,
		PhaseNumber: p.phaseIndex,
		TotalPhases: p.totalPhases,
		Progress:    float64(p.phaseIndex-1) / float64(p.totalPhases),
		Message:     fmt.Sprintf("Starting phase: %s", phaseName),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	p.emit(msg)
}

// EmitResult emits a result from a phase
func (p *ProgressWriter) EmitResult(phase string, data interface{}, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	msg := ProgressMessage{
		Type:    "result",
		Phase:   phase,
		Data:    toMap(data),
		Count:   count,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	p.emit(msg)
}

// EmitComplete emits a completion message
func (p *ProgressWriter) EmitComplete(totalResults map[string]int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	msg := ProgressMessage{
		Type:            "complete",
		PhasesCompleted: p.phases[:p.phaseIndex],
		TotalResults:    totalResults,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}

	p.emit(msg)
}

// EmitError emits an error message
func (p *ProgressWriter) EmitError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	msg := ProgressMessage{
		Type:      "error",
		Message:   err.Error(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	p.emit(msg)
}

// emit writes the message to appropriate outputs
func (p *ProgressWriter) emit(msg ProgressMessage) {
	// Write to stdout if JSONProgress is enabled
	if p.config.JSONProgress {
		jsonBytes, err := json.Marshal(msg)
		if err == nil {
			fmt.Println(string(jsonBytes))
		}
	}

	// Write to progress file if specified
	if p.outputFile != nil {
		jsonBytes, err := json.Marshal(msg)
		if err == nil {
			p.outputFile.Write(jsonBytes)
			p.outputFile.Write([]byte("\n"))
			p.outputFile.Sync()
		}
	}
}

// WriteProgressFile writes current progress to the progress file
func (p *ProgressWriter) WriteProgressFile(currentPhase string, hostsScanned, subdomainsFound, vulnsFound int) {
	if p.outputFile == nil {
		return
	}

	progress := map[string]interface{}{
		"current_phase":          currentPhase,
		"phase_index":            p.phaseIndex,
		"total_phases":           p.totalPhases,
		"percentage":             int(float64(p.phaseIndex) / float64(p.totalPhases) * 100),
		"hosts_scanned":          hostsScanned,
		"subdomains_found":       subdomainsFound,
		"vulnerabilities_found":  vulnsFound,
		"timestamp":              time.Now().UTC().Format(time.RFC3339),
	}

	jsonBytes, _ := json.MarshalIndent(progress, "", "  ")
	p.outputFile.Truncate(0)
	p.outputFile.Seek(0, 0)
	p.outputFile.Write(jsonBytes)
	p.outputFile.Sync()
}

// Close closes the progress writer
func (p *ProgressWriter) Close() {
	if p.outputFile != nil {
		p.outputFile.Close()
	}
}

// toMap converts an interface to a map
func toMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case map[string]interface{}:
		return val
	default:
		// Try to marshal and unmarshal
		if data, err := json.Marshal(val); err == nil {
			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err == nil {
				return result
			}
		}
		return nil
	}
}
