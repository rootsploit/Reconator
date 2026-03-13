package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// JSONLEvent represents a single JSONL event emitted during scan
type JSONLEvent struct {
	Timestamp string      `json:"ts"`
	Phase     string      `json:"phase"`
	Type      string      `json:"type"` // "scan_start", "phase_start", "finding", "progress", "phase_complete", "scan_complete", "error"
	Data      interface{} `json:"data,omitempty"`
}

// JSONLEmitter writes JSONL events to a writer (typically stdout)
type JSONLEmitter struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewJSONLEmitter creates a new JSONL emitter
func NewJSONLEmitter(w io.Writer) *JSONLEmitter {
	return &JSONLEmitter{writer: w}
}

// Emit writes a single JSONL event
func (e *JSONLEmitter) Emit(event JSONLEvent) error {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal JSONL event: %w", err)
	}

	_, err = fmt.Fprintf(e.writer, "%s\n", data)
	return err
}

// EmitScanStart emits a scan start event
func (e *JSONLEmitter) EmitScanStart(target string, phases []string) error {
	return e.Emit(JSONLEvent{
		Phase: "scan",
		Type:  "scan_start",
		Data: map[string]interface{}{
			"target": target,
			"phases": phases,
		},
	})
}

// EmitPhaseStart emits a phase start event
func (e *JSONLEmitter) EmitPhaseStart(phase string) error {
	return e.Emit(JSONLEvent{
		Phase: phase,
		Type:  "phase_start",
	})
}

// EmitFinding emits a finding/result event
func (e *JSONLEmitter) EmitFinding(phase string, data interface{}) error {
	return e.Emit(JSONLEvent{
		Phase: phase,
		Type:  "finding",
		Data:  data,
	})
}

// EmitProgress emits a progress update event
func (e *JSONLEmitter) EmitProgress(phase string, percent int, message string) error {
	return e.Emit(JSONLEvent{
		Phase: phase,
		Type:  "progress",
		Data: map[string]interface{}{
			"percent": percent,
			"message": message,
		},
	})
}

// EmitPhaseComplete emits a phase completion event
func (e *JSONLEmitter) EmitPhaseComplete(phase string, summary interface{}) error {
	return e.Emit(JSONLEvent{
		Phase: phase,
		Type:  "phase_complete",
		Data:  summary,
	})
}

// EmitError emits an error event
func (e *JSONLEmitter) EmitError(phase string, err error) error {
	return e.Emit(JSONLEvent{
		Phase: phase,
		Type:  "error",
		Data: map[string]interface{}{
			"error": err.Error(),
		},
	})
}

// EmitScanComplete emits a scan completion event
func (e *JSONLEmitter) EmitScanComplete(target string, duration time.Duration, stats map[string]interface{}) error {
	data := map[string]interface{}{
		"target":       target,
		"duration_sec": duration.Seconds(),
	}
	for k, v := range stats {
		data[k] = v
	}
	return e.Emit(JSONLEvent{
		Phase: "scan",
		Type:  "scan_complete",
		Data:  data,
	})
}
