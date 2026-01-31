package runner

import (
	"fmt"
	"sync"

	"github.com/fatih/color"
)

// StepStatus represents the state of an individual step within a phase
type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepCompleted StepStatus = "completed"
	StepSkipped   StepStatus = "skipped"
	StepFailed    StepStatus = "failed"
)

// StepResult holds the result of a step execution
type StepResult struct {
	Name   string
	Status StepStatus
	Count  int    // Number of items found/processed
	Reason string // Skip/fail reason
}

// StepReporter interface for reporting step progress
// Phases can accept this interface to report granular progress
type StepReporter interface {
	ReportStep(name string, status StepStatus, count int)
	ReportStepSkipped(name string, reason string)
	ReportStepFailed(name string, err error)
}

// StepProgressReporter provides step-level progress reporting within a phase
// Thread-safe for parallel tool execution
type StepProgressReporter struct {
	mu      sync.Mutex
	phase   string
	steps   []StepResult
	verbose bool
	indent  string
}

// NewStepProgressReporter creates a reporter for a phase
func NewStepProgressReporter(phaseName string, verbose bool) *StepProgressReporter {
	return &StepProgressReporter{
		phase:   phaseName,
		steps:   make([]StepResult, 0),
		verbose: verbose,
		indent:  "      ", // 6 spaces for nested step output under phase
	}
}

// ReportStep reports progress for a completed step
func (r *StepProgressReporter) ReportStep(name string, status StepStatus, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := StepResult{Name: name, Status: status, Count: count}
	r.steps = append(r.steps, result)

	if r.verbose {
		r.printStep(result)
	}
}

// ReportStepSkipped reports a skipped step with reason
func (r *StepProgressReporter) ReportStepSkipped(name string, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := StepResult{Name: name, Status: StepSkipped, Reason: reason}
	r.steps = append(r.steps, result)

	if r.verbose {
		r.printStep(result)
	}
}

// ReportStepFailed reports a failed step
func (r *StepProgressReporter) ReportStepFailed(name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	reason := ""
	if err != nil {
		reason = err.Error()
	}
	result := StepResult{Name: name, Status: StepFailed, Reason: reason}
	r.steps = append(r.steps, result)

	if r.verbose {
		r.printStep(result)
	}
}

func (r *StepProgressReporter) printStep(step StepResult) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)

	// Tree branch character (all use same prefix for simplicity in parallel execution)
	branch := "├─"

	icon := getStepIcon(step.Status)

	switch step.Status {
	case StepCompleted:
		if step.Count > 0 {
			green.Printf("%s%s %s %s ", r.indent, branch, icon, step.Name)
			dim.Printf("(%d)\n", step.Count)
		} else {
			green.Printf("%s%s %s %s\n", r.indent, branch, icon, step.Name)
		}
	case StepSkipped:
		yellow.Printf("%s%s %s %s ", r.indent, branch, icon, step.Name)
		if step.Reason != "" {
			dim.Printf("(%s)\n", step.Reason)
		} else {
			fmt.Println()
		}
	case StepFailed:
		red.Printf("%s%s %s %s ", r.indent, branch, icon, step.Name)
		if step.Reason != "" {
			dim.Printf("(%s)\n", step.Reason)
		} else {
			fmt.Println("FAILED")
		}
	case StepRunning:
		dim.Printf("%s%s %s %s...\n", r.indent, branch, icon, step.Name)
	default:
		dim.Printf("%s%s %s %s\n", r.indent, branch, icon, step.Name)
	}
}

// getStepIcon returns the icon for a step status (Osmedeus-style)
func getStepIcon(status StepStatus) string {
	switch status {
	case StepCompleted:
		return "✓"
	case StepSkipped:
		return "⏹"
	case StepFailed:
		return "✗"
	case StepRunning:
		return "◐"
	case StepPending:
		return "○"
	default:
		return "○"
	}
}

// GetSteps returns all recorded steps (for summary/logging)
func (r *StepProgressReporter) GetSteps() []StepResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]StepResult{}, r.steps...)
}

// GetCompletedCount returns count of completed steps
func (r *StepProgressReporter) GetCompletedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, s := range r.steps {
		if s.Status == StepCompleted {
			count++
		}
	}
	return count
}

// GetSkippedCount returns count of skipped steps
func (r *StepProgressReporter) GetSkippedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, s := range r.steps {
		if s.Status == StepSkipped {
			count++
		}
	}
	return count
}

// NilStepReporter is a no-op reporter for when verbose mode is disabled
type NilStepReporter struct{}

func (r *NilStepReporter) ReportStep(name string, status StepStatus, count int)    {}
func (r *NilStepReporter) ReportStepSkipped(name string, reason string)            {}
func (r *NilStepReporter) ReportStepFailed(name string, err error)                 {}

// StringStepReporter wraps StepProgressReporter to accept string-based status
// This allows packages (like subdomain) to use a simple string-based interface
// without importing runner.StepStatus, avoiding circular imports
type StringStepReporter struct {
	reporter *StepProgressReporter
}

// NewStringStepReporter creates a string-based wrapper around StepProgressReporter
func NewStringStepReporter(reporter *StepProgressReporter) *StringStepReporter {
	return &StringStepReporter{reporter: reporter}
}

// ReportStep reports a step with string-based status
func (r *StringStepReporter) ReportStep(name string, status string, count int) {
	if r.reporter == nil {
		return
	}
	// Convert string status to StepStatus
	var s StepStatus
	switch status {
	case "completed":
		s = StepCompleted
	case "skipped":
		s = StepSkipped
	case "failed":
		s = StepFailed
	case "running":
		s = StepRunning
	case "pending":
		s = StepPending
	default:
		s = StepCompleted
	}
	r.reporter.ReportStep(name, s, count)
}

// ReportStepSkipped reports a skipped step
func (r *StringStepReporter) ReportStepSkipped(name string, reason string) {
	if r.reporter != nil {
		r.reporter.ReportStepSkipped(name, reason)
	}
}

// ReportStepFailed reports a failed step
func (r *StringStepReporter) ReportStepFailed(name string, err error) {
	if r.reporter != nil {
		r.reporter.ReportStepFailed(name, err)
	}
}
