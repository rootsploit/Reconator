package runner

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/pipeline"
)

// PhaseProgress tracks the status of all phases for display
// Thread-safe and designed for minimal overhead
type PhaseProgress struct {
	mu       sync.RWMutex
	statuses map[pipeline.Phase]PhaseStatus
	counts   map[pipeline.Phase]map[string]int
	debug    bool
	silent   bool
}

// PhaseStatus represents the current state of a phase
type PhaseStatus struct {
	Status   string        // pending, running, completed, failed, skipped
	Duration time.Duration // Duration when completed
	Error    string        // Error message if failed
}

// NewPhaseProgress creates a new progress tracker
func NewPhaseProgress(debug, silent bool) *PhaseProgress {
	pp := &PhaseProgress{
		statuses: make(map[pipeline.Phase]PhaseStatus),
		counts:   make(map[pipeline.Phase]map[string]int),
		debug:    debug,
		silent:   silent,
	}
	// Initialize all phases as pending
	for _, phase := range pipeline.GetAllPhases() {
		pp.statuses[phase] = PhaseStatus{Status: "pending"}
		pp.counts[phase] = make(map[string]int)
	}
	return pp
}

// MarkRunning marks a phase as running
func (pp *PhaseProgress) MarkRunning(phase pipeline.Phase) {
	pp.mu.Lock()
	pp.statuses[phase] = PhaseStatus{Status: "running"}
	pp.mu.Unlock()

	if !pp.debug && !pp.silent {
		pp.printPhaseStatus(phase, "running", 0, nil)
	}
}

// MarkCompleted marks a phase as completed with duration
func (pp *PhaseProgress) MarkCompleted(phase pipeline.Phase, duration time.Duration) {
	pp.mu.Lock()
	pp.statuses[phase] = PhaseStatus{Status: "completed", Duration: duration}
	counts := make(map[string]int)
	for k, v := range pp.counts[phase] {
		counts[k] = v
	}
	pp.mu.Unlock()

	if !pp.debug && !pp.silent {
		pp.printPhaseStatus(phase, "completed", duration, counts)
	}
}

// MarkFailed marks a phase as failed
func (pp *PhaseProgress) MarkFailed(phase pipeline.Phase, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	pp.mu.Lock()
	pp.statuses[phase] = PhaseStatus{Status: "failed", Error: errMsg}
	pp.mu.Unlock()

	if !pp.debug && !pp.silent {
		pp.printPhaseStatus(phase, "failed", 0, nil)
	}
}

// MarkSkipped marks a phase as skipped
func (pp *PhaseProgress) MarkSkipped(phase pipeline.Phase) {
	pp.mu.Lock()
	pp.statuses[phase] = PhaseStatus{Status: "skipped"}
	pp.mu.Unlock()

	if !pp.debug && !pp.silent {
		pp.printPhaseStatus(phase, "skipped", 0, nil)
	}
}

// SetCounts sets the counts/metrics for a phase
func (pp *PhaseProgress) SetCounts(phase pipeline.Phase, metrics map[string]int) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	if pp.counts[phase] == nil {
		pp.counts[phase] = make(map[string]int)
	}
	for k, v := range metrics {
		pp.counts[phase][k] = v
	}
}

// PrintPhaseList prints all phases in sequence (sorted by phase number) - Osmedeus-style
func (pp *PhaseProgress) PrintPhaseList() {
	if pp.debug || pp.silent {
		return // Debug/silent mode skips this
	}

	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.Faint)

	fmt.Println()
	cyan.Println("┌──────────────────────────────────────────────────┐")
	cyan.Print("│")
	white.Print("              RECONNAISSANCE PHASES               ")
	cyan.Println("│")
	cyan.Println("├──────────────────────────────────────────────────┤")

	// Get phases sorted by phase number (0, 1, 2, ... 11)
	phases := pp.getSortedPhases()

	for i, phase := range phases {
		num := pipeline.PhaseNumber[phase]
		name := pipeline.PhaseName[phase]
		cyan.Print("│  ")
		dim.Printf("○ [%2d] %-38s", num, name)
		cyan.Println("│")

		// Add separator every 4 phases for visual grouping
		if (i+1)%4 == 0 && i < len(phases)-1 {
			cyan.Println("│                                                  │")
		}
	}
	cyan.Println("└──────────────────────────────────────────────────┘")
	fmt.Println()
}

// UpdateStatus updates the status of a phase with optional duration and error
func (pp *PhaseProgress) UpdateStatus(phase pipeline.Phase, status string, duration time.Duration, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	pp.mu.Lock()
	pp.statuses[phase] = PhaseStatus{Status: status, Duration: duration, Error: errMsg}
	pp.mu.Unlock()

	if !pp.debug {
		pp.printPhaseStatus(phase, status, duration, nil)
	}
}

// GetStatus returns the current status of a phase
func (pp *PhaseProgress) GetStatus(phase pipeline.Phase) PhaseStatus {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	return pp.statuses[phase]
}

// GetCounts returns the current counts for a phase
func (pp *PhaseProgress) GetCounts(phase pipeline.Phase) map[string]int {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	counts := make(map[string]int)
	for k, v := range pp.counts[phase] {
		counts[k] = v
	}
	return counts
}

// printPhaseStatus prints a single phase status update - Osmedeus-style
func (pp *PhaseProgress) printPhaseStatus(phase pipeline.Phase, status string, duration time.Duration, counts map[string]int) {
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)

	name := pipeline.PhaseName[phase]
	icon := pp.getStatusIcon(status)

	// Format: ├── [icon] Phase Name                    (duration) [metrics]
	switch status {
	case "running":
		cyan.Print("├── ")
		white.Printf("[%s] ", icon)
		cyan.Printf("%-25s ", name)
		dim.Println("running...")
	case "completed":
		green.Print("├── ")
		white.Printf("[%s] ", icon)
		green.Printf("%-25s ", name)
		if duration > 0 {
			dim.Printf("%-8s ", formatDuration(duration))
		}
		pp.printCountsSummaryClean(counts)
		fmt.Println()
	case "failed":
		red.Print("├── ")
		white.Printf("[%s] ", icon)
		red.Printf("%-25s ", name)
		dim.Println("failed")
	case "skipped":
		dim.Print("├── ")
		white.Printf("[%s] ", icon)
		dim.Printf("%-25s ", name)
		dim.Println("skipped")
	default:
		dim.Print("├── ")
		white.Printf("[%s] ", icon)
		dim.Printf("%-25s ", name)
		dim.Println(status)
	}
}

// printCountsSummaryClean prints a compact summary of counts (clean version)
func (pp *PhaseProgress) printCountsSummaryClean(counts map[string]int) {
	if len(counts) == 0 {
		return
	}

	dim := color.New(color.Faint)

	// Show up to 3 key metrics
	keys := []string{"alive", "total", "vulns", "hosts", "urls", "subdomains"}
	shown := 0

	for _, k := range keys {
		if v, ok := counts[k]; ok && shown < 3 {
			dim.Printf("%s:%d ", k, v)
			shown++
		}
	}

	// If no key metrics found, show first available
	if shown == 0 {
		for k, v := range counts {
			if shown >= 3 {
				break
			}
			dim.Printf("%s:%d ", k, v)
			shown++
		}
	}
}

// getStatusIcon returns the icon for a status
func (pp *PhaseProgress) getStatusIcon(status string) string {
	switch status {
	case "completed":
		return "✓"
	case "skipped":
		return "⏹"
	case "failed":
		return "✗"
	default:
		return "○"
	}
}

// getSortedPhases returns phases sorted by phase number
func (pp *PhaseProgress) getSortedPhases() []pipeline.Phase {
	phases := make([]pipeline.Phase, 0, len(pipeline.GetAllPhases()))
	for phase := range pipeline.PhaseNumber {
		phases = append(phases, phase)
	}
	sort.Slice(phases, func(i, j int) bool {
		return pipeline.PhaseNumber[phases[i]] < pipeline.PhaseNumber[phases[j]]
	})
	return phases
}

// formatDuration formats duration in human-readable format
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

// PrintLevelHeader prints level header with phases
func (pp *PhaseProgress) PrintLevelHeader(level int, phases []pipeline.Phase) {
	if pp.debug || pp.silent {
		return
	}

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	dim := color.New(color.Faint)

	fmt.Println()
	cyan.Printf("┌─ Level %d ", level)
	green.Print("(")
	for i, phase := range phases {
		if i > 0 {
			dim.Print(" + ")
		}
		dim.Print(pipeline.PhaseName[phase])
	}
	green.Println(")")
	fmt.Println()
}

// PrintSummary prints final scan summary
func (pp *PhaseProgress) PrintSummary(duration time.Duration, outputDir string) {
	if pp.debug || pp.silent {
		return
	}

	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.Faint)

	// Count completed/failed/skipped
	var completed, failed, skipped int
	pp.mu.RLock()
	for _, status := range pp.statuses {
		switch status.Status {
		case "completed":
			completed++
		case "failed":
			failed++
		case "skipped":
			skipped++
		}
	}
	pp.mu.RUnlock()

	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	green.Print("  Scan Complete: ")
	white.Printf("%s", formatDuration(duration))
	cyan.Println()
	dim.Printf("  Output: %s\n", outputDir)
	dim.Printf("  Phases: %d completed, %d failed, %d skipped\n", completed, failed, skipped)
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}
