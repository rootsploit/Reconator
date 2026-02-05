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
}

// PhaseStatus represents the current state of a phase
type PhaseStatus struct {
	Status   string        // pending, running, completed, failed, skipped
	Duration time.Duration // Duration when completed
	Error    string        // Error message if failed
}

// NewPhaseProgress creates a new progress tracker
func NewPhaseProgress(debug bool) *PhaseProgress {
	pp := &PhaseProgress{
		statuses: make(map[pipeline.Phase]PhaseStatus),
		counts:   make(map[pipeline.Phase]map[string]int),
		debug:    debug,
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

	if !pp.debug {
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

	if !pp.debug {
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

	if !pp.debug {
		pp.printPhaseStatus(phase, "failed", 0, nil)
	}
}

// MarkSkipped marks a phase as skipped
func (pp *PhaseProgress) MarkSkipped(phase pipeline.Phase) {
	pp.mu.Lock()
	pp.statuses[phase] = PhaseStatus{Status: "skipped"}
	pp.mu.Unlock()

	if !pp.debug {
		pp.printPhaseStatus(phase, "skipped", 0, nil)
	}
}

// SetCount updates a count metric for a phase (thread-safe)
func (pp *PhaseProgress) SetCount(phase pipeline.Phase, metric string, count int) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	if pp.counts[phase] == nil {
		pp.counts[phase] = make(map[string]int)
	}
	pp.counts[phase][metric] = count
}

// SetCounts updates multiple count metrics at once (more efficient)
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
	if pp.debug {
		return // Debug mode skips this
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

// getSortedPhases returns phases sorted by their phase number
func (pp *PhaseProgress) getSortedPhases() []pipeline.Phase {
	phases := pipeline.GetAllPhases()
	sort.Slice(phases, func(i, j int) bool {
		return pipeline.PhaseNumber[phases[i]] < pipeline.PhaseNumber[phases[j]]
	})
	return phases
}

// printPhaseStatus prints status update for a single phase (Osmedeus-style)
func (pp *PhaseProgress) printPhaseStatus(phase pipeline.Phase, status string, duration time.Duration, counts map[string]int) {
	name := pipeline.PhaseName[phase]
	icon := getStatusIcon(status)

	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.Faint)

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
		red.Println("FAILED")
	case "skipped":
		yellow.Print("├── ")
		white.Printf("[%s] ", icon)
		dim.Printf("%-25s ", name)
		dim.Println("skipped")
	}
}

// printCountsSummaryClean prints key counts in a clean format (max 4 items)
func (pp *PhaseProgress) printCountsSummaryClean(counts map[string]int) {
	if len(counts) == 0 {
		return
	}

	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite)

	// Priority order for display
	priority := []string{
		"subdomains", "validated", "alive_hosts", "alive",
		"urls", "vulnerabilities", "critical", "high",
		"screenshots", "techs", "discoveries",
	}

	var items []string
	shown := make(map[string]bool)

	// Show priority items first
	for _, key := range priority {
		if count, ok := counts[key]; ok && count > 0 {
			items = append(items, fmt.Sprintf("%s: %d", key, count))
			shown[key] = true
			if len(items) >= 4 {
				break
			}
		}
	}

	// If we have room, add other non-zero counts
	if len(items) < 4 {
		for key, count := range counts {
			if count > 0 && !shown[key] {
				items = append(items, fmt.Sprintf("%s: %d", key, count))
				if len(items) >= 4 {
					break
				}
			}
		}
	}

	if len(items) > 0 {
		cyan.Print("│ ")
		for i, item := range items {
			white.Print(item)
			if i < len(items)-1 {
				cyan.Print(" │ ")
			}
		}
	}
}

// printCountsSummary prints key counts inline (max 3 items)
func (pp *PhaseProgress) printCountsSummary(counts map[string]int) {
	if len(counts) == 0 {
		return
	}

	dim := color.New(color.Faint)

	// Priority order for display
	priority := []string{
		"subdomains", "validated", "alive_hosts", "alive",
		"urls", "vulnerabilities", "critical", "high",
		"screenshots", "techs", "discoveries",
	}

	var items []string
	shown := make(map[string]bool)

	// Show priority items first
	for _, key := range priority {
		if count, ok := counts[key]; ok && count > 0 {
			items = append(items, fmt.Sprintf("%s=%d", key, count))
			shown[key] = true
			if len(items) >= 3 {
				break
			}
		}
	}

	// If we have room, add other non-zero counts
	if len(items) < 3 {
		for key, count := range counts {
			if count > 0 && !shown[key] {
				items = append(items, fmt.Sprintf("%s=%d", key, count))
				if len(items) >= 3 {
					break
				}
			}
		}
	}

	if len(items) > 0 {
		dim.Printf(" [%s", items[0])
		for i := 1; i < len(items); i++ {
			dim.Printf(", %s", items[i])
		}
		dim.Printf("]")
	}
}

// PrintLevelHeader prints a level header (Osmedeus-style)
func (pp *PhaseProgress) PrintLevelHeader(level int, phases []pipeline.Phase) {
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.Faint)

	// Build phase names for header
	var names []string
	for _, p := range phases {
		names = append(names, pipeline.PhaseName[p])
	}

	if pp.debug {
		// Debug mode: verbose format with separator
		if len(phases) > 1 {
			cyan.Printf("\n[Level %d] Running %d phases in parallel: %v\n", level, len(phases), names)
		} else if len(phases) == 1 {
			cyan.Printf("\n[Level %d] Running: %v\n", level, names)
		}
		fmt.Println("───────────────────────────────────────────────────")
	} else {
		// Clean mode: tree-style format
		fmt.Println()
		cyan.Print("┌─")
		white.Printf(" Level %d ", level)
		if len(phases) > 1 {
			dim.Printf("(%d parallel)", len(phases))
		}
		fmt.Println()
	}
}

// PrintSummary prints final summary (Osmedeus-style)
func (pp *PhaseProgress) PrintSummary(totalDuration time.Duration, outputDir string) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	completed := 0
	failed := 0
	skipped := 0

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

	total := len(pp.statuses)

	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.Faint)

	fmt.Println()
	cyan.Println("╔══════════════════════════════════════════════════╗")
	cyan.Print("║")
	white.Print("                   SCAN COMPLETE                   ")
	cyan.Println("║")
	cyan.Println("╠══════════════════════════════════════════════════╣")

	// Status line
	cyan.Print("║  ")
	fmt.Print("Status: ")
	green.Printf("✓ %d completed", completed)
	if failed > 0 {
		fmt.Print(" │ ")
		red.Printf("✗ %d failed", failed)
	}
	if skipped > 0 {
		fmt.Print(" │ ")
		yellow.Printf("⊘ %d skipped", skipped)
	}
	// Padding to align box
	padding := 48 - (15 + len(fmt.Sprintf("%d", completed)) + len(fmt.Sprintf("%d", failed)) + len(fmt.Sprintf("%d", skipped)))
	if failed > 0 {
		padding -= 12
	}
	if skipped > 0 {
		padding -= 14
	}
	for i := 0; i < padding; i++ {
		fmt.Print(" ")
	}
	cyan.Println("║")

	// Time line
	cyan.Print("║  ")
	fmt.Print("Time:   ")
	white.Printf("%s", formatDuration(totalDuration))
	dim.Printf(" (%d phases)", total)
	timePadding := 48 - (8 + len(formatDuration(totalDuration)) + len(fmt.Sprintf(" (%d phases)", total)))
	for i := 0; i < timePadding; i++ {
		fmt.Print(" ")
	}
	cyan.Println("║")

	cyan.Println("╠══════════════════════════════════════════════════╣")

	// Results line
	cyan.Print("║  ")
	fmt.Print("Results: ")
	dim.Print(outputDir)
	resultPadding := 48 - (9 + len(outputDir))
	if resultPadding < 0 {
		resultPadding = 0
	}
	for i := 0; i < resultPadding; i++ {
		fmt.Print(" ")
	}
	cyan.Println("║")

	cyan.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
}

// IsDebug returns whether debug mode is enabled
func (pp *PhaseProgress) IsDebug() bool {
	return pp.debug
}

// Helper functions

func getStatusIcon(status string) string {
	switch status {
	case "pending":
		return "○"
	case "running":
		return "◐"
	case "completed":
		return "✓"
	case "failed":
		return "✗"
	case "skipped":
		return "⊘"
	default:
		return "○"
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	if seconds == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}
