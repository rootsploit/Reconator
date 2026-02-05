package debug

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	enabled bool
	mu      sync.Mutex
	logs    []LogEntry
)

type LogEntry struct {
	Timestamp time.Time     `json:"timestamp"`
	Tool      string        `json:"tool"`
	Args      string        `json:"args"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"`
	Output    string        `json:"output,omitempty"`
}

// Enable turns on debug logging
func Enable() {
	mu.Lock()
	enabled = true
	mu.Unlock()
}

// IsEnabled returns whether debug logging is enabled
func IsEnabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled
}

// LogStart logs the start of a tool execution
func LogStart(tool string, args []string) time.Time {
	if !IsEnabled() {
		return time.Now()
	}
	start := time.Now()
	gray := color.New(color.FgHiBlack)
	gray.Printf("    [DEBUG %s] START: %s %s\n", start.Format("15:04:05.000"), tool, strings.Join(args, " "))
	return start
}

// LogEnd logs the completion of a tool execution
func LogEnd(tool string, args []string, start time.Time, err error, outputLines int) {
	if !IsEnabled() {
		return
	}
	duration := time.Since(start)
	end := time.Now()

	status := "OK"
	statusColor := color.New(color.FgGreen)
	if err != nil {
		status = fmt.Sprintf("ERROR: %v", err)
		statusColor = color.New(color.FgRed)
	}

	gray := color.New(color.FgHiBlack)
	gray.Printf("    [DEBUG %s] END:   %s ", end.Format("15:04:05.000"), tool)
	statusColor.Printf("%s", status)
	gray.Printf(" (duration: %s, output: %d lines)\n", duration.Round(time.Millisecond), outputLines)

	mu.Lock()
	logs = append(logs, LogEntry{
		Timestamp: end,
		Tool:      tool,
		Args:      strings.Join(args, " "),
		Duration:  duration,
		Status:    status,
	})
	mu.Unlock()
}

// LogPhaseStart logs the start of a phase
func LogPhaseStart(phase string) time.Time {
	if !IsEnabled() {
		return time.Now()
	}
	start := time.Now()
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("    [DEBUG %s] PHASE START: %s\n", start.Format("15:04:05.000"), phase)
	return start
}

// LogPhaseEnd logs the end of a phase
func LogPhaseEnd(phase string, start time.Time) {
	if !IsEnabled() {
		return
	}
	duration := time.Since(start)
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Printf("    [DEBUG %s] PHASE END:   %s (total: %s)\n", time.Now().Format("15:04:05.000"), phase, duration.Round(time.Millisecond))
}

// Summary prints a summary of all tool executions
func Summary() {
	if !IsEnabled() || len(logs) == 0 {
		return
	}

	cyan := color.New(color.FgCyan, color.Bold)
	fmt.Println()
	cyan.Println("═══════════════════════════════════════════════════════")
	cyan.Println("                    DEBUG SUMMARY")
	cyan.Println("═══════════════════════════════════════════════════════")

	var total time.Duration
	for _, l := range logs {
		status := "✓"
		if strings.HasPrefix(l.Status, "ERROR") {
			status = "✗"
		}
		fmt.Printf("  %s %-20s %10s\n", status, l.Tool, l.Duration.Round(time.Millisecond))
		total += l.Duration
	}

	fmt.Println("───────────────────────────────────────────────────────")
	fmt.Printf("  Total tool execution time: %s\n", total.Round(time.Millisecond))
	fmt.Printf("  Tools executed: %d\n", len(logs))
	cyan.Println("═══════════════════════════════════════════════════════")
}

// GetLogs returns all logged entries
func GetLogs() []LogEntry {
	mu.Lock()
	defer mu.Unlock()
	return append([]LogEntry{}, logs...)
}
