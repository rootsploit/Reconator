package tools

import (
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Spinner provides a loading animation
type Spinner struct {
	frames   []string
	interval time.Duration
	mu       sync.Mutex
	running  bool
	done     chan struct{}
	message  string
}

// NewSpinner creates a new spinner with the given message
func NewSpinner(message string) *Spinner {
	return &Spinner{
		frames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		interval: 80 * time.Millisecond,
		message:  message,
		done:     make(chan struct{}),
	}
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.done = make(chan struct{})
	s.mu.Unlock()

	go func() {
		cyan := color.New(color.FgCyan)
		i := 0
		for {
			select {
			case <-s.done:
				return
			default:
				s.mu.Lock()
				msg := s.message
				s.mu.Unlock()
				fmt.Printf("\r    %s %s", cyan.Sprint(s.frames[i]), msg)
				i = (i + 1) % len(s.frames)
				time.Sleep(s.interval)
			}
		}
	}()
}

// Update changes the spinner message
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// Stop stops the spinner and clears the line
func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()
	fmt.Print("\r\033[K") // Clear the line
}

// Success stops the spinner and shows a success message
func (s *Spinner) Success(message string) {
	s.Stop()
	green := color.New(color.FgGreen)
	fmt.Printf("    %s %s\n", green.Sprint("✓"), message)
}

// Fail stops the spinner and shows a failure message
func (s *Spinner) Fail(message string) {
	s.Stop()
	yellow := color.New(color.FgYellow)
	fmt.Printf("    %s %s\n", yellow.Sprint("✗"), message)
}

// Skip stops the spinner and shows a skip message
func (s *Spinner) Skip(message string) {
	s.Stop()
	gray := color.New(color.FgHiBlack)
	fmt.Printf("    %s %s\n", gray.Sprint("○"), message)
}

// ProgressBar provides a simple progress bar
type ProgressBar struct {
	total     int
	current   int
	width     int
	mu        sync.Mutex
	startTime time.Time
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		width:     30,
		startTime: time.Now(),
	}
}

// Increment increases the progress by 1
func (p *ProgressBar) Increment() {
	p.mu.Lock()
	p.current++
	p.render()
	p.mu.Unlock()
}

// SetCurrent sets the current progress
func (p *ProgressBar) SetCurrent(current int) {
	p.mu.Lock()
	p.current = current
	p.render()
	p.mu.Unlock()
}

func (p *ProgressBar) render() {
	percent := float64(p.current) / float64(p.total)
	filled := int(percent * float64(p.width))
	empty := p.width - filled

	cyan := color.New(color.FgCyan)
	gray := color.New(color.FgHiBlack)

	bar := cyan.Sprint(repeatStr("█", filled)) + gray.Sprint(repeatStr("░", empty))
	fmt.Printf("\r    [%s] %d/%d (%.0f%%)", bar, p.current, p.total, percent*100)
}

// Done finishes the progress bar
func (p *ProgressBar) Done() {
	elapsed := time.Since(p.startTime).Round(time.Second)
	fmt.Printf(" - %s\n", elapsed)
}

func repeatStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

// InstallStatus tracks the status of multiple installations
type InstallStatus struct {
	mu       sync.Mutex
	items    map[string]string // name -> status (pending, installing, ok, skip, fail)
	order    []string
	spinner  *Spinner
	messages map[string]string // name -> error message
}

// NewInstallStatus creates a new install status tracker
func NewInstallStatus(items []string) *InstallStatus {
	is := &InstallStatus{
		items:    make(map[string]string),
		order:    items,
		messages: make(map[string]string),
	}
	for _, item := range items {
		is.items[item] = "pending"
	}
	return is
}

// SetInstalling marks an item as currently installing
func (is *InstallStatus) SetInstalling(name string) {
	is.mu.Lock()
	is.items[name] = "installing"
	is.mu.Unlock()
}

// SetOK marks an item as successfully installed
func (is *InstallStatus) SetOK(name string) {
	is.mu.Lock()
	is.items[name] = "ok"
	is.mu.Unlock()
}

// SetSkip marks an item as skipped
func (is *InstallStatus) SetSkip(name, message string) {
	is.mu.Lock()
	is.items[name] = "skip"
	is.messages[name] = message
	is.mu.Unlock()
}

// SetFail marks an item as failed
func (is *InstallStatus) SetFail(name, message string) {
	is.mu.Lock()
	is.items[name] = "fail"
	is.messages[name] = message
	is.mu.Unlock()
}

// PrintSummary prints the final installation summary
func (is *InstallStatus) PrintSummary() {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	gray := color.New(color.FgHiBlack)

	is.mu.Lock()
	defer is.mu.Unlock()

	for _, name := range is.order {
		status := is.items[name]
		switch status {
		case "ok":
			fmt.Printf("    %s %s\n", green.Sprint("✓"), name)
		case "skip":
			msg := is.messages[name]
			if msg != "" {
				fmt.Printf("    %s %s: %s\n", gray.Sprint("○"), name, gray.Sprint(msg))
			} else {
				fmt.Printf("    %s %s\n", gray.Sprint("○"), name)
			}
		case "fail":
			msg := is.messages[name]
			if msg != "" {
				fmt.Printf("    %s %s: %s\n", yellow.Sprint("✗"), name, yellow.Sprint(msg))
			} else {
				fmt.Printf("    %s %s\n", yellow.Sprint("✗"), name)
			}
		}
	}
}

// GetCounts returns the count of ok, skip, and fail items
func (is *InstallStatus) GetCounts() (ok, skip, fail int) {
	is.mu.Lock()
	defer is.mu.Unlock()

	for _, status := range is.items {
		switch status {
		case "ok":
			ok++
		case "skip":
			skip++
		case "fail":
			fail++
		}
	}
	return
}
