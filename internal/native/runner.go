// Package native provides a unified interface for running reconnaissance tools
// with hybrid native Go library + exec fallback implementation.
//
// The hybrid approach:
// 1. Tries native Go library first (if available and enabled)
// 2. Falls back to binary/exec if native fails or produces bad results
// 3. Tracks which method was used for debugging
package native

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// ExecutionMethod indicates how a tool was executed
type ExecutionMethod string

const (
	MethodNative   ExecutionMethod = "native"   // Used native Go library
	MethodBinary   ExecutionMethod = "binary"   // Used exec.Command
	MethodFallback ExecutionMethod = "fallback" // Native failed, fell back to binary
)

// Runner provides a unified interface for reconnaissance tools
// with automatic fallback from native to binary execution
type Runner struct {
	checker       *tools.Checker
	timeout       time.Duration
	threads       int
	tryNative     bool  // Whether to attempt native execution first
	minResults    int   // Minimum results expected (triggers fallback if below)
	nativeFuncs   map[string]NativeFunc // Registered native implementations
	stats         *Stats
}

// NativeFunc is a function that runs a tool natively
// Returns results, whether results are valid, and any error
type NativeFunc func(ctx context.Context, input interface{}) (interface{}, bool, error)

// Stats tracks execution statistics
type Stats struct {
	NativeAttempts  int
	NativeSuccesses int
	NativeFailures  int
	BinaryAttempts  int
	BinarySuccesses int
	BinaryFailures  int
	Fallbacks       int
}

// Option configures the runner
type Option func(*Runner)

// WithTimeout sets the execution timeout
func WithTimeout(timeout time.Duration) Option {
	return func(r *Runner) {
		r.timeout = timeout
	}
}

// WithThreads sets the number of concurrent threads
func WithThreads(threads int) Option {
	return func(r *Runner) {
		r.threads = threads
	}
}

// WithNative enables/disables native library execution
func WithNative(enabled bool) Option {
	return func(r *Runner) {
		r.tryNative = enabled
	}
}

// WithMinResults sets minimum expected results (triggers fallback if below)
func WithMinResults(min int) Option {
	return func(r *Runner) {
		r.minResults = min
	}
}

// NewRunner creates a new tool runner with hybrid execution
func NewRunner(checker *tools.Checker, opts ...Option) *Runner {
	r := &Runner{
		checker:     checker,
		timeout:     5 * time.Minute,
		threads:     50,
		tryNative:   true, // Default to trying native first
		minResults:  0,    // No minimum by default
		nativeFuncs: make(map[string]NativeFunc),
		stats:       &Stats{},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// RegisterNative registers a native implementation for a tool
func (r *Runner) RegisterNative(tool string, fn NativeFunc) {
	r.nativeFuncs[tool] = fn
}

// GetStats returns execution statistics
func (r *Runner) GetStats() Stats {
	return *r.stats
}

// SubfinderResult contains subdomain enumeration results
type SubfinderResult struct {
	Subdomains []string
	Duration   time.Duration
	Method     ExecutionMethod
	Error      error
}

// Subfinder runs subdomain enumeration with hybrid native/binary execution
func (r *Runner) Subfinder(ctx context.Context, domain string) (*SubfinderResult, error) {
	start := time.Now()

	// Try native implementation first if enabled and registered
	if r.tryNative {
		if nativeFn, ok := r.nativeFuncs["subfinder"]; ok {
			r.stats.NativeAttempts++
			result, valid, err := nativeFn(ctx, domain)
			if err == nil && valid {
				if subs, ok := result.([]string); ok && len(subs) >= r.minResults {
					r.stats.NativeSuccesses++
					return &SubfinderResult{
						Subdomains: subs,
						Duration:   time.Since(start),
						Method:     MethodNative,
					}, nil
				}
			}
			// Native failed or produced bad results, will fallback
			r.stats.NativeFailures++
			r.stats.Fallbacks++
		}
	}

	// Fallback to binary execution
	if !r.checker.IsInstalled("subfinder") {
		return nil, fmt.Errorf("subfinder not installed")
	}

	r.stats.BinaryAttempts++
	args := []string{
		"-d", domain,
		"-silent",
		"-all", // Use all sources including API keys
		"-t", fmt.Sprintf("%d", r.threads),
	}

	result := exec.Run("subfinder", args, &exec.Options{Timeout: r.timeout})

	subs := exec.Lines(result.Stdout)
	if result.Error != nil {
		r.stats.BinaryFailures++
		return &SubfinderResult{
			Subdomains: subs,
			Duration:   time.Since(start),
			Method:     MethodBinary,
			Error:      result.Error,
		}, result.Error
	}

	r.stats.BinarySuccesses++
	method := MethodBinary
	if r.tryNative && r.nativeFuncs["subfinder"] != nil {
		method = MethodFallback // We tried native first but fell back
	}

	return &SubfinderResult{
		Subdomains: subs,
		Duration:   time.Since(start),
		Method:     method,
	}, nil
}

// HTTPXResult contains HTTP probing results
type HTTPXResult struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title"`
	Technologies  []string `json:"technologies,omitempty"`
	Failed        bool     `json:"failed"`
}

// HTTPXResults contains batch HTTP probing results
type HTTPXResults struct {
	Results  []HTTPXResult
	Alive    []string
	Duration time.Duration
	Method   ExecutionMethod
	Error    error
}

// HTTPX runs HTTP probing on hosts with hybrid native/binary execution
func (r *Runner) HTTPX(ctx context.Context, hosts []string, techDetect bool) (*HTTPXResults, error) {
	if len(hosts) == 0 {
		return &HTTPXResults{Method: MethodBinary}, nil
	}

	start := time.Now()

	// Try native implementation first if enabled and registered
	if r.tryNative {
		if nativeFn, ok := r.nativeFuncs["httpx"]; ok {
			r.stats.NativeAttempts++
			input := map[string]interface{}{
				"hosts":      hosts,
				"techDetect": techDetect,
			}
			result, valid, err := nativeFn(ctx, input)
			if err == nil && valid {
				if alive, ok := result.([]string); ok && len(alive) >= r.minResults {
					r.stats.NativeSuccesses++
					return &HTTPXResults{
						Alive:    alive,
						Duration: time.Since(start),
						Method:   MethodNative,
					}, nil
				}
			}
			// Native failed or produced bad results
			r.stats.NativeFailures++
			r.stats.Fallbacks++
		}
	}

	// Fallback to binary execution
	if !r.checker.IsInstalled("httpx") {
		return nil, fmt.Errorf("httpx not installed")
	}

	r.stats.BinaryAttempts++

	// Write hosts to temp file
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{
		"-l", tmpFile,
		"-silent",
		"-threads", fmt.Sprintf("%d", r.threads),
		"-status-code",
		"-content-length",
		"-title",
		"-no-color",
		"-follow-redirects",
	}
	if techDetect {
		args = append(args, "-tech-detect")
	}

	result := exec.Run("httpx", args, &exec.Options{Timeout: r.timeout})

	// Parse output (simplified - httpx outputs host info line by line)
	var alive []string
	seen := make(map[string]bool)
	for _, line := range exec.Lines(result.Stdout) {
		// Extract host from httpx output
		parts := strings.Fields(line)
		if len(parts) > 0 {
			host := extractHost(parts[0])
			if host != "" && !seen[host] {
				seen[host] = true
				alive = append(alive, host)
			}
		}
	}

	method := MethodBinary
	if r.tryNative && r.nativeFuncs["httpx"] != nil {
		method = MethodFallback
	}

	if result.Error != nil {
		r.stats.BinaryFailures++
	} else {
		r.stats.BinarySuccesses++
	}

	return &HTTPXResults{
		Alive:    alive,
		Duration: time.Since(start),
		Method:   method,
		Error:    result.Error,
	}, result.Error
}

// DNSXResult contains DNS resolution results
type DNSXResult struct {
	Resolved []string
	HostIPs  map[string][]string
	Duration time.Duration
	Method   ExecutionMethod
	Error    error
}

// DNSX runs DNS resolution on hosts with hybrid native/binary execution
func (r *Runner) DNSX(ctx context.Context, hosts []string) (*DNSXResult, error) {
	if len(hosts) == 0 {
		return &DNSXResult{HostIPs: make(map[string][]string), Method: MethodBinary}, nil
	}

	start := time.Now()

	// Try native implementation first if enabled and registered
	if r.tryNative {
		if nativeFn, ok := r.nativeFuncs["dnsx"]; ok {
			r.stats.NativeAttempts++
			result, valid, err := nativeFn(ctx, hosts)
			if err == nil && valid {
				if resolved, ok := result.([]string); ok && len(resolved) >= r.minResults {
					r.stats.NativeSuccesses++
					return &DNSXResult{
						Resolved: resolved,
						HostIPs:  make(map[string][]string),
						Duration: time.Since(start),
						Method:   MethodNative,
					}, nil
				}
			}
			// Native failed or produced bad results
			r.stats.NativeFailures++
			r.stats.Fallbacks++
		}
	}

	// Fallback to binary execution
	if !r.checker.IsInstalled("dnsx") {
		return nil, fmt.Errorf("dnsx not installed")
	}

	r.stats.BinaryAttempts++

	// Write hosts to temp file
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{
		"-l", tmpFile,
		"-silent",
		"-t", fmt.Sprintf("%d", r.threads),
		"-resp",
		"-a",
	}

	result := exec.Run("dnsx", args, &exec.Options{Timeout: r.timeout})

	// Parse output
	var resolved []string
	hostIPs := make(map[string][]string)

	for _, line := range exec.Lines(result.Stdout) {
		// dnsx with -resp -a outputs "host [IP1,IP2,...]"
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			host := parts[0]
			resolved = append(resolved, host)

			// Extract IPs if present
			if len(parts) >= 2 {
				ipPart := strings.Trim(parts[1], "[]")
				ips := strings.Split(ipPart, ",")
				hostIPs[host] = ips
			}
		}
	}

	method := MethodBinary
	if r.tryNative && r.nativeFuncs["dnsx"] != nil {
		method = MethodFallback
	}

	if result.Error != nil {
		r.stats.BinaryFailures++
	} else {
		r.stats.BinarySuccesses++
	}

	return &DNSXResult{
		Resolved: resolved,
		HostIPs:  hostIPs,
		Duration: time.Since(start),
		Method:   method,
		Error:    result.Error,
	}, result.Error
}

// NaabuResult contains port scanning results
type NaabuResult struct {
	OpenPorts map[string][]int // host -> ports
	Duration  time.Duration
	Error     error
}

// Naabu runs port scanning
func (r *Runner) Naabu(ctx context.Context, hosts []string, ports string) (*NaabuResult, error) {
	if len(hosts) == 0 {
		return &NaabuResult{OpenPorts: make(map[string][]int)}, nil
	}

	if !r.checker.IsInstalled("naabu") {
		return nil, fmt.Errorf("naabu not installed")
	}

	start := time.Now()

	// Write hosts to temp file
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{
		"-l", tmpFile,
		"-silent",
		"-c", fmt.Sprintf("%d", r.threads),
	}
	if ports != "" {
		args = append(args, "-p", ports)
	} else {
		args = append(args, "-top-ports", "1000")
	}

	result := exec.Run("naabu", args, &exec.Options{Timeout: r.timeout})

	// Parse output (host:port format)
	openPorts := make(map[string][]int)
	for _, line := range exec.Lines(result.Stdout) {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			host := parts[0]
			var port int
			fmt.Sscanf(parts[1], "%d", &port)
			if port > 0 {
				openPorts[host] = append(openPorts[host], port)
			}
		}
	}

	return &NaabuResult{
		OpenPorts: openPorts,
		Duration:  time.Since(start),
		Error:     result.Error,
	}, result.Error
}

// NucleiResult contains vulnerability scanning results
type NucleiResult struct {
	Findings []NucleiFinding
	Duration time.Duration
	Error    error
}

// NucleiFinding represents a single nuclei finding
type NucleiFinding struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	URL        string `json:"url,omitempty"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Type       string `json:"type"`
}

// Nuclei runs vulnerability scanning
func (r *Runner) Nuclei(ctx context.Context, hosts []string, tags []string, templates []string) (*NucleiResult, error) {
	if len(hosts) == 0 {
		return &NucleiResult{}, nil
	}

	if !r.checker.IsInstalled("nuclei") {
		return nil, fmt.Errorf("nuclei not installed")
	}

	start := time.Now()

	// Write hosts to temp file
	input := strings.Join(hosts, "\n")
	tmpFile, cleanup, err := exec.TempFile(input, ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{
		"-l", tmpFile,
		"-silent",
		"-c", fmt.Sprintf("%d", r.threads),
		"-jsonl",
	}

	// Add tags if specified
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	// Add templates if specified
	for _, t := range templates {
		args = append(args, "-t", t)
	}

	result := exec.Run("nuclei", args, &exec.Options{Timeout: 30 * time.Minute})

	// Parse JSON output
	var findings []NucleiFinding
	for _, line := range exec.Lines(result.Stdout) {
		var finding NucleiFinding
		// Simplified parsing - would need proper JSON unmarshal
		if strings.Contains(line, "template-id") {
			findings = append(findings, finding)
		}
	}

	return &NucleiResult{
		Findings: findings,
		Duration: time.Since(start),
		Error:    result.Error,
	}, result.Error
}

// GetAliveHosts combines DNS resolution and HTTP probing
func (r *Runner) GetAliveHosts(ctx context.Context, hosts []string) ([]string, error) {
	// First try DNS resolution
	dnsResult, err := r.DNSX(ctx, hosts)
	resolved := hosts
	if err == nil && len(dnsResult.Resolved) > 0 {
		resolved = dnsResult.Resolved
	}

	// Then probe HTTP
	httpResult, err := r.HTTPX(ctx, resolved, false)
	if err != nil {
		return nil, err
	}

	return httpResult.Alive, nil
}

// extractHost extracts hostname from URL or host:port
func extractHost(s string) string {
	// Remove protocol
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")

	// Remove port
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}

	// Remove path
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}

	return strings.TrimSpace(s)
}
