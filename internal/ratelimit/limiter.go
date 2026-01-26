package ratelimit

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RateLimiter provides intelligent rate limiting with WAF detection
type RateLimiter struct {
	mu sync.RWMutex

	// Per-host tracking
	hostStates map[string]*HostState

	// Default settings
	defaultRPS      int           // Default requests per second
	minRPS          int           // Minimum RPS (never go below)
	maxRPS          int           // Maximum RPS (never go above)
	backoffFactor   float64       // Multiplier when rate limited (0.5 = halve)
	recoveryFactor  float64       // Multiplier when recovering (1.2 = 20% increase)
	cooldownPeriod  time.Duration // Time before attempting recovery
	consecutiveOK   int           // Consecutive OK responses before recovery

	// WAF detection patterns
	wafPatterns []WAFPattern
}

// HostState tracks rate limiting state for a single host
type HostState struct {
	Host            string
	CurrentRPS      int
	LastRateLimited time.Time
	ConsecutiveOK   int
	TotalRequests   int
	RateLimited     int
	WAFDetected     bool
	WAFName         string
	Blocked         bool // Host is temporarily blocked
	BlockedUntil    time.Time
}

// WAFPattern defines a WAF detection pattern
type WAFPattern struct {
	Name         string
	StatusCodes  []int
	Headers      map[string]*regexp.Regexp
	BodyPatterns []*regexp.Regexp
}

// NewRateLimiter creates a new rate limiter with sensible defaults
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		hostStates:     make(map[string]*HostState),
		defaultRPS:     50,
		minRPS:         5,
		maxRPS:         150,
		backoffFactor:  0.5,
		recoveryFactor: 1.2,
		cooldownPeriod: 30 * time.Second,
		consecutiveOK:  10,
		wafPatterns:    defaultWAFPatterns(),
	}
	return rl
}

// NewRateLimiterWithConfig creates a rate limiter with custom config
func NewRateLimiterWithConfig(defaultRPS, minRPS, maxRPS int) *RateLimiter {
	rl := NewRateLimiter()
	rl.defaultRPS = defaultRPS
	rl.minRPS = minRPS
	rl.maxRPS = maxRPS
	return rl
}

// defaultWAFPatterns returns common WAF detection patterns
func defaultWAFPatterns() []WAFPattern {
	return []WAFPattern{
		{
			Name:        "Cloudflare",
			StatusCodes: []int{429, 503, 520, 521, 522, 523, 524},
			Headers: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)cloudflare`),
				"cf-ray":     regexp.MustCompile(`.+`),
				"cf-cache-status": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)cloudflare`),
				regexp.MustCompile(`(?i)ray ID`),
			},
		},
		{
			Name:        "AWS WAF",
			StatusCodes: []int{403, 429},
			Headers: map[string]*regexp.Regexp{
				"x-amzn-requestid": regexp.MustCompile(`.+`),
				"x-amz-cf-id":      regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)request blocked`),
			},
		},
		{
			Name:        "Akamai",
			StatusCodes: []int{403, 429, 503},
			Headers: map[string]*regexp.Regexp{
				"server":          regexp.MustCompile(`(?i)akamai`),
				"x-akamai-session": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)access denied`),
				regexp.MustCompile(`Reference #`),
			},
		},
		{
			Name:        "Imperva/Incapsula",
			StatusCodes: []int{403, 429},
			Headers: map[string]*regexp.Regexp{
				"x-iinfo": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)incapsula`),
				regexp.MustCompile(`(?i)imperva`),
			},
		},
		{
			Name:        "F5 BIG-IP",
			StatusCodes: []int{403, 429},
			Headers: map[string]*regexp.Regexp{
				"server": regexp.MustCompile(`(?i)big-?ip`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)request rejected`),
			},
		},
		{
			Name:        "ModSecurity",
			StatusCodes: []int{403, 406},
			Headers: map[string]*regexp.Regexp{
				"server": regexp.MustCompile(`(?i)mod_security`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)mod_security`),
				regexp.MustCompile(`(?i)OWASP`),
			},
		},
		{
			Name:        "Generic Rate Limit",
			StatusCodes: []int{429},
			Headers: map[string]*regexp.Regexp{
				"retry-after":           regexp.MustCompile(`.+`),
				"x-ratelimit-remaining": regexp.MustCompile(`^0$`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)rate limit`),
				regexp.MustCompile(`(?i)too many requests`),
			},
		},
	}
}

// GetRPS returns the current recommended RPS for a host
func (rl *RateLimiter) GetRPS(host string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	state, exists := rl.hostStates[host]
	if !exists {
		return rl.defaultRPS
	}

	if state.Blocked && time.Now().Before(state.BlockedUntil) {
		return 0 // Host is blocked
	}

	return state.CurrentRPS
}

// IsBlocked checks if a host is currently blocked
func (rl *RateLimiter) IsBlocked(host string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	state, exists := rl.hostStates[host]
	if !exists {
		return false
	}

	return state.Blocked && time.Now().Before(state.BlockedUntil)
}

// RecordResponse records a response and adjusts rate limiting
func (rl *RateLimiter) RecordResponse(host string, statusCode int, headers http.Header, body string) *RateLimitEvent {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Get or create host state
	state, exists := rl.hostStates[host]
	if !exists {
		state = &HostState{
			Host:       host,
			CurrentRPS: rl.defaultRPS,
		}
		rl.hostStates[host] = state
	}

	state.TotalRequests++
	event := &RateLimitEvent{Host: host, PreviousRPS: state.CurrentRPS}

	// Check for rate limiting / WAF blocking
	isRateLimited, wafName := rl.detectRateLimit(statusCode, headers, body)

	if isRateLimited {
		state.RateLimited++
		state.ConsecutiveOK = 0
		state.LastRateLimited = time.Now()

		if wafName != "" {
			state.WAFDetected = true
			state.WAFName = wafName
		}

		// Apply backoff
		newRPS := int(float64(state.CurrentRPS) * rl.backoffFactor)
		if newRPS < rl.minRPS {
			newRPS = rl.minRPS
		}

		// If already at min RPS and still rate limited, block temporarily
		if state.CurrentRPS == rl.minRPS && isRateLimited {
			state.Blocked = true
			state.BlockedUntil = time.Now().Add(rl.cooldownPeriod * 2)
			event.Action = "blocked"
			event.Reason = fmt.Sprintf("Rate limited at minimum RPS, blocking for %v", rl.cooldownPeriod*2)
		} else {
			state.CurrentRPS = newRPS
			event.Action = "backoff"
			event.Reason = fmt.Sprintf("Rate limited (status %d), reducing RPS", statusCode)
		}

		event.NewRPS = state.CurrentRPS
		event.WAFDetected = state.WAFDetected
		event.WAFName = state.WAFName
		return event
	}

	// Successful response - track consecutive OKs
	state.ConsecutiveOK++

	// Unblock if blocked
	if state.Blocked && time.Now().After(state.BlockedUntil) {
		state.Blocked = false
		event.Action = "unblocked"
		event.Reason = "Block period expired"
	}

	// Recovery: increase RPS after consecutive successful requests
	if state.ConsecutiveOK >= rl.consecutiveOK && time.Since(state.LastRateLimited) > rl.cooldownPeriod {
		newRPS := int(float64(state.CurrentRPS) * rl.recoveryFactor)
		if newRPS > rl.maxRPS {
			newRPS = rl.maxRPS
		}
		if newRPS > state.CurrentRPS {
			state.CurrentRPS = newRPS
			state.ConsecutiveOK = 0
			event.Action = "recovery"
			event.Reason = fmt.Sprintf("Increasing RPS after %d consecutive OK responses", rl.consecutiveOK)
		}
	}

	event.NewRPS = state.CurrentRPS
	return event
}

// detectRateLimit checks if response indicates rate limiting
func (rl *RateLimiter) detectRateLimit(statusCode int, headers http.Header, body string) (bool, string) {
	// Quick check for 429
	if statusCode == 429 {
		// Try to identify WAF
		for _, pattern := range rl.wafPatterns {
			if rl.matchesPattern(pattern, statusCode, headers, body) {
				return true, pattern.Name
			}
		}
		return true, "Generic Rate Limit"
	}

	// Check each WAF pattern
	for _, pattern := range rl.wafPatterns {
		// Check status code
		codeMatches := false
		for _, code := range pattern.StatusCodes {
			if statusCode == code {
				codeMatches = true
				break
			}
		}

		if codeMatches && rl.matchesPattern(pattern, statusCode, headers, body) {
			return true, pattern.Name
		}
	}

	return false, ""
}

// matchesPattern checks if response matches a WAF pattern
func (rl *RateLimiter) matchesPattern(pattern WAFPattern, statusCode int, headers http.Header, body string) bool {
	matchCount := 0

	// Check headers
	for headerName, headerPattern := range pattern.Headers {
		headerValue := headers.Get(headerName)
		if headerValue != "" && headerPattern.MatchString(headerValue) {
			matchCount++
		}
	}

	// Check body patterns
	for _, bodyPattern := range pattern.BodyPatterns {
		if bodyPattern.MatchString(body) {
			matchCount++
		}
	}

	// Need at least one match beyond status code
	return matchCount > 0
}

// GetState returns the current state for a host
func (rl *RateLimiter) GetState(host string) *HostState {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if state, exists := rl.hostStates[host]; exists {
		// Return a copy
		copy := *state
		return &copy
	}
	return nil
}

// GetAllStates returns all host states
func (rl *RateLimiter) GetAllStates() map[string]*HostState {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	result := make(map[string]*HostState)
	for host, state := range rl.hostStates {
		copy := *state
		result[host] = &copy
	}
	return result
}

// GetSummary returns a summary of rate limiting activity
func (rl *RateLimiter) GetSummary() *RateLimitSummary {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	summary := &RateLimitSummary{
		TotalHosts:   len(rl.hostStates),
		WAFsByName:   make(map[string]int),
		HostsByState: make(map[string]int),
	}

	for _, state := range rl.hostStates {
		summary.TotalRequests += state.TotalRequests
		summary.TotalRateLimited += state.RateLimited

		if state.WAFDetected {
			summary.WAFDetected++
			summary.WAFsByName[state.WAFName]++
		}
		if state.Blocked {
			summary.CurrentlyBlocked++
			summary.HostsByState["blocked"]++
		} else if state.CurrentRPS < rl.defaultRPS {
			summary.HostsByState["throttled"]++
		} else {
			summary.HostsByState["normal"]++
		}
	}

	return summary
}

// Reset resets rate limiting state for a host
func (rl *RateLimiter) Reset(host string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.hostStates, host)
}

// ResetAll resets all rate limiting state
func (rl *RateLimiter) ResetAll() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.hostStates = make(map[string]*HostState)
}

// RateLimitEvent describes a rate limit adjustment event
type RateLimitEvent struct {
	Host        string
	PreviousRPS int
	NewRPS      int
	Action      string // "backoff", "recovery", "blocked", "unblocked"
	Reason      string
	WAFDetected bool
	WAFName     string
}

// RateLimitSummary provides aggregate statistics
type RateLimitSummary struct {
	TotalHosts       int
	TotalRequests    int
	TotalRateLimited int
	WAFDetected      int
	CurrentlyBlocked int
	WAFsByName       map[string]int
	HostsByState     map[string]int
}

// String returns a formatted summary string
func (s *RateLimitSummary) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Rate Limit Summary:\n"))
	sb.WriteString(fmt.Sprintf("  Total Hosts: %d\n", s.TotalHosts))
	sb.WriteString(fmt.Sprintf("  Total Requests: %d\n", s.TotalRequests))
	sb.WriteString(fmt.Sprintf("  Rate Limited: %d (%.1f%%)\n", s.TotalRateLimited,
		float64(s.TotalRateLimited)/float64(s.TotalRequests)*100))
	sb.WriteString(fmt.Sprintf("  WAF Detected: %d hosts\n", s.WAFDetected))
	sb.WriteString(fmt.Sprintf("  Currently Blocked: %d hosts\n", s.CurrentlyBlocked))

	if len(s.WAFsByName) > 0 {
		sb.WriteString("  WAFs Detected:\n")
		for name, count := range s.WAFsByName {
			sb.WriteString(fmt.Sprintf("    - %s: %d hosts\n", name, count))
		}
	}

	return sb.String()
}
