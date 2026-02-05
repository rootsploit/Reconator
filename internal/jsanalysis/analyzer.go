package jsanalysis

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// Result holds the complete JavaScript analysis results
type Result struct {
	Endpoints            []Endpoint            `json:"endpoints"`
	DOMXSSSinks          []DOMXSSSink          `json:"dom_xss_sinks"`
	DOMXSSSources        []DOMXSSSource        `json:"dom_xss_sources"`
	TaintFlows           []TaintFlow           `json:"taint_flows"` // Source-to-sink connections
	PrototypePollutions  []PrototypePollution  `json:"prototype_pollutions"`
	Secrets              []Secret              `json:"secrets"`
	APIPaths             []string              `json:"api_paths"`
	TotalFiles           int                   `json:"total_files"`
	FilesScanned         int                   `json:"files_scanned"`
	Duration             time.Duration         `json:"duration"`
}

// Endpoint represents an extracted API endpoint
type Endpoint struct {
	URL       string `json:"url"`
	Path      string `json:"path"`
	Method    string `json:"method,omitempty"` // GET, POST, etc. if detectable
	Source    string `json:"source"`           // JS file where found
	Context   string `json:"context,omitempty"`
	Sensitive bool   `json:"sensitive"` // Contains auth, admin, etc.
}

// DOMXSSSink represents a potential DOM XSS vulnerability
type DOMXSSSink struct {
	Type     string `json:"type"`      // innerHTML, eval, document.write, etc.
	Code     string `json:"code"`      // Snippet of code
	Source   string `json:"source"`    // JS file
	Line     int    `json:"line"`      // Line number (approx)
	Severity string `json:"severity"`  // high, medium, low
	HasInput bool   `json:"has_input"` // True if sink has user-controlled input
}

// DOMXSSSource represents a user-controllable input source
type DOMXSSSource struct {
	Type        string `json:"type"`         // location.hash, document.URL, etc.
	Code        string `json:"code"`         // Snippet of code
	Source      string `json:"source"`       // JS file
	Line        int    `json:"line"`         // Line number
	Category    string `json:"category"`     // url, storage, dom, postMessage
	Controllability string `json:"controllability"` // full, partial
}

// TaintFlow represents a potential source-to-sink data flow
type TaintFlow struct {
	SourceType   string `json:"source_type"`
	SourceLine   int    `json:"source_line"`
	SinkType     string `json:"sink_type"`
	SinkLine     int    `json:"sink_line"`
	File         string `json:"file"`
	Exploitable  bool   `json:"exploitable"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
}

// PrototypePollution represents a potential prototype pollution vulnerability
type PrototypePollution struct {
	Type        string `json:"type"`        // __proto__, constructor, Object.assign, merge, etc.
	Code        string `json:"code"`        // Snippet of vulnerable code
	Source      string `json:"source"`      // JS file
	Line        int    `json:"line"`        // Line number
	Severity    string `json:"severity"`    // critical, high, medium
	Pattern     string `json:"pattern"`     // Pattern that matched
	Exploitable bool   `json:"exploitable"` // True if exploitable pattern detected
	Description string `json:"description"` // Explanation
}

// Secret represents a potential hardcoded secret/API key
type Secret struct {
	Type    string `json:"type"`    // API Key, Token, Password, etc.
	Value   string `json:"value"`   // Masked value
	Pattern string `json:"pattern"` // Pattern that matched
	Source  string `json:"source"`  // JS file
}

// Analyzer performs JavaScript file analysis
type Analyzer struct {
	cfg     *config.Config
	checker *tools.Checker
	client  *http.Client
}

// NewAnalyzer creates a new JavaScript analyzer
func NewAnalyzer(cfg *config.Config, checker *tools.Checker) *Analyzer {
	return &Analyzer{
		cfg:     cfg,
		checker: checker,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Analyze performs deep analysis on JavaScript files
func (a *Analyzer) Analyze(ctx context.Context, jsURLs []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TotalFiles: len(jsURLs),
	}

	if len(jsURLs) == 0 {
		return result, nil
	}

	fmt.Printf("    [*] Analyzing %d JavaScript files...\n", len(jsURLs))

	// Limit concurrent fetches
	maxConcurrent := 20
	if a.cfg.Threads > 0 && a.cfg.Threads < maxConcurrent {
		maxConcurrent = a.cfg.Threads
	}

	// Semaphore for concurrency control
	sem := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	var mu sync.Mutex

	endpointSet := make(map[string]bool)
	var allEndpoints []Endpoint
	var allSinks []DOMXSSSink
	var allSources []DOMXSSSource
	var allFlows []TaintFlow
	var allPollutions []PrototypePollution
	var allSecrets []Secret
	apiPathSet := make(map[string]bool)

	// Limit to first 200 JS files for performance
	maxFiles := 200
	if len(jsURLs) > maxFiles {
		jsURLs = jsURLs[:maxFiles]
		fmt.Printf("        Limiting analysis to first %d files\n", maxFiles)
	}

	for _, jsURL := range jsURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			// Fetch JS content
			content, err := a.fetchJS(ctx, url)
			if err != nil || len(content) == 0 {
				return
			}

			// Extract endpoints
			endpoints := a.extractEndpoints(content, url)

			// Detect DOM XSS sinks
			sinks := a.detectDOMXSSSinks(content, url)

			// Detect DOM XSS sources
			sources := a.detectDOMXSSSources(content, url)

			// Analyze taint flows (source-to-sink connections)
			flows := a.analyzeTaintFlows(content, url, sources, sinks)

			// Detect prototype pollution vulnerabilities
			pollutions := a.detectPrototypePollution(content, url)

			// Find secrets
			secrets := a.findSecrets(content, url)

			// Extract API paths
			paths := a.extractAPIPaths(content)

			mu.Lock()
			result.FilesScanned++
			for _, ep := range endpoints {
				key := ep.Path
				if !endpointSet[key] {
					endpointSet[key] = true
					allEndpoints = append(allEndpoints, ep)
				}
			}
			allSinks = append(allSinks, sinks...)
			allSources = append(allSources, sources...)
			allFlows = append(allFlows, flows...)
			allPollutions = append(allPollutions, pollutions...)
			allSecrets = append(allSecrets, secrets...)
			for _, p := range paths {
				apiPathSet[p] = true
			}
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()

	// Convert API paths to slice
	for p := range apiPathSet {
		result.APIPaths = append(result.APIPaths, p)
	}
	sort.Strings(result.APIPaths)

	result.Endpoints = allEndpoints
	result.DOMXSSSinks = allSinks
	result.DOMXSSSources = allSources
	result.TaintFlows = allFlows
	result.PrototypePollutions = allPollutions
	result.Secrets = allSecrets
	result.Duration = time.Since(start)

	fmt.Printf("        Found: %d endpoints, %d DOM XSS sinks, %d sources, %d taint flows, %d prototype pollutions, %d secrets, %d API paths\n",
		len(result.Endpoints), len(result.DOMXSSSinks), len(result.DOMXSSSources),
		len(result.TaintFlows), len(result.PrototypePollutions), len(result.Secrets), len(result.APIPaths))

	return result, nil
}

// fetchJS retrieves JavaScript content from URL
func (a *Analyzer) fetchJS(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconator/1.0)")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	// Read up to 5MB
	buf := make([]byte, 5*1024*1024)
	n, _ := resp.Body.Read(buf)

	return string(buf[:n]), nil
}

// Endpoint extraction patterns
var (
	// Full URL patterns
	urlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)["']https?://[^"'\s<>]+["']`),
		regexp.MustCompile(`(?i)["']//[^"'\s<>]+["']`),
	}

	// API path patterns
	apiPathPatterns = []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/v\d+/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/v\d+/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/graphql[/a-zA-Z0-9_-]*)["']`),
		regexp.MustCompile(`["'](/rest/[a-zA-Z0-9/_-]+)["']`),
	}

	// Relative path patterns
	relativePathPatterns = []*regexp.Regexp{
		regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`axios\.[a-z]+\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`XMLHttpRequest[^;]*\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`),
		regexp.MustCompile(`\$\.(get|post|ajax)\s*\(\s*["']([^"']+)["']`),
	}

	// Sensitive keywords for endpoints
	sensitiveKeywords = []string{
		"admin", "auth", "login", "logout", "password", "secret",
		"token", "key", "private", "internal", "debug", "config",
		"user", "account", "session", "oauth", "jwt", "payment",
		"billing", "credit", "bank", "ssn", "social",
	}
)

// extractEndpoints finds API endpoints and URLs in JS content
func (a *Analyzer) extractEndpoints(content, source string) []Endpoint {
	var endpoints []Endpoint
	seen := make(map[string]bool)

	// Extract full URLs
	for _, pattern := range urlPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, m := range matches {
			url := strings.Trim(m, "\"'")
			if !seen[url] && isValidEndpoint(url) {
				seen[url] = true
				endpoints = append(endpoints, Endpoint{
					URL:       url,
					Path:      extractPath(url),
					Source:    source,
					Sensitive: containsSensitive(url),
				})
			}
		}
	}

	// Extract API paths
	for _, pattern := range apiPathPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 1 {
				path := m[1]
				if !seen[path] && isValidPath(path) {
					seen[path] = true
					endpoints = append(endpoints, Endpoint{
						Path:      path,
						Source:    source,
						Sensitive: containsSensitive(path),
					})
				}
			}
		}
	}

	// Extract from fetch/axios/ajax calls
	for _, pattern := range relativePathPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			for i := 1; i < len(m); i++ {
				path := m[i]
				if path != "" && !seen[path] && isValidPath(path) {
					seen[path] = true
					endpoints = append(endpoints, Endpoint{
						Path:      path,
						Source:    source,
						Sensitive: containsSensitive(path),
					})
				}
			}
		}
	}

	return endpoints
}

// DOM XSS sink patterns
var domXSSSinks = []struct {
	pattern  *regexp.Regexp
	sinkType string
	severity string
}{
	{regexp.MustCompile(`\.innerHTML\s*=`), "innerHTML", "high"},
	{regexp.MustCompile(`\.outerHTML\s*=`), "outerHTML", "high"},
	{regexp.MustCompile(`document\.write\s*\(`), "document.write", "high"},
	{regexp.MustCompile(`document\.writeln\s*\(`), "document.writeln", "high"},
	{regexp.MustCompile(`eval\s*\(`), "eval", "critical"},
	{regexp.MustCompile(`setTimeout\s*\([^)]*['"]\s*\+`), "setTimeout", "high"},
	{regexp.MustCompile(`setInterval\s*\([^)]*['"]\s*\+`), "setInterval", "high"},
	{regexp.MustCompile(`new\s+Function\s*\(`), "new Function", "critical"},
	{regexp.MustCompile(`\.insertAdjacentHTML\s*\(`), "insertAdjacentHTML", "high"},
	{regexp.MustCompile(`\.src\s*=\s*[^"'][^;]*\+`), "src assignment", "medium"},
	{regexp.MustCompile(`\.href\s*=\s*[^"'][^;]*\+`), "href assignment", "medium"},
	{regexp.MustCompile(`location\s*=`), "location assignment", "high"},
	{regexp.MustCompile(`location\.href\s*=`), "location.href", "high"},
	{regexp.MustCompile(`location\.replace\s*\(`), "location.replace", "high"},
	{regexp.MustCompile(`\.setAttribute\s*\(\s*["']on`), "setAttribute (event)", "high"},
	{regexp.MustCompile(`\$\s*\([^)]*\)\.html\s*\(`), "jQuery.html", "high"},
	{regexp.MustCompile(`\$\s*\([^)]*\)\.append\s*\(`), "jQuery.append", "medium"},
	{regexp.MustCompile(`\$\s*\([^)]*\)\.prepend\s*\(`), "jQuery.prepend", "medium"},
}

// DOM XSS source patterns (user input) with categories
var domXSSSourcePatterns = []struct {
	pattern         *regexp.Regexp
	sourceType      string
	category        string // url, storage, dom, postMessage, other
	controllability string // full, partial
}{
	// URL-based sources (fully controllable)
	{regexp.MustCompile(`location\.hash`), "location.hash", "url", "full"},
	{regexp.MustCompile(`location\.search`), "location.search", "url", "full"},
	{regexp.MustCompile(`location\.href`), "location.href", "url", "partial"},
	{regexp.MustCompile(`location\.pathname`), "location.pathname", "url", "partial"},
	{regexp.MustCompile(`document\.URL`), "document.URL", "url", "partial"},
	{regexp.MustCompile(`document\.documentURI`), "document.documentURI", "url", "partial"},
	{regexp.MustCompile(`document\.baseURI`), "document.baseURI", "url", "partial"},
	{regexp.MustCompile(`new\s+URL\s*\(`), "URL constructor", "url", "full"},
	{regexp.MustCompile(`URLSearchParams`), "URLSearchParams", "url", "full"},
	{regexp.MustCompile(`\.searchParams`), "searchParams", "url", "full"},

	// Referrer (partially controllable)
	{regexp.MustCompile(`document\.referrer`), "document.referrer", "url", "partial"},

	// DOM-based sources
	{regexp.MustCompile(`window\.name`), "window.name", "dom", "full"},
	{regexp.MustCompile(`document\.cookie`), "document.cookie", "dom", "partial"},
	{regexp.MustCompile(`\.textContent`), "textContent", "dom", "partial"},
	{regexp.MustCompile(`\.innerText`), "innerText", "dom", "partial"},
	{regexp.MustCompile(`\.value`), "input.value", "dom", "full"},

	// Storage-based sources
	{regexp.MustCompile(`localStorage\.getItem`), "localStorage.getItem", "storage", "full"},
	{regexp.MustCompile(`localStorage\[`), "localStorage[]", "storage", "full"},
	{regexp.MustCompile(`sessionStorage\.getItem`), "sessionStorage.getItem", "storage", "full"},
	{regexp.MustCompile(`sessionStorage\[`), "sessionStorage[]", "storage", "full"},

	// postMessage sources (cross-origin)
	{regexp.MustCompile(`\.data\s*[;,\)]`), "message.data", "postMessage", "full"},
	{regexp.MustCompile(`event\.data`), "event.data", "postMessage", "full"},
	{regexp.MustCompile(`addEventListener\s*\(\s*["']message["']`), "message listener", "postMessage", "full"},

	// URL parameter extraction patterns
	{regexp.MustCompile(`getParameter\s*\(`), "getParameter()", "url", "full"},
	{regexp.MustCompile(`\$\.param`), "$.param", "url", "full"},
	{regexp.MustCompile(`querystring`), "querystring", "url", "full"},
	{regexp.MustCompile(`\.get\s*\(\s*["'][^"']+["']\s*\)`), "params.get()", "url", "full"},

	// Fragment/hash extraction
	{regexp.MustCompile(`\.split\s*\(\s*["']#["']\s*\)`), "hash split", "url", "full"},
	{regexp.MustCompile(`\.split\s*\(\s*["']\?["']\s*\)`), "query split", "url", "full"},
	{regexp.MustCompile(`\.substring\s*\(\s*1\s*\)`), "substring(1)", "url", "partial"},
}

// Simple source strings for backward compatibility
var domXSSSources = []string{
	"location.hash", "location.search", "location.href", "location.pathname",
	"document.URL", "document.documentURI", "document.referrer",
	"window.name", "document.cookie", "localStorage", "sessionStorage",
	"URLSearchParams", "getParameter", "$.param", "querystring",
}

// Prototype pollution patterns
var prototypePollutionPatterns = []struct {
	pattern     *regexp.Regexp
	pollType    string
	severity    string
	description string
}{
	// Direct __proto__ assignment (most dangerous)
	{regexp.MustCompile(`__proto__\s*[\[\.]`), "__proto__ access", "critical", "Direct __proto__ property access"},
	{regexp.MustCompile(`\[["']__proto__["']\]`), "__proto__ bracket", "critical", "__proto__ accessed via bracket notation"},

	// Constructor pollution
	{regexp.MustCompile(`\.constructor\s*\[\s*["']prototype["']\s*\]`), "constructor.prototype", "critical", "Constructor prototype pollution"},
	{regexp.MustCompile(`\[["']constructor["']\]\s*\[\s*["']prototype["']\s*\]`), "constructor[prototype]", "critical", "Constructor prototype access"},

	// Unsafe merge/extend functions (common in libraries)
	{regexp.MustCompile(`(?i)(merge|extend|assign|clone|copy|deepCopy|deepMerge|deepExtend)\s*\(`), "unsafe merge", "high", "Potentially unsafe object merge operation"},
	{regexp.MustCompile(`Object\.assign\s*\(`), "Object.assign", "high", "Object.assign without prototype pollution protection"},

	// Recursive merge patterns (dangerous if no prototype check)
	{regexp.MustCompile(`function\s+\w*\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*in[^)]*\)[^}]*\[[^\]]*\]\s*=`), "recursive merge", "high", "Recursive property assignment without hasOwnProperty check"},

	// jQuery extend/merge (vulnerable in older versions)
	{regexp.MustCompile(`\$\.extend\s*\(\s*true`), "jQuery.extend(true)", "high", "jQuery deep extend (vulnerable if < 3.4.0)"},
	{regexp.MustCompile(`\$\.merge\s*\(`), "jQuery.merge", "medium", "jQuery merge operation"},

	// Lodash merge (vulnerable in older versions)
	{regexp.MustCompile(`_\.merge\s*\(`), "lodash.merge", "high", "Lodash merge (vulnerable if < 4.17.12)"},
	{regexp.MustCompile(`_\.mergeWith\s*\(`), "lodash.mergeWith", "high", "Lodash mergeWith"},
	{regexp.MustCompile(`_\.defaultsDeep\s*\(`), "lodash.defaultsDeep", "high", "Lodash defaultsDeep"},

	// Unsafe property assignment patterns
	{regexp.MustCompile(`\[\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\]\s*=.*\[\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\]`), "dynamic property copy", "medium", "Dynamic property copy without prototype check"},

	// JSON.parse with user input (can be exploited)
	{regexp.MustCompile(`JSON\.parse\s*\([^)]*(?:location|hash|search|query|param|body|request|input)`), "JSON.parse user input", "high", "JSON.parse with user-controllable input"},
}

// detectDOMXSSSinks identifies potential DOM XSS vulnerabilities
func (a *Analyzer) detectDOMXSSSinks(content, source string) []DOMXSSSink {
	var sinks []DOMXSSSink
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, sink := range domXSSSinks {
			if sink.pattern.MatchString(line) {
				// Check if there's a source in the same context
				hasInput := false
				// Check surrounding lines for sources
				contextStart := max(0, lineNum-5)
				contextEnd := min(len(lines)-1, lineNum+5)
				contextLines := strings.Join(lines[contextStart:contextEnd+1], "\n")

				for _, src := range domXSSSources {
					if strings.Contains(contextLines, src) {
						hasInput = true
						break
					}
				}

				// Truncate code snippet
				code := strings.TrimSpace(line)
				if len(code) > 200 {
					code = code[:200] + "..."
				}

				sinks = append(sinks, DOMXSSSink{
					Type:     sink.sinkType,
					Code:     code,
					Source:   source,
					Line:     lineNum + 1,
					Severity: sink.severity,
					HasInput: hasInput,
				})
			}
		}
	}

	return sinks
}

// detectDOMXSSSources identifies user-controllable input sources
func (a *Analyzer) detectDOMXSSSources(content, source string) []DOMXSSSource {
	var sources []DOMXSSSource
	lines := strings.Split(content, "\n")
	seen := make(map[string]bool)

	for lineNum, line := range lines {
		for _, src := range domXSSSourcePatterns {
			if src.pattern.MatchString(line) {
				// Create unique key to avoid duplicates
				key := fmt.Sprintf("%s:%d", src.sourceType, lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				// Truncate code snippet
				code := strings.TrimSpace(line)
				if len(code) > 200 {
					code = code[:200] + "..."
				}

				sources = append(sources, DOMXSSSource{
					Type:            src.sourceType,
					Code:            code,
					Source:          source,
					Line:            lineNum + 1,
					Category:        src.category,
					Controllability: src.controllability,
				})
			}
		}
	}

	return sources
}

// detectPrototypePollution identifies potential prototype pollution vulnerabilities
func (a *Analyzer) detectPrototypePollution(content, source string) []PrototypePollution {
	var pollutions []PrototypePollution
	lines := strings.Split(content, "\n")
	seen := make(map[string]bool)

	for lineNum, line := range lines {
		for _, pattern := range prototypePollutionPatterns {
			if pattern.pattern.MatchString(line) {
				// Create unique key to avoid duplicates
				key := fmt.Sprintf("%s:%d", pattern.pollType, lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				// Truncate code snippet
				code := strings.TrimSpace(line)
				if len(code) > 200 {
					code = code[:200] + "..."
				}

				// Determine if exploitable based on context
				exploitable := isPrototypePollutionExploitable(pattern.pollType, line, lines, lineNum)

				// Adjust severity if definitely exploitable
				severity := pattern.severity
				if exploitable && severity != "critical" {
					severity = "critical"
				}

				pollutions = append(pollutions, PrototypePollution{
					Type:        pattern.pollType,
					Code:        code,
					Source:      source,
					Line:        lineNum + 1,
					Severity:    severity,
					Pattern:     pattern.description,
					Exploitable: exploitable,
					Description: pattern.description,
				})
			}
		}
	}

	return pollutions
}

// isPrototypePollutionExploitable checks if a prototype pollution pattern is likely exploitable
func isPrototypePollutionExploitable(pollType, line string, allLines []string, lineNum int) bool {
	// Direct __proto__ access is always exploitable
	if strings.Contains(pollType, "__proto__") || strings.Contains(pollType, "constructor") {
		return true
	}

	// Check for user input in the same context
	contextStart := max(0, lineNum-10)
	contextEnd := min(len(allLines)-1, lineNum+10)
	contextLines := strings.Join(allLines[contextStart:contextEnd+1], "\n")

	// User input indicators
	userInputIndicators := []string{
		"req.body", "req.query", "req.params", "request.",
		"JSON.parse", "location.", "window.name",
		"URLSearchParams", "document.cookie",
		"localStorage", "sessionStorage",
		".data", "message.data", "event.data",
	}

	for _, indicator := range userInputIndicators {
		if strings.Contains(contextLines, indicator) {
			return true
		}
	}

	// Check if there's no hasOwnProperty check (unsafe)
	if strings.Contains(pollType, "merge") || strings.Contains(pollType, "assign") {
		// If no hasOwnProperty check in context, likely exploitable
		if !strings.Contains(contextLines, "hasOwnProperty") && !strings.Contains(contextLines, "Object.prototype.hasOwnProperty") {
			return true
		}
	}

	return false
}

// analyzeTaintFlows identifies potential source-to-sink connections
func (a *Analyzer) analyzeTaintFlows(content, file string, sources []DOMXSSSource, sinks []DOMXSSSink) []TaintFlow {
	var flows []TaintFlow
	lines := strings.Split(content, "\n")

	// For each sink with hasInput, try to find the actual source
	for _, sink := range sinks {
		if !sink.HasInput {
			continue
		}

		// Look for sources within a reasonable range (same function scope approximation)
		contextRange := 50 // lines
		startLine := max(0, sink.Line-contextRange)
		endLine := min(len(lines), sink.Line+10)

		for _, src := range sources {
			// Check if source is in range of sink
			if src.Line >= startLine && src.Line <= endLine {
				// Determine if this is likely exploitable
				exploitable := isLikelyExploitable(sink.Type, src.Category, src.Controllability)

				severity := "medium"
				if exploitable && src.Controllability == "full" {
					severity = "critical"
				} else if exploitable {
					severity = "high"
				}

				desc := fmt.Sprintf("%s flows to %s", src.Type, sink.Type)
				if exploitable {
					desc += " (potentially exploitable)"
				}

				flows = append(flows, TaintFlow{
					SourceType:  src.Type,
					SourceLine:  src.Line,
					SinkType:    sink.Type,
					SinkLine:    sink.Line,
					File:        file,
					Exploitable: exploitable,
					Severity:    severity,
					Description: desc,
				})
			}
		}
	}

	return flows
}

// isLikelyExploitable determines if a source-sink combination is likely exploitable
func isLikelyExploitable(sinkType, sourceCategory, controllability string) bool {
	// High-risk sinks that are almost always exploitable with any input
	highRiskSinks := map[string]bool{
		"eval":             true,
		"new Function":     true,
		"innerHTML":        true,
		"outerHTML":        true,
		"document.write":   true,
		"document.writeln": true,
	}

	// If sink is high-risk and source is fully controllable
	if highRiskSinks[sinkType] && controllability == "full" {
		return true
	}

	// URL-based sources to DOM sinks are often exploitable
	if sourceCategory == "url" && highRiskSinks[sinkType] {
		return true
	}

	// postMessage to eval/innerHTML is almost always a vuln
	if sourceCategory == "postMessage" && highRiskSinks[sinkType] {
		return true
	}

	return false
}

// Secret patterns for JS files
var jsSecretPatterns = []struct {
	pattern     *regexp.Regexp
	secretType  string
	description string
}{
	{regexp.MustCompile(`["']AIza[0-9A-Za-z_-]{35}["']`), "Google API Key", "Google API Key"},
	{regexp.MustCompile(`["']sk-[a-zA-Z0-9]{48}["']`), "OpenAI API Key", "OpenAI API Key"},
	{regexp.MustCompile(`["']AKIA[0-9A-Z]{16}["']`), "AWS Access Key", "AWS Access Key ID"},
	{regexp.MustCompile(`["']ghp_[a-zA-Z0-9]{36}["']`), "GitHub PAT", "GitHub Personal Access Token"},
	{regexp.MustCompile(`["']gho_[a-zA-Z0-9]{36}["']`), "GitHub OAuth", "GitHub OAuth Token"},
	{regexp.MustCompile(`["']glpat-[a-zA-Z0-9_-]{20}["']`), "GitLab PAT", "GitLab Personal Access Token"},
	{regexp.MustCompile(`["']xox[baprs]-[a-zA-Z0-9-]+["']`), "Slack Token", "Slack Token"},
	{regexp.MustCompile(`["']sk_live_[a-zA-Z0-9]{24,}["']`), "Stripe Live Key", "Stripe Live Secret Key"},
	{regexp.MustCompile(`["']pk_live_[a-zA-Z0-9]{24,}["']`), "Stripe Live Pub", "Stripe Live Publishable Key"},
	{regexp.MustCompile(`["']sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}["']`), "Square Token", "Square Access Token"},
	{regexp.MustCompile(`["'][a-f0-9]{32}["']`), "Generic API Key (32char hex)", "Potential API Key"},
	{regexp.MustCompile(`["'][a-zA-Z0-9_-]{40}["']`), "Generic Token (40char)", "Potential Token"},
	{regexp.MustCompile(`(?i)api[_-]?key["'\s:=]+["']([a-zA-Z0-9_-]{16,})["']`), "API Key", "API Key in config"},
	{regexp.MustCompile(`(?i)secret["'\s:=]+["']([a-zA-Z0-9_-]{16,})["']`), "Secret", "Secret in config"},
	{regexp.MustCompile(`(?i)token["'\s:=]+["']([a-zA-Z0-9_.-]{16,})["']`), "Token", "Token in config"},
	{regexp.MustCompile(`(?i)password["'\s:=]+["']([^"']{8,})["']`), "Password", "Hardcoded Password"},
}

// findSecrets looks for hardcoded secrets in JS content
func (a *Analyzer) findSecrets(content, source string) []Secret {
	var secrets []Secret
	seen := make(map[string]bool)

	for _, sp := range jsSecretPatterns {
		matches := sp.pattern.FindAllString(content, -1)
		for _, m := range matches {
			// Mask the value
			masked := maskSecret(m)
			key := sp.secretType + masked

			if !seen[key] {
				seen[key] = true
				secrets = append(secrets, Secret{
					Type:    sp.secretType,
					Value:   masked,
					Pattern: sp.description,
					Source:  source,
				})
			}
		}
	}

	return secrets
}

// extractAPIPaths finds common API path patterns
func (a *Analyzer) extractAPIPaths(content string) []string {
	var paths []string
	seen := make(map[string]bool)

	// Look for paths that look like API endpoints
	pathPattern := regexp.MustCompile(`["'](/[a-zA-Z0-9/_-]{3,50})["']`)
	matches := pathPattern.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		if len(m) > 1 {
			path := m[1]
			if !seen[path] && isAPIPath(path) {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// Helper functions

func isValidEndpoint(url string) bool {
	// Skip static resources
	lower := strings.ToLower(url)
	staticExts := []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico"}
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
}

func isValidPath(path string) bool {
	if len(path) < 2 || len(path) > 200 {
		return false
	}
	// Skip static paths
	lower := strings.ToLower(path)
	staticExts := []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".ico", ".map"}
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
}

func extractPath(url string) string {
	// Remove protocol and host
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "//")
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[idx:]
	}
	return "/"
}

func containsSensitive(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isAPIPath(path string) bool {
	lower := strings.ToLower(path)
	apiIndicators := []string{"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/auth/", "/user", "/admin"}
	for _, ind := range apiIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func maskSecret(value string) string {
	value = strings.Trim(value, "\"'")
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AnalyzeWithLinkFinder uses linkfinder tool if available for better extraction
func (a *Analyzer) AnalyzeWithLinkFinder(jsURLs []string, outDir string) ([]string, error) {
	if !a.checker.IsInstalled("linkfinder") {
		return nil, nil
	}

	if len(jsURLs) == 0 {
		return nil, nil
	}

	fmt.Println("        Running linkfinder for endpoint extraction...")

	// Limit URLs
	if len(jsURLs) > 100 {
		jsURLs = jsURLs[:100]
	}

	// Run linkfinder on each URL (parallel)
	var endpoints []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

	for _, url := range jsURLs[:min(50, len(jsURLs))] {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := exec.Run("linkfinder", []string{"-i", u, "-o", "cli"},
				&exec.Options{Timeout: 30 * time.Second})
			if r.Error == nil {
				mu.Lock()
				for _, line := range exec.Lines(r.Stdout) {
					if line != "" && strings.HasPrefix(line, "/") {
						endpoints = append(endpoints, line)
					}
				}
				mu.Unlock()
			}
		}(url)
	}
	wg.Wait()

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, ep := range endpoints {
		if !seen[ep] {
			seen[ep] = true
			unique = append(unique, ep)
		}
	}
	sort.Strings(unique)

	if len(unique) > 0 {
		fmt.Printf("        linkfinder: %d unique endpoints\n", len(unique))
	}

	return unique, nil
}
