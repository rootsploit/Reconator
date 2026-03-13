package aiguided

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// CheckpointRunner executes AI checkpoints between pipeline levels
type CheckpointRunner struct {
	pm *ProviderManager
}

// NewCheckpointRunner creates a checkpoint runner with AI provider support
func NewCheckpointRunner() *CheckpointRunner {
	pm := NewProviderManager()
	pm.LoadFromEnv()
	configPath := GetDefaultConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		pm.LoadFromFile(configPath)
	}
	return &CheckpointRunner{pm: pm}
}

// HasAISupport returns true if any AI provider is configured
func (cr *CheckpointRunner) HasAISupport() bool {
	return len(cr.pm.GetAvailableProviders()) > 0
}

// RunCheckpoint1 analyzes recon surface after subdomain + historic + JS analysis
// Returns prioritized hosts, adaptive wordlist entries, and phase skip recommendations
func (cr *CheckpointRunner) RunCheckpoint1(ctx context.Context, subdomains []string, historicURLs []string, jsFindings []string) *AIDecisions {
	start := time.Now()
	decisions := &AIDecisions{}

	if !cr.HasAISupport() {
		decisions.Checkpoints = append(decisions.Checkpoints, CheckpointMeta{
			Name:         "checkpoint1",
			Duration:     time.Since(start),
			UsedFallback: true,
		})
		return cr.checkpoint1Fallback(decisions, subdomains)
	}

	// Build TOON-formatted prompt
	prompt := cr.buildCheckpoint1Prompt(subdomains, historicURLs, jsFindings)

	// Execute with 8-second timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	type queryResult struct {
		response string
		provider ProviderType
		err      error
	}
	resultCh := make(chan queryResult, 1)
	go func() {
		result, provider, err := cr.pm.QueryRaw(prompt)
		resultCh <- queryResult{response: result, provider: provider, err: err}
	}()

	select {
	case qr := <-resultCh:
		if qr.err != nil {
			fmt.Printf("        [AI Checkpoint 1] AI error, using fallback: %v\n", qr.err)
			decisions.Checkpoints = append(decisions.Checkpoints, CheckpointMeta{
				Name:         "checkpoint1",
				Duration:     time.Since(start),
				UsedFallback: true,
				Error:        qr.err.Error(),
			})
			return cr.checkpoint1Fallback(decisions, subdomains)
		}
		parsed := cr.parseCheckpoint1Response(qr.response, decisions)
		parsed.Checkpoints = append(parsed.Checkpoints, CheckpointMeta{
			Name:         "checkpoint1",
			Provider:     string(qr.provider),
			Duration:     time.Since(start),
			UsedFallback: false,
		})
		fmt.Printf("        [AI Checkpoint 1] Completed in %s: %d prioritized hosts, %d wordlist entries\n",
			time.Since(start).Round(time.Millisecond), len(parsed.PrioritizedHosts), len(parsed.AdaptiveWordlist))
		return parsed
	case <-timeoutCtx.Done():
		fmt.Printf("        [AI Checkpoint 1] Timeout (8s), using rule-based fallback\n")
		decisions.Checkpoints = append(decisions.Checkpoints, CheckpointMeta{
			Name:         "checkpoint1",
			Duration:     time.Since(start),
			UsedFallback: true,
			Error:        "timeout",
		})
		return cr.checkpoint1Fallback(decisions, subdomains)
	}
}

// RunCheckpoint2 analyzes port/WAF/tech data to optimize scanning strategy
func (cr *CheckpointRunner) RunCheckpoint2(ctx context.Context, aliveHosts []string, openPorts map[string][]int, wafHosts []string, techByHost map[string][]string) *AIDecisions {
	start := time.Now()
	decisions := &AIDecisions{}

	if !cr.HasAISupport() {
		decisions.Checkpoints = append(decisions.Checkpoints, CheckpointMeta{
			Name:         "checkpoint2",
			Duration:     time.Since(start),
			UsedFallback: true,
		})
		return cr.checkpoint2Fallback(decisions, aliveHosts, techByHost)
	}

	prompt := cr.buildCheckpoint2Prompt(aliveHosts, openPorts, wafHosts, techByHost)

	timeoutCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	type queryResult struct {
		response string
		provider ProviderType
		err      error
	}
	resultCh := make(chan queryResult, 1)
	go func() {
		result, provider, err := cr.pm.QueryRaw(prompt)
		resultCh <- queryResult{response: result, provider: provider, err: err}
	}()

	select {
	case qr := <-resultCh:
		if qr.err != nil {
			fmt.Printf("        [AI Checkpoint 2] AI error, using fallback: %v\n", qr.err)
			decisions.Checkpoints = append(decisions.Checkpoints, CheckpointMeta{
				Name:         "checkpoint2",
				Duration:     time.Since(start),
				UsedFallback: true,
				Error:        qr.err.Error(),
			})
			return cr.checkpoint2Fallback(decisions, aliveHosts, techByHost)
		}
		parsed := cr.parseCheckpoint2Response(qr.response, decisions)
		parsed.Checkpoints = append(parsed.Checkpoints, CheckpointMeta{
			Name:         "checkpoint2",
			Provider:     string(qr.provider),
			Duration:     time.Since(start),
			UsedFallback: false,
		})
		fmt.Printf("        [AI Checkpoint 2] Completed in %s: %d nuclei tags, %d custom words\n",
			time.Since(start).Round(time.Millisecond), len(parsed.NucleiTags), len(parsed.CustomDirWords))
		return parsed
	case <-timeoutCtx.Done():
		fmt.Printf("        [AI Checkpoint 2] Timeout (8s), using rule-based fallback\n")
		decisions.Checkpoints = append(decisions.Checkpoints, CheckpointMeta{
			Name:         "checkpoint2",
			Duration:     time.Since(start),
			UsedFallback: true,
			Error:        "timeout",
		})
		return cr.checkpoint2Fallback(decisions, aliveHosts, techByHost)
	}
}

// buildCheckpoint1Prompt creates TOON-formatted prompt for checkpoint 1
func (cr *CheckpointRunner) buildCheckpoint1Prompt(subdomains []string, historicURLs []string, jsFindings []string) string {
	var sb strings.Builder
	sb.WriteString("You are a reconnaissance AI analyst. Analyze the following recon surface and provide strategic recommendations.\n\n")
	sb.WriteString("[recon_surface]\n")

	// Limit to prevent token explosion
	maxSubs := 50
	if len(subdomains) > maxSubs {
		sb.WriteString(fmt.Sprintf("subdomains=%d (showing %d)\n", len(subdomains), maxSubs))
		for _, s := range subdomains[:maxSubs] {
			sb.WriteString(fmt.Sprintf("  %s\n", s))
		}
	} else {
		sb.WriteString(fmt.Sprintf("subdomains=%d\n", len(subdomains)))
		for _, s := range subdomains {
			sb.WriteString(fmt.Sprintf("  %s\n", s))
		}
	}

	sb.WriteString(fmt.Sprintf("historic_urls=%d\n", len(historicURLs)))
	// Show sample interesting URLs
	maxURLs := 20
	interesting := filterInterestingURLs(historicURLs)
	if len(interesting) > maxURLs {
		interesting = interesting[:maxURLs]
	}
	for _, u := range interesting {
		sb.WriteString(fmt.Sprintf("  %s\n", u))
	}

	if len(jsFindings) > 0 {
		sb.WriteString(fmt.Sprintf("js_findings=%d\n", len(jsFindings)))
		maxJS := 10
		if len(jsFindings) > maxJS {
			jsFindings = jsFindings[:maxJS]
		}
		for _, f := range jsFindings {
			sb.WriteString(fmt.Sprintf("  %s\n", f))
		}
	}

	sb.WriteString("\n[respond_json]\n")
	sb.WriteString(`{
  "prioritized_hosts": [{"host": "example.com", "priority": 1, "reason": "..."}],
  "adaptive_wordlist": ["/api/v1/", "/admin/"],
  "skip_phases": []
}`)
	sb.WriteString("\nReturn ONLY valid JSON. Priority 1=highest, 5=lowest.")

	return sb.String()
}

// buildCheckpoint2Prompt creates TOON-formatted prompt for checkpoint 2
func (cr *CheckpointRunner) buildCheckpoint2Prompt(aliveHosts []string, openPorts map[string][]int, wafHosts []string, techByHost map[string][]string) string {
	var sb strings.Builder
	sb.WriteString("You are a reconnaissance AI analyst. Based on discovered infrastructure, optimize the scanning strategy.\n\n")
	sb.WriteString("[infrastructure]\n")

	sb.WriteString(fmt.Sprintf("alive_hosts=%d waf_hosts=%d\n", len(aliveHosts), len(wafHosts)))

	// Show host details
	maxHosts := 30
	shown := 0
	for host, ports := range openPorts {
		if shown >= maxHosts {
			break
		}
		portStrs := make([]string, 0, len(ports))
		for _, p := range ports {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		techs := techByHost[host]
		isWAF := false
		for _, w := range wafHosts {
			if w == host {
				isWAF = true
				break
			}
		}
		sb.WriteString(fmt.Sprintf("  %s ports=[%s] tech=[%s] waf=%v\n",
			host, strings.Join(portStrs, ","), strings.Join(techs, ","), isWAF))
		shown++
	}

	sb.WriteString("\n[respond_json]\n")
	sb.WriteString(`{
  "nuclei_tags": ["cve", "tech-specific-tag"],
  "host_scan_strategy": {"host.com": "full"},
  "custom_dir_words": ["/api/", "/swagger/"]
}`)
	sb.WriteString("\nReturn ONLY valid JSON. Strategy: full|light|skip.")

	return sb.String()
}

// parseCheckpoint1Response parses AI response for checkpoint 1
func (cr *CheckpointRunner) parseCheckpoint1Response(response string, decisions *AIDecisions) *AIDecisions {
	// Extract JSON from response (may be wrapped in markdown code blocks)
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return decisions
	}

	var parsed struct {
		PrioritizedHosts []HostPriority `json:"prioritized_hosts"`
		AdaptiveWordlist []string       `json:"adaptive_wordlist"`
		SkipPhases       []string       `json:"skip_phases"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		fmt.Printf("        [AI Checkpoint 1] Failed to parse response: %v\n", err)
		return decisions
	}

	decisions.PrioritizedHosts = parsed.PrioritizedHosts
	decisions.AdaptiveWordlist = parsed.AdaptiveWordlist
	decisions.SkipPhases = parsed.SkipPhases
	return decisions
}

// parseCheckpoint2Response parses AI response for checkpoint 2
func (cr *CheckpointRunner) parseCheckpoint2Response(response string, decisions *AIDecisions) *AIDecisions {
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return decisions
	}

	var parsed struct {
		NucleiTags       []string          `json:"nuclei_tags"`
		HostScanStrategy map[string]string `json:"host_scan_strategy"`
		CustomDirWords   []string          `json:"custom_dir_words"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		fmt.Printf("        [AI Checkpoint 2] Failed to parse response: %v\n", err)
		return decisions
	}

	decisions.NucleiTags = parsed.NucleiTags
	decisions.HostScanStrategy = parsed.HostScanStrategy
	decisions.CustomDirWords = parsed.CustomDirWords
	return decisions
}

// checkpoint1Fallback applies rule-based logic when AI is unavailable
func (cr *CheckpointRunner) checkpoint1Fallback(decisions *AIDecisions, subdomains []string) *AIDecisions {
	// All hosts get equal priority
	for _, sub := range subdomains {
		decisions.PrioritizedHosts = append(decisions.PrioritizedHosts, HostPriority{
			Host:     sub,
			Priority: 3,
			Reason:   "default",
		})
	}
	// No adaptive wordlist or phase skipping in fallback mode
	return decisions
}

// checkpoint2Fallback applies rule-based tech-to-tag mapping
func (cr *CheckpointRunner) checkpoint2Fallback(decisions *AIDecisions, aliveHosts []string, techByHost map[string][]string) *AIDecisions {
	// Use existing tech -> nuclei tag mapping pattern from scanner.go getDefaultRecommendations()
	tagSet := make(map[string]bool)
	wordSet := make(map[string]bool)

	for _, techs := range techByHost {
		for _, tech := range techs {
			techLower := strings.ToLower(tech)
			// Map tech to nuclei tags
			switch {
			case strings.Contains(techLower, "wordpress"):
				tagSet["wordpress"] = true
				tagSet["wp-plugin"] = true
				wordSet["/wp-admin/"] = true
				wordSet["/wp-content/uploads/"] = true
				wordSet["/wp-json/wp/v2/users"] = true
				wordSet["/xmlrpc.php"] = true
			case strings.Contains(techLower, "joomla"):
				tagSet["joomla"] = true
				wordSet["/administrator/"] = true
			case strings.Contains(techLower, "drupal"):
				tagSet["drupal"] = true
				wordSet["/admin/"] = true
				wordSet["/sites/default/files/"] = true
			case strings.Contains(techLower, "apache"):
				tagSet["apache"] = true
				wordSet["/.htaccess"] = true
				wordSet["/server-status"] = true
			case strings.Contains(techLower, "nginx"):
				tagSet["nginx"] = true
				wordSet["/nginx_status"] = true
			case strings.Contains(techLower, "iis"):
				tagSet["iis"] = true
				wordSet["/web.config"] = true
			case strings.Contains(techLower, "php"):
				tagSet["php"] = true
				wordSet["/info.php"] = true
				wordSet["/phpinfo.php"] = true
			case strings.Contains(techLower, "django"), strings.Contains(techLower, "python"):
				tagSet["django"] = true
				wordSet["/admin/"] = true
				wordSet["/__debug__/"] = true
				wordSet["/api/schema/"] = true
			case strings.Contains(techLower, "spring"), strings.Contains(techLower, "java"):
				tagSet["spring"] = true
				wordSet["/actuator/"] = true
				wordSet["/actuator/env"] = true
				wordSet["/swagger-ui/"] = true
				wordSet["/h2-console/"] = true
			case strings.Contains(techLower, "laravel"):
				tagSet["laravel"] = true
				wordSet["/.env"] = true
				wordSet["/telescope/"] = true
				wordSet["/horizon/"] = true
			case strings.Contains(techLower, "node"), strings.Contains(techLower, "express"):
				tagSet["nodejs"] = true
				wordSet["/.env"] = true
				wordSet["/api/"] = true
			case strings.Contains(techLower, "ruby"), strings.Contains(techLower, "rails"):
				tagSet["rails"] = true
				wordSet["/rails/info/routes"] = true
			case strings.Contains(techLower, "tomcat"):
				tagSet["tomcat"] = true
				wordSet["/manager/html"] = true
				wordSet["/host-manager/html"] = true
			case strings.Contains(techLower, "grafana"):
				tagSet["grafana"] = true
			case strings.Contains(techLower, "jenkins"):
				tagSet["jenkins"] = true
				wordSet["/script"] = true
			case strings.Contains(techLower, "gitlab"):
				tagSet["gitlab"] = true
			}
		}
	}

	// Always include common tags
	tagSet["cve"] = true
	tagSet["exposure"] = true
	tagSet["misconfig"] = true

	for tag := range tagSet {
		decisions.NucleiTags = append(decisions.NucleiTags, tag)
	}
	for word := range wordSet {
		decisions.CustomDirWords = append(decisions.CustomDirWords, word)
	}

	// Default strategy: full for all hosts
	decisions.HostScanStrategy = make(map[string]string)
	for _, host := range aliveHosts {
		decisions.HostScanStrategy[host] = "full"
	}

	return decisions
}

// extractJSON extracts JSON from a response that may contain markdown code blocks
func extractJSON(response string) string {
	// Try to find JSON block in markdown
	if idx := strings.Index(response, "```json"); idx >= 0 {
		start := idx + 7
		end := strings.Index(response[start:], "```")
		if end >= 0 {
			return strings.TrimSpace(response[start : start+end])
		}
	}
	if idx := strings.Index(response, "```"); idx >= 0 {
		start := idx + 3
		// Skip language identifier if present
		if nl := strings.Index(response[start:], "\n"); nl >= 0 {
			start += nl + 1
		}
		end := strings.Index(response[start:], "```")
		if end >= 0 {
			return strings.TrimSpace(response[start : start+end])
		}
	}

	// Try to find raw JSON
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start >= 0 && end > start {
		return response[start : end+1]
	}

	return ""
}

// filterInterestingURLs filters URLs to only include interesting ones
func filterInterestingURLs(urls []string) []string {
	var interesting []string
	for _, u := range urls {
		lower := strings.ToLower(u)
		if strings.Contains(lower, "api") ||
			strings.Contains(lower, "admin") ||
			strings.Contains(lower, "config") ||
			strings.Contains(lower, "debug") ||
			strings.Contains(lower, "swagger") ||
			strings.Contains(lower, "graphql") ||
			strings.Contains(lower, ".env") ||
			strings.Contains(lower, "upload") ||
			strings.Contains(lower, "login") ||
			strings.Contains(lower, "dashboard") ||
			strings.Contains(lower, "internal") ||
			strings.Contains(lower, "secret") {
			interesting = append(interesting, u)
		}
	}
	if len(interesting) == 0 && len(urls) > 0 {
		// Return first few URLs if no interesting ones found
		maxURLs := 10
		if len(urls) < maxURLs {
			maxURLs = len(urls)
		}
		return urls[:maxURLs]
	}
	return interesting
}
