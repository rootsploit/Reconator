package subdomain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
)

// AIPermutator generates smart subdomain permutations using LLM analysis
// Inspired by subwiz (https://github.com/hadriansecurity/subwiz) methodology:
// - Pattern learning from existing subdomains
// - N-gram analysis of subdomain tokens
// - Beam-search style candidate generation
type AIPermutator struct {
	cfg      *config.Config
	provider *aiguided.ProviderManager
}

// NewAIPermutator creates a new AI-powered permutation generator
func NewAIPermutator(cfg *config.Config) *AIPermutator {
	pm := aiguided.NewProviderManager()
	pm.LoadFromEnv()

	configPath := aiguided.GetDefaultConfigPath()
	pm.LoadFromFile(configPath)

	return &AIPermutator{cfg: cfg, provider: pm}
}

// PatternAnalysis represents the AI's analysis of subdomain patterns
type PatternAnalysis struct {
	Patterns        []string `json:"patterns"`
	NamingStyle     string   `json:"naming_style"`
	CommonPrefixes  []string `json:"common_prefixes"`
	CommonSuffixes  []string `json:"common_suffixes"`
	VersionPatterns []string `json:"version_patterns"`
	EnvPatterns     []string `json:"env_patterns"`
	Suggestions     []string `json:"suggestions"`
	Reasoning       string   `json:"reasoning"`
}

// TokenAnalysis holds n-gram analysis results
type TokenAnalysis struct {
	Unigrams  map[string]int // Single tokens: "api", "dev", "admin"
	Bigrams   map[string]int // Token pairs: "api-v", "dev-app"
	Prefixes  map[string]int // First token frequency
	Suffixes  map[string]int // Last token frequency
	Delimiter string         // Most common delimiter: "-", "_", "."
}

// GenerateSmartPermutations uses AI + statistical analysis for targeted permutations
func (p *AIPermutator) GenerateSmartPermutations(domain string, existingSubdomains []string) ([]string, error) {
	providers := p.provider.GetAvailableProviders()
	if len(providers) == 0 {
		// Fallback to pure statistical analysis without AI
		fmt.Println("        [SubGen] No AI providers - using statistical analysis only")
		return p.generateStatisticalPermutations(domain, existingSubdomains)
	}

	prefixes := extractPrefixes(existingSubdomains, domain)
	if len(prefixes) < 3 {
		return nil, fmt.Errorf("not enough subdomains for pattern analysis (need at least 3)")
	}

	// Phase 1: Statistical n-gram analysis (local, fast)
	fmt.Println("        [SubGen] Analyzing subdomain token patterns...")
	tokenAnalysis := analyzeTokens(prefixes)

	// Phase 2: AI-powered pattern recognition
	limitedPrefixes := prefixes
	if len(limitedPrefixes) > 50 {
		limitedPrefixes = limitedPrefixes[:50]
	}

	analysis, provider, err := p.analyzePatterns(domain, limitedPrefixes, tokenAnalysis)
	if err != nil {
		fmt.Printf("        [SubGen] AI analysis failed: %v, using statistical only\n", err)
		return p.generateStatisticalPermutations(domain, existingSubdomains)
	}

	fmt.Printf("        [AI-%s] Pattern analysis complete\n", provider)
	if analysis.NamingStyle != "" {
		fmt.Printf("        Naming style: %s\n", analysis.NamingStyle)
	}
	if len(analysis.Patterns) > 0 {
		fmt.Printf("        Patterns detected: %v\n", analysis.Patterns)
	}
	fmt.Printf("        Top tokens: %v\n", getTopN(tokenAnalysis.Unigrams, 5))

	// Phase 3: Generate permutations using both AI suggestions and statistical patterns
	permutations := p.generateHybridPermutations(domain, analysis, tokenAnalysis, prefixes)

	return permutations, nil
}

// analyzeTokens performs n-gram analysis on subdomain prefixes
// Inspired by subwiz's tokenization approach
func analyzeTokens(prefixes []string) *TokenAnalysis {
	analysis := &TokenAnalysis{
		Unigrams:  make(map[string]int),
		Bigrams:   make(map[string]int),
		Prefixes:  make(map[string]int),
		Suffixes:  make(map[string]int),
		Delimiter: "-",
	}

	delimiterCount := map[string]int{"-": 0, "_": 0, ".": 0}

	for _, prefix := range prefixes {
		// Count delimiters to find most common
		delimiterCount["-"] += strings.Count(prefix, "-")
		delimiterCount["_"] += strings.Count(prefix, "_")
		delimiterCount["."] += strings.Count(prefix, ".")

		// Tokenize by common delimiters
		tokens := tokenize(prefix)
		if len(tokens) == 0 {
			continue
		}

		// Unigrams
		for _, token := range tokens {
			if len(token) > 1 { // Skip single chars
				analysis.Unigrams[token]++
			}
		}

		// Bigrams
		for i := 0; i < len(tokens)-1; i++ {
			bigram := tokens[i] + "-" + tokens[i+1]
			analysis.Bigrams[bigram]++
		}

		// First and last tokens
		analysis.Prefixes[tokens[0]]++
		analysis.Suffixes[tokens[len(tokens)-1]]++
	}

	// Determine most common delimiter
	maxDelim := "-"
	maxCount := 0
	for d, c := range delimiterCount {
		if c > maxCount {
			maxDelim = d
			maxCount = c
		}
	}
	analysis.Delimiter = maxDelim

	return analysis
}

// tokenize splits a subdomain prefix into tokens
func tokenize(prefix string) []string {
	// Split by common delimiters
	re := regexp.MustCompile(`[-_.]`)
	parts := re.Split(prefix, -1)

	// Also split camelCase
	var tokens []string
	for _, part := range parts {
		if part == "" {
			continue
		}
		// Split camelCase: apiGateway -> api, gateway
		camelParts := splitCamelCase(part)
		tokens = append(tokens, camelParts...)
	}

	// Normalize to lowercase
	for i := range tokens {
		tokens[i] = strings.ToLower(tokens[i])
	}

	return tokens
}

// splitCamelCase splits camelCase strings
func splitCamelCase(s string) []string {
	var result []string
	current := ""

	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			if current != "" {
				result = append(result, current)
			}
			current = string(r)
		} else {
			current += string(r)
		}
	}
	if current != "" {
		result = append(result, current)
	}

	return result
}

// getTopN returns top N items from a frequency map
func getTopN(m map[string]int, n int) []string {
	type kv struct {
		Key   string
		Value int
	}

	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make([]string, 0, n)
	for i := 0; i < n && i < len(sorted); i++ {
		result = append(result, sorted[i].Key)
	}
	return result
}

// generateStatisticalPermutations generates permutations without AI
func (p *AIPermutator) generateStatisticalPermutations(domain string, existingSubdomains []string) ([]string, error) {
	prefixes := extractPrefixes(existingSubdomains, domain)
	if len(prefixes) < 3 {
		return nil, fmt.Errorf("not enough subdomains")
	}

	tokenAnalysis := analyzeTokens(prefixes)
	seen := make(map[string]bool)
	for _, prefix := range prefixes {
		seen[prefix] = true
	}

	var permutations []string

	// Get top tokens
	topUnigrams := getTopN(tokenAnalysis.Unigrams, 20)
	topPrefixes := getTopN(tokenAnalysis.Prefixes, 10)
	topSuffixes := getTopN(tokenAnalysis.Suffixes, 10)

	delim := tokenAnalysis.Delimiter

	// Security-relevant tokens to combine
	securityTokens := []string{
		"admin", "api", "internal", "dev", "staging", "prod", "test",
		"beta", "alpha", "v2", "new", "old", "backup", "portal",
		"dashboard", "console", "panel", "mgmt", "manage", "auth",
		"login", "sso", "oauth", "gateway", "proxy", "cdn", "edge",
		"db", "database", "cache", "redis", "mongo", "mysql", "elastic",
	}

	envTokens := []string{"dev", "staging", "qa", "uat", "prod", "test", "demo", "sandbox"}

	// Combine top prefixes with security tokens
	for _, prefix := range topPrefixes {
		for _, sec := range securityTokens {
			perm := prefix + delim + sec
			if !seen[perm] {
				seen[perm] = true
				permutations = append(permutations, perm+"."+domain)
			}
		}
	}

	// Combine security tokens with top suffixes
	for _, sec := range securityTokens[:10] {
		for _, suffix := range topSuffixes {
			perm := sec + delim + suffix
			if !seen[perm] {
				seen[perm] = true
				permutations = append(permutations, perm+"."+domain)
			}
		}
	}

	// Environment variations of top unigrams
	for _, token := range topUnigrams {
		for _, env := range envTokens {
			variations := []string{
				env + delim + token,
				token + delim + env,
			}
			for _, v := range variations {
				if !seen[v] {
					seen[v] = true
					permutations = append(permutations, v+"."+domain)
				}
			}
		}
	}

	// Version increments
	versionPattern := regexp.MustCompile(`(.*?)[-_]?v?(\d+)$`)
	for _, prefix := range prefixes[:min(20, len(prefixes))] {
		matches := versionPattern.FindStringSubmatch(prefix)
		if len(matches) == 3 && matches[1] != "" {
			base := matches[1]
			for i := 1; i <= 5; i++ {
				variations := []string{
					fmt.Sprintf("%sv%d", base, i),
					fmt.Sprintf("%s%sv%d", base, delim, i),
					fmt.Sprintf("%s%d", base, i),
				}
				for _, v := range variations {
					if !seen[v] {
						seen[v] = true
						permutations = append(permutations, v+"."+domain)
					}
				}
			}
		}
	}

	// Limit
	if len(permutations) > 300 {
		permutations = permutations[:300]
	}

	fmt.Printf("        [SubGen] Generated %d statistical permutations\n", len(permutations))
	return permutations, nil
}

func extractPrefixes(subdomains []string, domain string) []string {
	suffix := "." + domain
	seen := make(map[string]bool)
	var prefixes []string

	for _, sub := range subdomains {
		if strings.HasSuffix(sub, suffix) {
			prefix := strings.TrimSuffix(sub, suffix)
			if prefix != "" && !seen[prefix] {
				seen[prefix] = true
				prefixes = append(prefixes, prefix)
			}
		}
	}

	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) != len(prefixes[j]) {
			return len(prefixes[i]) < len(prefixes[j])
		}
		return prefixes[i] < prefixes[j]
	})

	return prefixes
}

func (p *AIPermutator) analyzePatterns(domain string, prefixes []string, tokenAnalysis *TokenAnalysis) (*PatternAnalysis, aiguided.ProviderType, error) {
	prompt := p.buildEnhancedPrompt(domain, prefixes, tokenAnalysis)

	response, provider, err := p.provider.QueryRaw(prompt)
	if err != nil {
		return nil, "", err
	}

	analysis, err := parsePatternAnalysis(response)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse AI response: %w", err)
	}

	return analysis, provider, nil
}

func parsePatternAnalysis(response string) (*PatternAnalysis, error) {
	// Remove <analysis> tags (Few-Shot Pattern Induction output)
	if idx := strings.Index(response, "</analysis>"); idx != -1 {
		response = response[idx+len("</analysis>"):]
	}
	// Also handle case where analysis tag is at the start
	if idx := strings.Index(response, "<analysis>"); idx != -1 {
		if endIdx := strings.Index(response, "</analysis>"); endIdx != -1 {
			response = response[:idx] + response[endIdx+len("</analysis>"):]
		}
	}

	response = strings.TrimSpace(response)

	// Strip markdown code blocks if present
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
	}
	if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
	}
	response = strings.TrimSuffix(response, "```")
	response = strings.TrimSpace(response)

	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]
	var analysis PatternAnalysis
	if err := json.Unmarshal([]byte(jsonStr), &analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}

// buildEnhancedPrompt uses TOON format for 40% token reduction vs XML/JSON
func (p *AIPermutator) buildEnhancedPrompt(domain string, prefixes []string, tokenAnalysis *TokenAnalysis) string {
	topTokens := getTopN(tokenAnalysis.Unigrams, 15)
	topPrefixes := getTopN(tokenAnalysis.Prefixes, 10)
	topSuffixes := getTopN(tokenAnalysis.Suffixes, 10)

	sampleCount := min(30, len(prefixes))

	// Build observed subdomains list (limited sample)
	observedSamples := make([]string, 0, sampleCount)
	for i := 0; i < sampleCount && i < len(prefixes); i++ {
		observedSamples = append(observedSamples, prefixes[i])
	}

	// Use TOON format for compact encoding
	return fmt.Sprintf(`ROLE: Expert DNS Reconnaissance Analyst trained on Fortune 500 subdomain datasets
TASK: Induce naming grammar and predict undiscovered subdomains

==TARGET==
domain: %s
delimiter: %s
observed_count: %d
token_frequency[%d]: %s
common_prefixes[%d]: %s
common_suffixes[%d]: %s

observed_subdomains[%d]:
  %s

==FEW_SHOT_EXAMPLES==
examples[4]{input,grammar,predictions}:
  "api api-prod web-prod auth-service","service(-env)?","api-dev api-staging web-dev auth-service-dev internal-api admin-prod"
  "k8s-master k8s-worker-01 prometheus-k8s grafana","service-k8s | k8s-role-number","k8s-worker-02 k8s-worker-03 alertmanager-k8s loki-k8s k8s-ingress"
  "api-us-east api-eu-west cdn-us cdn-eu","service-region(-zone)?","api-ap-south api-us-west cdn-ap db-us-east cache-eu-west"
  "app-v1 app-v2 api-v3","service-v{N}","app-v3 api-v4 admin-v1 portal-v2"

==PREDICTION_CATEGORIES==
categories[6]{name,priority,keywords}:
  Infrastructure,high,"vpn sso ldap radius gateway proxy waf firewall dns ntp"
  DevOps,high,"jenkins gitlab github bitbucket artifactory nexus sonar ci cd"
  Monitoring,medium,"grafana prometheus kibana elastic datadog newrelic splunk logstash"
  Cloud-K8s,high,"k8s eks aks gke rancher istio consul vault docker registry"
  Internal,medium,"jira confluence wiki intranet helpdesk ticketing hr erp crm"
  Environments,critical,"dev staging uat qa test sandbox demo beta alpha canary"

==CONSTRAINTS==
- NO repeats from observed_subdomains
- ALL predictions follow induced grammar
- MAX 60 predictions
- PRIORITY: env variants > common infra > speculative

==OUTPUT==
First <analysis>: state (1) induced grammar (2) cloud/k8s patterns (3) env convention

Then JSON:
{"patterns":[],"naming_style":"kebab|camel|dot|mixed","cloud_patterns":[],"common_prefixes":[],"common_suffixes":[],"version_patterns":[],"env_patterns":[],"suggestions":["..."],"reasoning":"..."}`,
		domain,
		tokenAnalysis.Delimiter,
		len(prefixes),
		len(topTokens), strings.Join(topTokens, " "),
		len(topPrefixes), strings.Join(topPrefixes, " "),
		len(topSuffixes), strings.Join(topSuffixes, " "),
		len(observedSamples),
		strings.Join(observedSamples, "\n  "),
	)
}

// generateHybridPermutations combines AI suggestions with statistical generation
func (p *AIPermutator) generateHybridPermutations(domain string, analysis *PatternAnalysis, tokenAnalysis *TokenAnalysis, existingPrefixes []string) []string {
	seen := make(map[string]bool)
	for _, prefix := range existingPrefixes {
		seen[prefix] = true
	}

	var permutations []string

	// Priority 1: AI suggestions (highest quality)
	for _, suggestion := range analysis.Suggestions {
		suggestion = strings.ToLower(strings.TrimSpace(suggestion))
		suggestion = strings.TrimSuffix(suggestion, "."+domain)
		if suggestion != "" && !seen[suggestion] {
			seen[suggestion] = true
			permutations = append(permutations, suggestion+"."+domain)
		}
	}

	// Priority 2: Pattern-based generation
	additionalPerms := p.generatePatternBasedPermutations(analysis, tokenAnalysis, existingPrefixes, seen)
	for _, perm := range additionalPerms {
		if !seen[perm] {
			seen[perm] = true
			permutations = append(permutations, perm+"."+domain)
		}
	}

	fmt.Printf("        [SubGen] Generated %d permutations (%d AI + %d pattern-based)\n",
		len(permutations), len(analysis.Suggestions), len(permutations)-len(analysis.Suggestions))

	return permutations
}

func (p *AIPermutator) generatePatternBasedPermutations(analysis *PatternAnalysis, tokenAnalysis *TokenAnalysis, existingPrefixes []string, seen map[string]bool) []string {
	var perms []string
	delim := tokenAnalysis.Delimiter

	securitySuffixes := []string{
		"admin", "api", "internal", "staging", "dev", "test",
		"backup", "old", "new", "v2", "beta", "alpha",
		"portal", "dashboard", "console", "panel", "mgmt",
	}

	envs := analysis.EnvPatterns
	if len(envs) == 0 {
		envs = []string{"dev", "staging", "qa", "uat", "prod", "test"}
	}

	// Combine detected prefixes with environments
	for _, prefix := range analysis.CommonPrefixes {
		for _, env := range envs {
			variations := []string{
				prefix + delim + env,
				env + delim + prefix,
			}
			for _, v := range variations {
				if !seen[v] {
					perms = append(perms, v)
				}
			}
		}
	}

	// Version increments
	versionPattern := regexp.MustCompile(`(.*?)[-_]?v?(\d+)$`)
	for _, prefix := range existingPrefixes[:min(15, len(existingPrefixes))] {
		matches := versionPattern.FindStringSubmatch(prefix)
		if len(matches) == 3 && matches[1] != "" {
			base := matches[1]
			for i := 1; i <= 5; i++ {
				variations := []string{
					fmt.Sprintf("%sv%d", base, i),
					fmt.Sprintf("%s%sv%d", base, delim, i),
					fmt.Sprintf("%s%d", base, i),
				}
				for _, v := range variations {
					if !seen[v] {
						perms = append(perms, v)
					}
				}
			}
		}
	}

	// Security suffix variations
	for _, prefix := range existingPrefixes[:min(10, len(existingPrefixes))] {
		for _, suffix := range securitySuffixes {
			perm := prefix + delim + suffix
			if !seen[perm] {
				perms = append(perms, perm)
			}
		}
	}

	// Combine top unigrams with security tokens
	topTokens := getTopN(tokenAnalysis.Unigrams, 10)
	for _, token := range topTokens {
		for _, sec := range securitySuffixes[:8] {
			if token != sec {
				variations := []string{
					token + delim + sec,
					sec + delim + token,
				}
				for _, v := range variations {
					if !seen[v] {
						perms = append(perms, v)
					}
				}
			}
		}
	}

	if len(perms) > 200 {
		perms = perms[:200]
	}

	return perms
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
