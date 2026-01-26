package aiguided

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	TargetSummary        string            `json:"target_summary"`
	CVEsFromTech         []CVEInfo         `json:"cves_from_tech,omitempty"`
	RecommendedTags      []string          `json:"recommended_tags"`
	RecommendedTemplates []string          `json:"recommended_templates"`
	AIProvider           string            `json:"ai_provider"`
	Vulnerabilities      []Vulnerability   `json:"vulnerabilities"`
	ChainAnalysis        *ChainAnalysis    `json:"chain_analysis,omitempty"`
	ExecutiveSummary     *ExecutiveSummary `json:"executive_summary,omitempty"`
	Duration             time.Duration     `json:"duration"`
}

type CVEInfo struct {
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	Product     string  `json:"product"`
	HasPOC      bool    `json:"has_poc"`
	IsKEV       bool    `json:"is_kev"`
	Description string  `json:"description,omitempty"`
}

type Vulnerability struct {
	Host        string `json:"host"`
	URL         string `json:"url,omitempty"`
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

type TargetContext struct {
	Domain               string   `json:"domain"`
	Technologies         []string `json:"technologies"`
	Endpoints            []string `json:"endpoints"`
	JSFiles              []string `json:"js_files"`
	APIEndpoints         []string `json:"api_endpoints"`
	Services             []string `json:"services"`
	WAFDetected          bool     `json:"waf_detected"`
	CDNHosts             int      `json:"cdn_hosts"`
	SecurityHeaderIssues int      `json:"security_header_issues"` // Hosts with missing security headers
}

type Scanner struct {
	cfg      *config.Config
	c        *tools.Checker
	provider *ProviderManager
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	// Initialize provider manager with environment keys
	pm := NewProviderManager()
	pm.LoadFromEnv()

	// Also load from config file if specified
	configPath := GetDefaultConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		pm.LoadFromFile(configPath)
	}

	// Add keys from config if not already loaded from env
	if cfg.OpenAIKey != "" {
		pm.addProvider(ProviderOpenAI, []string{cfg.OpenAIKey}, "", "gpt-4o-mini", 60)
	}
	if cfg.ClaudeKey != "" {
		pm.addProvider(ProviderClaude, []string{cfg.ClaudeKey}, "", "claude-sonnet-4-20250514", 50)
	}
	if cfg.GeminiKey != "" {
		pm.addProvider(ProviderGemini, []string{cfg.GeminiKey}, "", "gemini-1.5-flash", 60)
	}
	if cfg.OllamaURL != "" || cfg.OllamaModel != "" {
		url := cfg.OllamaURL
		if url == "" {
			url = "http://localhost:11434"
		}
		model := cfg.OllamaModel
		if model == "" {
			model = "llama3.2"
		}
		pm.addProvider(ProviderOllama, []string{""}, url, model, 0)
	}

	return &Scanner{cfg: cfg, c: checker, provider: pm}
}

// Scan performs smart scanning using CVEMap (primary) + AI recommendations (secondary)
func (s *Scanner) Scan(hosts []string, ctx *TargetContext) (*Result, error) {
	start := time.Now()
	result := &Result{
		CVEsFromTech:    []CVEInfo{},
		Vulnerabilities: []Vulnerability{},
	}

	if len(hosts) == 0 {
		return result, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Phase 1: VulnX lookup for detected technologies (PRIMARY - real CVE data)
	var cveIDs []string
	if s.c.IsInstalled("vulnx") && len(ctx.Technologies) > 0 {
		fmt.Println("        [VulnX] Looking up CVEs for detected technologies...")
		cves := s.lookupCVEsForTech(ctx.Technologies)
		mu.Lock()
		result.CVEsFromTech = cves
		for _, cve := range cves {
			cveIDs = append(cveIDs, cve.CVEID)
		}
		mu.Unlock()
		fmt.Printf("        [VulnX] Found %d relevant CVEs\n", len(cves))

		// Summarize by severity
		if len(cves) > 0 {
			sevCount := make(map[string]int)
			pocCount := 0
			kevCount := 0
			for _, cve := range cves {
				sevCount[cve.Severity]++
				if cve.HasPOC {
					pocCount++
				}
				if cve.IsKEV {
					kevCount++
				}
			}
			fmt.Printf("        Severity: critical=%d high=%d medium=%d | POC=%d KEV=%d\n",
				sevCount["critical"], sevCount["high"], sevCount["medium"], pocCount, kevCount)
		}
	}

	// Phase 2: AI recommendations for misconfigs (SECONDARY)
	// Use ProviderManager for key rotation and failover
	hasAIProviders := len(s.provider.GetAvailableProviders()) > 0
	if hasAIProviders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        [AI] Getting misconfiguration recommendations...")
			fmt.Printf("        [AI] Available providers: %v\n", s.provider.GetAvailableProviders())
			rec, provider, err := s.getAIRecommendationsWithRotation(ctx)
			if err != nil {
				fmt.Printf("        [AI] Failed: %v, using defaults\n", err)
				rec = s.getDefaultRecommendations(ctx)
				provider = ProviderType("fallback")
			}
			mu.Lock()
			result.TargetSummary = rec.Summary
			result.RecommendedTags = rec.Tags
			result.RecommendedTemplates = append(result.RecommendedTemplates, rec.Templates...)
			result.AIProvider = string(provider)
			mu.Unlock()
			fmt.Printf("        [AI] Provider: %s, Tags: %v\n", provider, rec.Tags)
		}()
	} else {
		rec := s.getDefaultRecommendations(ctx)
		result.TargetSummary = rec.Summary
		result.RecommendedTags = rec.Tags
		result.AIProvider = "fallback"
	}

	wg.Wait()

	// Add CVE IDs from vulnx to recommended templates
	result.RecommendedTemplates = append(result.RecommendedTemplates, cveIDs...)

	// Phase 3: Run nuclei with combined recommendations
	if s.c.IsInstalled("nuclei") && (len(cveIDs) > 0 || len(result.RecommendedTags) > 0) {
		fmt.Println("        [Nuclei] Running with smart template selection...")
		vulns := s.runNuclei(hosts, cveIDs, result.RecommendedTags)
		result.Vulnerabilities = vulns
		fmt.Printf("        [Nuclei] Found %d vulnerabilities\n", len(vulns))
	}

	// Phase 4: AI Vulnerability Chaining Analysis
	if len(result.Vulnerabilities) >= 2 && hasAIProviders {
		fmt.Println("        [AI Chain] Analyzing vulnerability chains...")
		chainer := NewVulnChainer()
		chainAnalysis, err := chainer.AnalyzeChains(result.Vulnerabilities, ctx)
		if err == nil && chainAnalysis != nil {
			result.ChainAnalysis = chainAnalysis
			fmt.Printf("        [AI Chain] Found %d potential attack chains\n", len(chainAnalysis.Chains))
			if len(chainAnalysis.Chains) > 0 {
				for _, chain := range chainAnalysis.Chains {
					fmt.Printf("          - %s [%s]: %s\n", chain.Name, chain.Severity, chain.Description)
				}
			}
		} else if err != nil {
			fmt.Printf("        [AI Chain] Analysis failed: %v\n", err)
		}
	}

	// Phase 5: Executive Summary (ALWAYS generated - even without vulnerabilities)
	// Provides valuable asset overview, attack surface analysis, and manual testing priorities
	fmt.Println("        [AI Summary] Generating executive summary...")
	assetSummary := GenerateAssetSummary(ctx, nil, result.Vulnerabilities)
	// Set security header issues from context
	assetSummary.SetSecurityHeaderIssues(ctx.SecurityHeaderIssues)
	summaryGen := NewSummaryGenerator()
	execSummary, err := summaryGen.GenerateExecutiveSummary(assetSummary, result.Vulnerabilities, result.ChainAnalysis)
	if err == nil && execSummary != nil {
		result.ExecutiveSummary = execSummary
		fmt.Printf("        [AI Summary] Generated by: %s\n", execSummary.Provider)
	} else if err != nil {
		fmt.Printf("        [AI Summary] Generation failed: %v\n", err)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// lookupCVEsForTech uses vulnx to find CVEs for technologies
func (s *Scanner) lookupCVEsForTech(technologies []string) []CVEInfo {
	var allCVEs []CVEInfo
	seen := make(map[string]bool)

	for _, tech := range technologies {
		searchTerm := normalizeTechName(tech)
		if searchTerm == "" {
			continue
		}

		cves := s.queryCVEMap(searchTerm)
		for _, cve := range cves {
			if !seen[cve.CVEID] {
				seen[cve.CVEID] = true
				cve.Product = tech
				allCVEs = append(allCVEs, cve)
			}
		}
	}

	return allCVEs
}

// queryCVEMap runs vulnx for a specific product (next-gen cvemap)
func (s *Scanner) queryCVEMap(product string) []CVEInfo {
	var cves []CVEInfo

	// Use vulnx search command with product filter
	// Docs: vulnx search --product apache --severity critical,high --json
	args := []string{
		"search",
		"--product", product,
		"--severity", "critical,high",
		"--json",
		"--limit", "25",
		"--silent",
	}

	r := exec.Run("vulnx", args, &exec.Options{Timeout: 2 * time.Minute})
	if r.Error != nil {
		return cves
	}

	// Parse JSON lines output
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			CVEID     string  `json:"cve_id"`
			Severity  string  `json:"severity"`
			CVSSScore float64 `json:"cvss_score"`
			HasPOC    bool    `json:"has_poc"`
			IsKEV     bool    `json:"is_kev"`
			Summary   string  `json:"summary"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.CVEID != "" {
			cves = append(cves, CVEInfo{
				CVEID:       entry.CVEID,
				Severity:    entry.Severity,
				CVSSScore:   entry.CVSSScore,
				HasPOC:      entry.HasPOC,
				IsKEV:       entry.IsKEV,
				Description: truncateString(entry.Summary, 150),
			})
		}
	}

	return cves
}

// normalizeTechName converts technology names to vulnx search terms
func normalizeTechName(tech string) string {
	techMap := map[string]string{
		"nginx":         "nginx",
		"apache":        "apache",
		"iis":           "microsoft iis",
		"tomcat":        "apache tomcat",
		"wordpress":     "wordpress",
		"drupal":        "drupal",
		"joomla":        "joomla",
		"php":           "php",
		"java":          "java",
		"spring":        "spring",
		"springboot":    "spring boot",
		"nodejs":        "node.js",
		"express":       "express",
		"django":        "django",
		"flask":         "flask",
		"rails":         "ruby on rails",
		"laravel":       "laravel",
		"jenkins":       "jenkins",
		"gitlab":        "gitlab",
		"jira":          "jira",
		"confluence":    "confluence",
		"grafana":       "grafana",
		"elasticsearch": "elasticsearch",
		"kibana":        "kibana",
		"mongodb":       "mongodb",
		"mysql":         "mysql",
		"postgresql":    "postgresql",
		"redis":         "redis",
		"docker":        "docker",
		"kubernetes":    "kubernetes",
		"openssl":       "openssl",
		"traefik":       "traefik",
		"haproxy":       "haproxy",
		"varnish":       "varnish",
	}

	lower := strings.ToLower(tech)

	if mapped, ok := techMap[lower]; ok {
		return mapped
	}

	for key, value := range techMap {
		if strings.Contains(lower, key) {
			return value
		}
	}

	if len(tech) > 2 {
		return lower
	}

	return ""
}

type AIRecommendation struct {
	Summary   string   `json:"summary"`
	Tags      []string `json:"tags"`
	Templates []string `json:"templates"`
	Reasoning string   `json:"reasoning"`
}

// getAIRecommendationsWithRotation uses ProviderManager for key rotation and failover
func (s *Scanner) getAIRecommendationsWithRotation(ctx *TargetContext) (*AIRecommendation, ProviderType, error) {
	prompt := s.buildPrompt(ctx)
	return s.provider.Query(prompt)
}

// getAIRecommendations is the legacy method (kept for backwards compatibility)
func (s *Scanner) getAIRecommendations(ctx *TargetContext) (*AIRecommendation, string, error) {
	rec, provider, err := s.getAIRecommendationsWithRotation(ctx)
	return rec, string(provider), err
}

func (s *Scanner) buildPrompt(ctx *TargetContext) string {
	// Build technologies list safely
	techList := "None detected"
	if len(ctx.Technologies) > 0 {
		techList = strings.Join(ctx.Technologies, ", ")
	}

	// Build services list
	servicesList := "None detected"
	if len(ctx.Services) > 0 {
		servicesList = strings.Join(ctx.Services, ", ")
	}

	// Truncate endpoints for prompt (max 10)
	endpointSample := ""
	if len(ctx.Endpoints) > 0 {
		limit := 10
		if len(ctx.Endpoints) < limit {
			limit = len(ctx.Endpoints)
		}
		endpointSample = strings.Join(ctx.Endpoints[:limit], "\n    ")
	}

	// Truncate JS files for prompt (max 5)
	jsSample := ""
	if len(ctx.JSFiles) > 0 {
		limit := 5
		if len(ctx.JSFiles) < limit {
			limit = len(ctx.JSFiles)
		}
		jsSample = strings.Join(ctx.JSFiles[:limit], "\n    ")
	}

	// Truncate API endpoints for prompt (max 5)
	apiSample := ""
	if len(ctx.APIEndpoints) > 0 {
		limit := 5
		if len(ctx.APIEndpoints) < limit {
			limit = len(ctx.APIEndpoints)
		}
		apiSample = strings.Join(ctx.APIEndpoints[:limit], "\n    ")
	}

	wafStatus := "Not Detected"
	if ctx.WAFDetected {
		wafStatus = "DETECTED - Use evasion-friendly techniques"
	}

	return fmt.Sprintf(`<agent_core>
  <context>You are the Logic Engine for a specialized vulnerability scanner. Your ONLY task is to map detected technologies to precise Nuclei templates/tags.</context>
  <objective>Analyze the target's technology fingerprint and recommend the highest-impact Nuclei tags for vulnerability discovery.</objective>
</agent_core>

<target_fingerprint>
  <domain>%s</domain>
  <technologies>%s</technologies>
  <services>%s</services>
  <waf_status>%s</waf_status>
  <attack_surface>
    <total_endpoints>%d</total_endpoints>
    <total_js_files>%d</total_js_files>
    <total_api_endpoints>%d</total_api_endpoints>
    <cdn_protected_hosts>%d</cdn_protected_hosts>
  </attack_surface>
  <sample_endpoints>
    %s
  </sample_endpoints>
  <sample_js_files>
    %s
  </sample_js_files>
  <sample_api_endpoints>
    %s
  </sample_api_endpoints>
</target_fingerprint>

<tech_to_tag_mapping>
  <!-- Web Servers -->
  nginx -> nginx, nginx-detect
  apache -> apache, apache-detect
  iis -> iis, microsoft
  tomcat -> tomcat, apache-tomcat

  <!-- CMS -->
  wordpress -> wordpress, wp-plugin, wp-theme
  drupal -> drupal
  joomla -> joomla

  <!-- Frameworks -->
  spring, springboot -> springboot, actuator, spring
  django -> django, python
  laravel -> laravel, php
  express, nodejs -> nodejs, express
  rails -> rails, ruby

  <!-- DevOps/CI -->
  jenkins -> jenkins, ci
  gitlab -> gitlab, git
  kubernetes -> kubernetes, k8s, helm
  docker -> docker, container

  <!-- Databases -->
  mysql -> mysql, database
  postgresql -> postgresql, database
  mongodb -> mongodb, nosql
  redis -> redis, cache
  elasticsearch -> elasticsearch, elastic

  <!-- Monitoring -->
  grafana -> grafana, monitoring
  prometheus -> prometheus
  kibana -> kibana

  <!-- Cloud -->
  aws -> aws, amazon, s3
  azure -> azure, microsoft
  gcp -> gcp, google-cloud
</tech_to_tag_mapping>

<constraints>
  <hard_rules>
    - ONLY recommend tags that exist in Nuclei's public template library
    - Maximum 12 tags total to avoid scan timeout
    - If WAF detected, prioritize: misconfig, exposure, token-spray (passive/semi-passive)
    - If no WAF, include: cve, sqli, xss, rce for active testing
  </hard_rules>
  <priority_order>
    1. Technology-specific tags (highest signal)
    2. Service-specific tags (ports/protocols)
    3. Generic high-value: misconfig, exposure, default-login, cve
    4. API-specific if endpoints detected: api, swagger, graphql
  </priority_order>
</constraints>

<output_format>
First, write your analysis in <thinking> tags. Then output ONLY valid JSON:
{
  "summary": "Brief description of target and focus areas",
  "tags": ["tag1", "tag2", ...],
  "templates": [],
  "reasoning": "Why these specific tags were chosen based on detected tech"
}
</output_format>`,
		ctx.Domain,
		techList,
		servicesList,
		wafStatus,
		len(ctx.Endpoints),
		len(ctx.JSFiles),
		len(ctx.APIEndpoints),
		ctx.CDNHosts,
		endpointSample,
		jsSample,
		apiSample,
	)
}

func (s *Scanner) queryOpenAI(prompt, apiKey string) (*AIRecommendation, error) {
	reqBody := map[string]interface{}{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  400,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OpenAI error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Choices[0].Message.Content)
}

func (s *Scanner) queryClaude(prompt, apiKey string) (*AIRecommendation, error) {
	reqBody := map[string]interface{}{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 400,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Claude error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Content[0].Text)
}

func (s *Scanner) queryGemini(prompt, apiKey string) (*AIRecommendation, error) {
	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{"temperature": 0.3, "maxOutputTokens": 400},
	}

	body, _ := json.Marshal(reqBody)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=%s", apiKey)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Gemini error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Candidates[0].Content.Parts[0].Text)
}

func (s *Scanner) queryOllama(prompt string) (*AIRecommendation, error) {
	// Default Ollama URL if not specified
	ollamaURL := s.cfg.OllamaURL
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	// Default model if not specified
	model := s.cfg.OllamaModel
	if model == "" {
		model = "llama3.2" // Default to llama3.2
	}

	// Ollama API uses /api/generate endpoint
	reqBody := map[string]interface{}{
		"model":  model,
		"prompt": "You are a security expert. Respond only with valid JSON.\n\n" + prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 500,
		},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", ollamaURL+"/api/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second} // Longer timeout for local inference
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Ollama connection failed: %v (is Ollama running?)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Ollama error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Response string `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Response == "" {
		return nil, fmt.Errorf("no response from Ollama")
	}

	return parseAIResponse(result.Response)
}

func parseAIResponse(content string) (*AIRecommendation, error) {
	content = strings.TrimSpace(content)

	// Remove <thinking> tags (System 2 Prompting output)
	if idx := strings.Index(content, "</thinking>"); idx != -1 {
		content = content[idx+len("</thinking>"):]
	}
	// Also handle case where thinking tag is at the start
	if idx := strings.Index(content, "<thinking>"); idx != -1 {
		if endIdx := strings.Index(content, "</thinking>"); endIdx != -1 {
			content = content[:idx] + content[endIdx+len("</thinking>"):]
		}
	}

	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
	}
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// Find the JSON object in the response
	startIdx := strings.Index(content, "{")
	endIdx := strings.LastIndex(content, "}")
	if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
		content = content[startIdx : endIdx+1]
	}

	var rec AIRecommendation
	if err := json.Unmarshal([]byte(content), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Scanner) getDefaultRecommendations(ctx *TargetContext) *AIRecommendation {
	tags := []string{"misconfig", "exposure", "default-login"}

	for _, tech := range ctx.Technologies {
		techLower := strings.ToLower(tech)
		switch {
		case strings.Contains(techLower, "wordpress"):
			tags = append(tags, "wordpress")
		case strings.Contains(techLower, "nginx"):
			tags = append(tags, "nginx")
		case strings.Contains(techLower, "apache"):
			tags = append(tags, "apache")
		case strings.Contains(techLower, "jenkins"):
			tags = append(tags, "jenkins")
		case strings.Contains(techLower, "gitlab"):
			tags = append(tags, "gitlab")
		case strings.Contains(techLower, "jira"):
			tags = append(tags, "jira")
		case strings.Contains(techLower, "grafana"):
			tags = append(tags, "grafana")
		}
	}

	return &AIRecommendation{
		Summary:   "Default recommendations based on detected technologies",
		Tags:      tags,
		Templates: []string{},
		Reasoning: "Using technology-based defaults",
	}
}

func (s *Scanner) runNuclei(hosts []string, cveIDs []string, tags []string) []Vulnerability {
	var vulns []Vulnerability

	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-smart-hosts.txt")
	if err != nil {
		return vulns
	}
	defer cleanup()

	args := []string{
		"-l", tmp,
		"-severity", "high,critical", // Skip medium for speed
		"-silent", "-jsonl",
		"-exclude-tags", "dos,fuzz",
		"-ss", "host-spray",
		"-mhe", "3",
		"-timeout", "5",
		"-duc",
	}

	// Add CVE IDs from vulnx (high priority - real CVEs)
	// Limit to 20 to avoid long scans
	if len(cveIDs) > 0 {
		limit := 20
		if len(cveIDs) < limit {
			limit = len(cveIDs)
		}
		for i := 0; i < limit; i++ {
			args = append(args, "-id", cveIDs[i])
		}
	}

	// Add tags for misconfiguration scanning
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	// Performance tuning
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
		args = append(args, "-bs", fmt.Sprintf("%d", s.cfg.Threads*2))
		args = append(args, "-pc", fmt.Sprintf("%d", s.cfg.Threads))
	} else {
		args = append(args, "-c", "50", "-bs", "100", "-pc", "50")
	}

	if s.cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.cfg.RateLimit))
	} else {
		args = append(args, "-rl", "500")
	}

	// 10 minute timeout for AI-guided scan (should be quick with targeted templates)
	r := exec.Run("nuclei", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return vulns
	}

	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			Host       string `json:"host"`
			MatchedAt  string `json:"matched-at"`
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"info"`
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if entry.Host == "" && entry.MatchedAt == "" {
			continue
		}

		vulns = append(vulns, Vulnerability{
			Host:        entry.Host,
			URL:         entry.MatchedAt,
			TemplateID:  entry.TemplateID,
			Name:        entry.Info.Name,
			Severity:    entry.Info.Severity,
			Type:        entry.Type,
			Description: entry.Info.Description,
		})
	}

	return vulns
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func GetAPIKeysFromEnv() (openai, claude, gemini string) {
	openai = os.Getenv("OPENAI_API_KEY")
	claude = os.Getenv("ANTHROPIC_API_KEY")
	if claude == "" {
		claude = os.Getenv("CLAUDE_API_KEY")
	}
	gemini = os.Getenv("GEMINI_API_KEY")
	if gemini == "" {
		gemini = os.Getenv("GOOGLE_AI_KEY")
	}
	return
}

// GetOllamaConfigFromEnv returns Ollama configuration from environment variables
func GetOllamaConfigFromEnv() (url, model string) {
	url = os.Getenv("OLLAMA_HOST")
	if url == "" {
		url = os.Getenv("OLLAMA_URL")
	}
	model = os.Getenv("OLLAMA_MODEL")
	return
}

// AIEndpointResult represents AI-discovered endpoints
type AIEndpointResult struct {
	Endpoints   []AIEndpoint `json:"endpoints"`
	Provider    string       `json:"provider"`
	Duration    time.Duration `json:"duration"`
	JSAnalyzed  int          `json:"js_analyzed"`
}

// AIEndpoint represents a single AI-discovered endpoint
type AIEndpoint struct {
	Path        string   `json:"path"`
	Method      string   `json:"method,omitempty"`
	Description string   `json:"description,omitempty"`
	Parameters  []string `json:"parameters,omitempty"`
	AuthRequired bool    `json:"auth_required,omitempty"`
	Confidence  string   `json:"confidence"` // high, medium, low
	Source      string   `json:"source"`     // JS file where found
}

// AnalyzeJSForEndpoints uses AI to discover hidden endpoints in JavaScript code
func (s *Scanner) AnalyzeJSForEndpoints(jsContents map[string]string) (*AIEndpointResult, error) {
	start := time.Now()
	result := &AIEndpointResult{
		Endpoints:  []AIEndpoint{},
		JSAnalyzed: len(jsContents),
	}

	if len(jsContents) == 0 {
		return result, nil
	}

	// Check if AI providers are available
	if len(s.provider.GetAvailableProviders()) == 0 {
		return result, fmt.Errorf("no AI providers configured")
	}

	fmt.Println("        [AI Endpoint Discovery] Analyzing JavaScript for hidden endpoints...")

	// Build JavaScript samples for analysis (limit to avoid token limits)
	var jsSamples []struct {
		file    string
		content string
	}

	maxFiles := 10
	maxContentPerFile := 15000 // ~3-4k tokens per file

	for file, content := range jsContents {
		if len(jsSamples) >= maxFiles {
			break
		}
		// Skip minified files that are too large
		if len(content) > 100000 {
			continue
		}
		// Truncate if needed
		if len(content) > maxContentPerFile {
			content = content[:maxContentPerFile] + "\n// ... truncated ..."
		}
		jsSamples = append(jsSamples, struct {
			file    string
			content string
		}{file, content})
	}

	if len(jsSamples) == 0 {
		return result, nil
	}

	// Analyze each JS file
	var allEndpoints []AIEndpoint
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process in batches of 3 concurrent
	sem := make(chan struct{}, 3)

	for _, sample := range jsSamples {
		wg.Add(1)
		go func(file, content string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			endpoints, provider, err := s.analyzeJSContent(file, content)
			if err != nil {
				return
			}

			mu.Lock()
			if result.Provider == "" {
				result.Provider = string(provider)
			}
			allEndpoints = append(allEndpoints, endpoints...)
			mu.Unlock()
		}(sample.file, sample.content)
	}

	wg.Wait()

	// Deduplicate endpoints
	seen := make(map[string]bool)
	for _, ep := range allEndpoints {
		key := ep.Path + ep.Method
		if !seen[key] {
			seen[key] = true
			result.Endpoints = append(result.Endpoints, ep)
		}
	}

	result.Duration = time.Since(start)

	fmt.Printf("        [AI Endpoint Discovery] Found %d unique endpoints from %d JS files\n",
		len(result.Endpoints), len(jsSamples))

	return result, nil
}

// analyzeJSContent sends a single JS file to AI for endpoint analysis
func (s *Scanner) analyzeJSContent(file, content string) ([]AIEndpoint, ProviderType, error) {
	prompt := s.buildEndpointPrompt(file, content)

	// Use provider manager for key rotation and failover
	rec, provider, err := s.queryForEndpoints(prompt)
	if err != nil {
		return nil, provider, err
	}

	// Tag each endpoint with source file
	for i := range rec {
		rec[i].Source = file
	}

	return rec, provider, nil
}

// buildEndpointPrompt creates a prompt for AI endpoint discovery
func (s *Scanner) buildEndpointPrompt(file, content string) string {
	return fmt.Sprintf(`<agent_core>
  <context>You are an expert JavaScript analyst specializing in discovering hidden API endpoints in web applications.</context>
  <objective>Analyze the JavaScript code and extract ALL API endpoints, including obfuscated or dynamically constructed ones.</objective>
</agent_core>

<javascript_file>%s</javascript_file>

<javascript_content>
%s
</javascript_content>

<analysis_instructions>
  1. Find explicit endpoints: /api/*, URLs in fetch/axios/ajax calls
  2. Find dynamically constructed endpoints: string concatenation, template literals
  3. Find hidden/admin endpoints: paths with auth, admin, internal, debug
  4. Identify GraphQL endpoints and operations
  5. Look for WebSocket endpoints (ws://, wss://)
  6. Find undocumented API versions: /v2/, /v3/, /internal/
  7. Extract query parameters and body parameters if visible
  8. Identify authentication requirements from code context
</analysis_instructions>

<output_format>
Output ONLY valid JSON array. Do NOT include any explanation or markdown:
[
  {
    "path": "/api/v1/users",
    "method": "GET",
    "description": "Fetches user list",
    "parameters": ["page", "limit"],
    "auth_required": true,
    "confidence": "high"
  }
]

Confidence levels:
- high: Clearly defined endpoint in code
- medium: Inferred from patterns or partial code
- low: Possible endpoint based on naming conventions

If no endpoints found, return empty array: []
</output_format>`, file, content)
}

// queryForEndpoints queries AI providers for endpoint analysis using the ProviderManager
func (s *Scanner) queryForEndpoints(prompt string) ([]AIEndpoint, ProviderType, error) {
	// Use ProviderManager's QueryRaw which handles key rotation and failover
	responseContent, provider, err := s.provider.QueryRaw(prompt)
	if err != nil {
		return nil, "", err
	}

	endpoints, err := parseEndpointResponse(responseContent)
	if err != nil {
		return nil, provider, err
	}

	return endpoints, provider, nil
}

// parseEndpointResponse parses AI response into endpoints
func parseEndpointResponse(content string) ([]AIEndpoint, error) {
	content = strings.TrimSpace(content)

	// Remove markdown code blocks if present
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
	}
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// Find JSON array
	startIdx := strings.Index(content, "[")
	endIdx := strings.LastIndex(content, "]")
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return []AIEndpoint{}, nil // Empty result if no valid array
	}
	content = content[startIdx : endIdx+1]

	var endpoints []AIEndpoint
	if err := json.Unmarshal([]byte(content), &endpoints); err != nil {
		return nil, err
	}

	return endpoints, nil
}
