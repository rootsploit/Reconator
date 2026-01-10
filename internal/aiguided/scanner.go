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
	TargetSummary        string          `json:"target_summary"`
	CVEsFromTech         []CVEInfo       `json:"cves_from_tech,omitempty"`
	RecommendedTags      []string        `json:"recommended_tags"`
	RecommendedTemplates []string        `json:"recommended_templates"`
	AIProvider           string          `json:"ai_provider"`
	Vulnerabilities      []Vulnerability `json:"vulnerabilities"`
	Duration             time.Duration   `json:"duration"`
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
	Domain       string   `json:"domain"`
	Technologies []string `json:"technologies"`
	Endpoints    []string `json:"endpoints"`
	JSFiles      []string `json:"js_files"`
	APIEndpoints []string `json:"api_endpoints"`
	Services     []string `json:"services"`
	WAFDetected  bool     `json:"waf_detected"`
	CDNHosts     int      `json:"cdn_hosts"`
}

type Scanner struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
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

	// Phase 1: CVEMap lookup for detected technologies (PRIMARY - real CVE data)
	var cveIDs []string
	if s.c.IsInstalled("cvemap") && len(ctx.Technologies) > 0 {
		fmt.Println("        [CVEMap] Looking up CVEs for detected technologies...")
		cves := s.lookupCVEsForTech(ctx.Technologies)
		mu.Lock()
		result.CVEsFromTech = cves
		for _, cve := range cves {
			cveIDs = append(cveIDs, cve.CVEID)
		}
		mu.Unlock()
		fmt.Printf("        [CVEMap] Found %d relevant CVEs\n", len(cves))

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
	hasAIKeys := s.cfg.OpenAIKey != "" || s.cfg.ClaudeKey != "" || s.cfg.GeminiKey != ""
	if hasAIKeys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("        [AI] Getting misconfiguration recommendations...")
			rec, provider, err := s.getAIRecommendations(ctx)
			if err != nil {
				fmt.Printf("        [AI] Failed: %v, using defaults\n", err)
				rec = s.getDefaultRecommendations(ctx)
				provider = "fallback"
			}
			mu.Lock()
			result.TargetSummary = rec.Summary
			result.RecommendedTags = rec.Tags
			result.RecommendedTemplates = append(result.RecommendedTemplates, rec.Templates...)
			result.AIProvider = provider
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

	// Add CVE IDs from cvemap to recommended templates
	result.RecommendedTemplates = append(result.RecommendedTemplates, cveIDs...)

	// Phase 3: Run nuclei with combined recommendations
	if s.c.IsInstalled("nuclei") && (len(cveIDs) > 0 || len(result.RecommendedTags) > 0) {
		fmt.Println("        [Nuclei] Running with smart template selection...")
		vulns := s.runNuclei(hosts, cveIDs, result.RecommendedTags)
		result.Vulnerabilities = vulns
		fmt.Printf("        [Nuclei] Found %d vulnerabilities\n", len(vulns))
	}

	result.Duration = time.Since(start)
	return result, nil
}

// lookupCVEsForTech uses vulnx/cvemap to find CVEs for technologies
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

// queryCVEMap runs cvemap for a specific product
func (s *Scanner) queryCVEMap(product string) []CVEInfo {
	var cves []CVEInfo

	// Query: product AND severity critical/high
	query := fmt.Sprintf("product:%s && severity:critical,high", product)

	args := []string{
		"search", query,
		"--json",
		"--limit", "25",
		"--sort-desc", "cvss_score",
	}

	r := exec.Run("cvemap", args, &exec.Options{Timeout: 2 * time.Minute})
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

// normalizeTechName converts technology names to cvemap search terms
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

func (s *Scanner) getAIRecommendations(ctx *TargetContext) (*AIRecommendation, string, error) {
	prompt := s.buildPrompt(ctx)

	if key := s.cfg.OpenAIKey; key != "" {
		rec, err := s.queryOpenAI(prompt, key)
		if err == nil {
			return rec, "openai", nil
		}
	}

	if key := s.cfg.ClaudeKey; key != "" {
		rec, err := s.queryClaude(prompt, key)
		if err == nil {
			return rec, "claude", nil
		}
	}

	if key := s.cfg.GeminiKey; key != "" {
		rec, err := s.queryGemini(prompt, key)
		if err == nil {
			return rec, "gemini", nil
		}
	}

	return nil, "", fmt.Errorf("no AI provider available")
}

func (s *Scanner) buildPrompt(ctx *TargetContext) string {
	return fmt.Sprintf(`You are a security expert. Recommend nuclei TAGS for misconfiguration scanning.
Note: CVE scanning is handled separately via cvemap. Focus ONLY on misconfigurations.

Target:
- Domain: %s
- Technologies: %v
- Endpoints: %d, JS files: %d, API endpoints: %d
- WAF: %v

Recommend tags for: misconfigurations, default credentials, information disclosure, security headers.

Respond with JSON only:
{"summary": "brief analysis", "tags": ["misconfig", "exposure", "default-login"], "templates": [], "reasoning": "brief"}`,
		ctx.Domain,
		ctx.Technologies,
		len(ctx.Endpoints),
		len(ctx.JSFiles),
		len(ctx.APIEndpoints),
		ctx.WAFDetected,
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

func parseAIResponse(content string) (*AIRecommendation, error) {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
	}
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

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
		"-severity", "medium,high,critical",
		"-silent", "-json",
	}

	// Add CVE IDs from cvemap (high priority - real CVEs)
	if len(cveIDs) > 0 {
		limit := 40
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

	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}

	if s.cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.cfg.RateLimit))
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: 45 * time.Minute})
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
