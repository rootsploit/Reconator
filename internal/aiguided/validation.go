package aiguided

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// VulnForValidation represents a vulnerability to be validated by AI
type VulnForValidation struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
	Severity   string `json:"severity"`
	URL        string `json:"url,omitempty"`
	Type       string `json:"type,omitempty"`
	Tool       string `json:"tool,omitempty"`
}

// ValidateVulnerabilities uses AI to validate discovered vulnerabilities
// Batches vulns in groups of 5 to stay within token budget
// Returns validated vulns with confidence scores and adjusted risk levels
func ValidateVulnerabilities(ctx context.Context, vulns []VulnForValidation, assetGraph string) []ValidatedVuln {
	if len(vulns) == 0 {
		return nil
	}

	pm := NewProviderManager()
	pm.LoadFromEnv()
	configPath := GetDefaultConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		pm.LoadFromFile(configPath)
	}

	if len(pm.GetAvailableProviders()) == 0 {
		return ruleBasedValidation(vulns)
	}

	var allValidated []ValidatedVuln

	// Process in batches of 5
	batchSize := 5
	for i := 0; i < len(vulns); i += batchSize {
		end := i + batchSize
		if end > len(vulns) {
			end = len(vulns)
		}
		batch := vulns[i:end]

		validated := validateBatch(ctx, pm, batch, assetGraph)
		allValidated = append(allValidated, validated...)
	}

	return allValidated
}

// validateBatch validates a batch of vulnerabilities using AI
func validateBatch(ctx context.Context, pm *ProviderManager, vulns []VulnForValidation, assetGraph string) []ValidatedVuln {
	prompt := buildValidationPrompt(vulns, assetGraph)

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		result, _, err := pm.QueryRaw(prompt)
		if err != nil {
			errCh <- err
		} else {
			resultCh <- result
		}
	}()

	select {
	case result := <-resultCh:
		return parseValidationResponse(result, vulns)
	case <-errCh:
		return ruleBasedValidation(vulns)
	case <-timeoutCtx.Done():
		return ruleBasedValidation(vulns)
	}
}

// buildValidationPrompt creates the prompt for vulnerability validation
func buildValidationPrompt(vulns []VulnForValidation, assetGraph string) string {
	var sb strings.Builder
	sb.WriteString("You are a security expert. Validate these vulnerability findings and assess if they are real or false positives.\n\n")

	if assetGraph != "" {
		sb.WriteString("[target_context]\n")
		sb.WriteString(assetGraph)
		sb.WriteString("\n\n")
	}

	sb.WriteString("[vulnerabilities]\n")
	for i, v := range vulns {
		sb.WriteString(fmt.Sprintf("%d. %s | %s | %s | %s | tool=%s\n",
			i+1, v.Host, v.Name, v.Severity, v.TemplateID, v.Tool))
		if v.URL != "" {
			sb.WriteString(fmt.Sprintf("   url=%s\n", v.URL))
		}
	}

	sb.WriteString("\n[respond_json]\n")
	sb.WriteString(`[{"vuln_index": 0, "is_real": true, "confidence": 0.85, "adjusted_risk": "high", "reasoning": "..."}]`)
	sb.WriteString("\nReturn ONLY a JSON array. confidence is 0.0-1.0. adjusted_risk: critical/high/medium/low/info/false-positive")

	return sb.String()
}

// parseValidationResponse parses AI validation response
func parseValidationResponse(response string, vulns []VulnForValidation) []ValidatedVuln {
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		// Try raw array
		start := strings.Index(response, "[")
		end := strings.LastIndex(response, "]")
		if start >= 0 && end > start {
			jsonStr = response[start : end+1]
		}
	}
	if jsonStr == "" {
		return ruleBasedValidation(vulns)
	}

	var parsed []struct {
		VulnIndex    int     `json:"vuln_index"`
		IsReal       bool    `json:"is_real"`
		Confidence   float64 `json:"confidence"`
		AdjustedRisk string  `json:"adjusted_risk"`
		Reasoning    string  `json:"reasoning"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return ruleBasedValidation(vulns)
	}

	var validated []ValidatedVuln
	for _, p := range parsed {
		if p.VulnIndex < 0 || p.VulnIndex >= len(vulns) {
			continue
		}
		v := vulns[p.VulnIndex]
		validated = append(validated, ValidatedVuln{
			Host:         v.Host,
			VulnName:     v.Name,
			TemplateID:   v.TemplateID,
			OrigSeverity: v.Severity,
			IsReal:       p.IsReal,
			Confidence:   p.Confidence,
			AdjustedRisk: p.AdjustedRisk,
			Reasoning:    p.Reasoning,
		})
	}

	// Fill in vulns that weren't in the AI response
	validatedSet := make(map[int]bool)
	for _, p := range parsed {
		validatedSet[p.VulnIndex] = true
	}
	for i, v := range vulns {
		if !validatedSet[i] {
			validated = append(validated, ValidatedVuln{
				Host:         v.Host,
				VulnName:     v.Name,
				TemplateID:   v.TemplateID,
				OrigSeverity: v.Severity,
				IsReal:       true,
				Confidence:   0.5,
				AdjustedRisk: v.Severity,
				Reasoning:    "not validated by AI",
			})
		}
	}

	return validated
}

// ruleBasedValidation applies heuristic false positive detection
func ruleBasedValidation(vulns []VulnForValidation) []ValidatedVuln {
	var validated []ValidatedVuln

	for _, v := range vulns {
		vv := ValidatedVuln{
			Host:         v.Host,
			VulnName:     v.Name,
			TemplateID:   v.TemplateID,
			OrigSeverity: v.Severity,
			IsReal:       true,
			Confidence:   0.7,
			AdjustedRisk: v.Severity,
			Reasoning:    "rule-based validation",
		}

		nameLower := strings.ToLower(v.Name)
		templateLower := strings.ToLower(v.TemplateID)

		// Known false positive patterns
		if strings.Contains(templateLower, "tech-detect") || strings.Contains(templateLower, "waf-detect") {
			vv.IsReal = true
			vv.Confidence = 0.95
			vv.AdjustedRisk = "info"
			vv.Reasoning = "technology detection - informational"
		} else if strings.Contains(nameLower, "security header") || strings.Contains(nameLower, "missing header") {
			vv.IsReal = true
			vv.Confidence = 0.9
			if v.Severity == "high" || v.Severity == "critical" {
				vv.AdjustedRisk = "medium"
				vv.Reasoning = "missing security headers - severity adjusted down"
			}
		} else if strings.Contains(templateLower, "cve-") {
			vv.IsReal = true
			vv.Confidence = 0.8
			vv.Reasoning = "CVE-based detection - likely real"
		} else if v.Tool == "quicktest" || v.Tool == "sxss" {
			vv.Confidence = 0.5
			vv.Reasoning = "reflection-based detection - needs manual verification"
		}

		validated = append(validated, vv)
	}

	return validated
}
