package attackpath

import (
	"fmt"
	"strings"

	"github.com/rootsploit/reconator/internal/vulnscan"
)

// SemanticMatcher uses pattern matching to validate attack chain feasibility
// Based on the paper's approach: "CanChain(A, B) = PatternMatch(A, B) OR SemanticMatch(A.postcondition, B.precondition) > threshold"
// LLM-based semantic matching can be added by registering an LLM client

// SemanticMatchResult contains the result of semantic matching
type SemanticMatchResult struct {
	CanChain     bool    `json:"can_chain"`
	Confidence  float64 `json:"confidence"` // 0.0-1.0
	Reason      string  `json:"reason"`
	PatternUsed bool    `json:"pattern_used"`
}

// MatchPostconditionToPrecondition checks if src's postconditions satisfy dst's preconditions
// Uses pattern matching for deterministic results
func MatchPostconditionToPrecondition(srcVuln, dstVuln vulnscan.Vulnerability, srcPostconditions, dstPreconditions []string) SemanticMatchResult {
	// Use pattern matching (deterministic, no LLM needed)
	return patternMatchPostconditionToPrecondition(srcPostconditions, dstPreconditions)
}

// patternMatchPostconditionToPrecondition checks for direct keyword matches
func patternMatchPostconditionToPrecondition(srcPostconditions, dstPreconditions []string) SemanticMatchResult {
	// Build keyword mapping from postcondition -> possible preconditions it satisfies
	postToPre := map[string][]string{
		"code_execution":              {"network_access", "target_reachable"},
		"server_access":               {"network_access"},
		"write_access":                {"network_access"},
		"internal_network_access":     {"network_access"},
		"metadata_access":             {"network_access"},
		"data_access":                 {"network_access"},
		"read_permission":             {"network_access"},
		"database_access":             {"network_access"},
		"session_theft":               {"network_access"},
		"client_code_execution":        {"network_access"},
		"credential_obtained":         {"network_access"},
		"authenticated_access":        {"network_access", "service_exposed"},
		"privileged_access":           {"authenticated_access", "low_privilege_user"},
		"admin_access":                {"authenticated_access"},
		"expanded_access":             {"initial_foothold"},
		"new_target_access":           {"network_access"},
		"data_obtained":               {"data_access"},
		"sensitive_data_leaked":       {"read_permission"},
		"persistent_access":           {"code_execution"},
		"backdoor_installed":          {"code_execution", "write_access"},
		"target_compromised":          {"privileged_access"},
		"initial_foothold":            {"network_access"},
	}

	matchCount := 0
	var matched []string

	for _, srcPost := range srcPostconditions {
		for _, dstPre := range dstPreconditions {
			// Direct match
			if strings.EqualFold(srcPost, dstPre) {
				matchCount++
				matched = append(matched, fmt.Sprintf("%s→%s", srcPost, dstPre))
				continue
			}

			// Keyword-based mapping
			if mappings, ok := postToPre[srcPost]; ok {
				for _, m := range mappings {
					if strings.EqualFold(m, dstPre) {
						matchCount++
						matched = append(matched, fmt.Sprintf("%s→%s", srcPost, dstPre))
					}
				}
			}
		}
	}

	if matchCount > 0 {
		confidence := float64(matchCount) / float64(len(dstPreconditions))
		if confidence > 1.0 {
			confidence = 1.0
		}
		return SemanticMatchResult{
			CanChain:    true,
			Confidence:  confidence,
			Reason:      fmt.Sprintf("Pattern match: %s", strings.Join(matched, ", ")),
			PatternUsed: true,
		}
	}

	return SemanticMatchResult{
		CanChain:    false,
		Confidence: 0.0,
		Reason:     "No pattern match found",
		PatternUsed: true,
	}
}

// ValidateChain validates an attack chain for feasibility
// Returns true if the chain is valid based on pattern matching
func ValidateChain(chain []vulnscan.Vulnerability) (bool, string) {
	if len(chain) < 2 {
		return true, "Chain too short to validate"
	}

	for i := 0; i < len(chain)-1; i++ {
		srcVuln := chain[i]
		dstVuln := chain[i+1]

		srcCat := CategorizeVulnerability(srcVuln)
		dstCat := CategorizeVulnerability(dstVuln)

		srcPost := GetPostconditions(srcVuln, srcCat)
		dstPre := GetPreconditions(dstVuln, dstCat)

		result := MatchPostconditionToPrecondition(srcVuln, dstVuln, srcPost, dstPre)

		if !result.CanChain {
			return false, fmt.Sprintf("Chain breaks at %s → %s: %s", srcVuln.Name, dstVuln.Name, result.Reason)
		}
	}

	return true, "Chain is valid"
}
