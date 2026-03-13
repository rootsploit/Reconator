package attackpath

import (
	"sort"
	"strings"

	"github.com/rootsploit/reconator/internal/vulnscan"
)

// CombinationLockConfig contains configuration for the Combination Lock algorithm
type CombinationLockConfig struct {
	// CategoryOrder defines the ordered list of attack categories (phases)
	CategoryOrder []string

	// EnableSemanticPruning uses LLM to validate edge feasibility
	EnableSemanticPruning bool

	// EnableStructuralPruning uses graph constraints to prune edges
	EnableStructuralPruning bool

	// MaxPathLength limits the maximum number of nodes in a path
	MaxPathLength int

	// MinPathLength requires minimum nodes for a valid path
	MinPathLength int

	// CategoryScoreWeights defines weights for each category
	CategoryScoreWeights map[string]float64
}

// DefaultCombinationLockConfig returns sensible defaults
func DefaultCombinationLockConfig() *CombinationLockConfig {
	return &CombinationLockConfig{
		CategoryOrder: []string{
			"initial_access",
			"credential_access",
			"privilege_escalation",
			"lateral_movement",
			"persistence",
			"impact",
		},
		EnableSemanticPruning:    false, // Enable when LLM is available
		EnableStructuralPruning: true,
		MaxPathLength:           7,
		MinPathLength:           2,
		CategoryScoreWeights: map[string]float64{
			"initial_access":      1.0,
			"credential_access":   0.9,
			"privilege_escalation": 0.8,
			"lateral_movement":    0.7,
			"persistence":        0.6,
			"impact":             1.0,
		},
	}
}

// CombinationLockPruner implements the Combination Lock algorithm from the paper
type CombinationLockPruner struct {
	cfg *CombinationLockConfig
}

// NewCombinationLockPruner creates a new pruner with the given config
func NewCombinationLockPruner(cfg *CombinationLockConfig) *CombinationLockPruner {
	if cfg == nil {
		cfg = DefaultCombinationLockConfig()
	}
	return &CombinationLockPruner{cfg: cfg}
}

// PruneEdges applies the Combination Lock algorithm to prune invalid edge combinations
// This implements the 3-level pruning from the paper:
// Level 1: Category ordering constraints
// Level 2: Graph structural constraints
// Level 3: Semantic feasibility (optional, requires LLM)
func (p *CombinationLockPruner) PruneEdges(vulns []vulnscan.Vulnerability, categoryMap map[string]string) []Edge {
	// Phase 1: Build category buckets
	buckets := p.buildCategoryBuckets(vulns, categoryMap)

	// Phase 2: Build constrained edge set with 3-level pruning
	edges := p.buildConstrainedEdges(vulns, buckets, categoryMap)

	return edges
}

// buildCategoryBuckets groups vulnerabilities by category
func (p *CombinationLockPruner) buildCategoryBuckets(vulns []vulnscan.Vulnerability, categoryMap map[string]string) map[string][]int {
	buckets := make(map[string][]int)
	for idx, v := range vulns {
		cat := categoryMap[v.Host]
		if cat == "" {
			cat = CategorizeVulnerability(v)
		}
		buckets[cat] = append(buckets[cat], idx)
	}
	return buckets
}

// buildConstrainedEdges builds edges with 3-level pruning
func (p *CombinationLockPruner) buildConstrainedEdges(vulns []vulnscan.Vulnerability, buckets map[string][]int, categoryMap map[string]string) []Edge {
	var edges []Edge

	// Get category order indices for validation
	catOrder := make(map[string]int)
	for i, cat := range p.cfg.CategoryOrder {
		catOrder[cat] = i
	}

	// Iterate through category pairs (only valid forward transitions)
	for i := 0; i < len(p.cfg.CategoryOrder)-1; i++ {
		srcCat := p.cfg.CategoryOrder[i]

		// Level 1: Category ordering constraint
		// Only consider transitions from srcCat to later categories
		for j := i + 1; j < len(p.cfg.CategoryOrder); j++ {
			dstCat := p.cfg.CategoryOrder[j]

			srcIndices := buckets[srcCat]
			dstIndices := buckets[dstCat]

			if len(srcIndices) == 0 || len(dstIndices) == 0 {
				continue
			}

			// Level 2: Structural constraints (same host or network reachable)
			for _, srcIdx := range srcIndices {
				for _, dstIdx := range dstIndices {
					srcVuln := vulns[srcIdx]
					dstVuln := vulns[dstIdx]

					// Check structural constraint: same host or related
					if !p.checkStructuralConstraint(srcVuln, dstVuln) {
						continue
					}

					// Level 3: Semantic feasibility (if enabled)
					if p.cfg.EnableSemanticPruning {
						srcPost := GetPostconditions(srcVuln, categoryMap[srcVuln.Host])
						dstPre := GetPreconditions(dstVuln, categoryMap[dstVuln.Host])
						result := MatchPostconditionToPrecondition(srcVuln, dstVuln, srcPost, dstPre)
						if !result.CanChain {
							continue
						}
						edges = append(edges, Edge{
							From:      srcVuln.Host,
							To:        dstVuln.Host,
							PatternID: "semantic",
							Weight:    result.Confidence,
							Label:     result.Reason,
						})
					} else {
						// Use pattern-based matching
						srcPost := GetPostconditions(srcVuln, categoryMap[srcVuln.Host])
						dstPre := GetPreconditions(dstVuln, categoryMap[dstVuln.Host])
						result := patternMatchPostconditionToPrecondition(srcPost, dstPre)
						if result.CanChain {
							edges = append(edges, Edge{
								From:      srcVuln.Host,
								To:        dstVuln.Host,
								PatternID: "pattern",
								Weight:    result.Confidence,
								Label:     result.Reason,
							})
						}
					}
				}
			}
		}
	}

	return edges
}

// checkStructuralConstraint checks if two vulnerabilities can be chained based on infrastructure
func (p *CombinationLockPruner) checkStructuralConstraint(src, dst vulnscan.Vulnerability) bool {
	// Same host - always valid
	if src.Host == dst.Host {
		return true
	}

	// Level 2 constraint: For cross-host chains, we need network connectivity
	// In a real implementation, this would check the host connectivity graph
	// For now, we allow same-domain chaining
	if extractDomain(src.Host) == extractDomain(dst.Host) {
		return true
	}

	// Allow some common cloud patterns
	srcDomain := extractDomain(src.Host)
	dstDomain := extractDomain(dst.Host)

	// AWS/GCP/Azure internal patterns
	cloudSuffixes := []string{"compute.internal", "internal", "googleusercontent.com", "cloudfront.net"}
	for _, suffix := range cloudSuffixes {
		if strings.HasSuffix(srcDomain, suffix) || strings.HasSuffix(dstDomain, suffix) {
			return true
		}
	}

	return false
}

// extractDomain extracts the base domain from a hostname
func extractDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// ScorePathWithCombinationLock scores a path using the Combination Lock algorithm
// Uses category weights and path structure for scoring
func (p *CombinationLockPruner) ScorePathWithCombinationLock(nodes []Node) float64 {
	if len(nodes) < p.cfg.MinPathLength {
		return 0.0
	}

	var score float64
	var weightSum float64

	for i, node := range nodes {
		// Get category weight
		catWeight := p.cfg.CategoryScoreWeights[node.Category]
		if catWeight == 0 {
			catWeight = 0.5
		}

		// Earlier nodes in the chain contribute more to likelihood
		positionWeight := 1.0 - (float64(i) / float64(len(nodes)))

		// Severity contribution
		severityWeight := getSeverityWeight(node.Vuln.Severity)

		score += catWeight * positionWeight * severityWeight
		weightSum += catWeight
	}

	if weightSum == 0 {
		return 0.0
	}

	// Normalize and apply chain length bonus
	normalizedScore := score / weightSum

	// Bonus for longer chains (more realistic attack scenarios)
	lengthBonus := float64(len(nodes)) / float64(p.cfg.MaxPathLength)
	if lengthBonus > 1.0 {
		lengthBonus = 1.0
	}

	// Final score: normalized * (1 + length_bonus * 0.2)
	finalScore := normalizedScore * (1.0 + lengthBonus*0.2)

	// Scale to 0-10
	return finalScore * 10
}

// getSeverityWeight returns numeric weight for severity
func getSeverityWeight(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 1.0
	case "high":
		return 0.8
	case "medium":
		return 0.5
	case "low":
		return 0.2
	default:
		return 0.1
	}
}

// FindOptimalPaths uses Combination Lock to find the best attack paths
// Returns paths sorted by score (highest first)
func (p *CombinationLockPruner) FindOptimalPaths(vulns []vulnscan.Vulnerability) []ScoredPath {
	if len(vulns) == 0 {
		return nil
	}

	// Build category map
	categoryMap := make(map[string]string)
	for _, v := range vulns {
		if categoryMap[v.Host] == "" {
			categoryMap[v.Host] = CategorizeVulnerability(v)
		}
	}

	// Prune edges using Combination Lock
	edges := p.PruneEdges(vulns, categoryMap)

	// Build adjacency list
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	// Find entry points (nodes with no incoming edges from our vulns)
	hasIncoming := make(map[string]bool)
	for _, e := range edges {
		hasIncoming[e.To] = true
	}

	var entries []string
	for _, v := range vulns {
		if !hasIncoming[v.Host] {
			entries = append(entries, v.Host)
		}
	}
	if len(entries) == 0 {
		entries = []string{vulns[0].Host}
	}

	// DFS to find all paths
	var allPaths [][]string
	visited := make(map[string]bool)

	var dfs func(current string, path []string)
	dfs = func(current string, path []string) {
		if len(path) >= p.cfg.MaxPathLength {
			return
		}

		path = append(path, current)
		allPaths = append(allPaths, path)

		for _, next := range adj[current] {
			if !visited[next] || len(path) < 3 { // Allow some cycles for persistence
				dfs(next, path)
			}
		}
	}

	for _, entry := range entries {
		dfs(entry, nil)
	}

	// Score and sort paths
	var scoredPaths []ScoredPath
	for _, path := range allPaths {
		if len(path) < p.cfg.MinPathLength {
			continue
		}

		// Build nodes for scoring
		var nodes []Node
		for _, host := range path {
			for _, v := range vulns {
				if v.Host == host {
					nodes = append(nodes, Node{
						ID:         host,
						Vuln:       v,
						Category:   categoryMap[host],
						MitreIDs:   Categories[categoryMap[host]].MitreIDs,
						Preconditions: GetPreconditions(v, categoryMap[host]),
						Postconditions: GetPostconditions(v, categoryMap[host]),
					})
					break
				}
			}
		}

		score := p.ScorePathWithCombinationLock(nodes)
		if score > 0 {
			scoredPaths = append(scoredPaths, ScoredPath{
				ID:          generatePathID(path),
				Name:        generatePathName(path),
				Description: generatePathDescription(path),
				Nodes:       nodes,
				Score:       score,
				Impact:      determinePathImpact(nodes),
				Category:    nodes[0].Category,
			})
		}
	}

	// Sort by score descending
	sort.Slice(scoredPaths, func(i, j int) bool {
		return scoredPaths[i].Score > scoredPaths[j].Score
	})

	return scoredPaths[:min(len(scoredPaths), 50)] // Return top 50 paths
}

func generatePathID(path []string) string {
	return "path-" + strings.Join(path, "-")
}

func generatePathName(path []string) string {
	if len(path) == 0 {
		return "Unknown Path"
	}
	return path[0] + " → " + path[len(path)-1]
}

func generatePathDescription(path []string) string {
	if len(path) < 2 {
		return "Single host path"
	}
	return "Attack chain through " + strings.Join(path, " → ")
}

func determinePathImpact(nodes []Node) string {
	maxSeverity := 0
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	for _, n := range nodes {
		if s, ok := severityOrder[n.Vuln.Severity]; ok && s > maxSeverity {
			maxSeverity = s
		}
	}

	for s, i := range severityOrder {
		if i == maxSeverity {
			return s
		}
	}
	return "medium"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
