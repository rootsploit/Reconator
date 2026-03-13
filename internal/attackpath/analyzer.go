package attackpath

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"

	"github.com/rootsploit/reconator/internal/vulnscan"
)

// Scoring weights
const (
	WeightImpact         = 0.4
	WeightLikelihood     = 0.35
	WeightExploitability = 0.25
)

// Analyzer builds attack graphs and finds scored paths
type Analyzer struct {
	Rules []PatternRule
}

// NewAnalyzer creates a new analyzer with default rules
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Rules: DefaultRules(),
	}
}

// BuildGraph constructs an attack graph from vulnerabilities
func (a *Analyzer) BuildGraph(vulns []vulnscan.Vulnerability) *AttackGraph {
	graph := NewAttackGraph()

	// Create nodes for each vulnerability
	for i, v := range vulns {
		category := CategorizeVulnerability(v)
		node := &Node{
			ID:             fmt.Sprintf("node-%d", i),
			Vuln:           v,
			Category:       category,
			MitreIDs:       Categories[category].MitreIDs,
			Preconditions:  GetPreconditions(v, category),
			Postconditions: GetPostconditions(v, category),
		}
		graph.AddNode(node)
	}

	// Create edges based on pattern rules
	nodeList := make([]*Node, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodeList = append(nodeList, n)
	}

	for i, src := range nodeList {
		for j, dst := range nodeList {
			if i == j {
				continue
			}

			for _, rule := range a.Rules {
				if rule.Condition != nil && rule.Condition(src.Vuln, dst.Vuln) {
					// Require postconditions of src to satisfy preconditions of dst
					if !a.hasConditionOverlap(src.Postconditions, dst.Preconditions) {
						continue
					}

					// Require host proximity - vulns must be on same host scope
					if !isSameHostScope(src.Vuln, dst.Vuln) {
						continue
					}

					edge := &Edge{
						From:      src.ID,
						To:        dst.ID,
						PatternID: rule.ID,
						Weight:    rule.Weight,
						Label:     rule.Name,
					}
					graph.AddEdge(edge)
				}
			}
		}
	}

	return graph
}

// hasConditionOverlap checks if any postconditions match any preconditions
// Enhanced to handle semantic relationships between vulnerabilities
func (a *Analyzer) hasConditionOverlap(postconditions, preconditions []string) bool {
	// Build semantic mapping for related concepts
	semanticGroups := map[string][]string{
		"session":    {"cookie", "token", "auth", "jwt", "session", "login", "sso"},
		"auth":       {"login", "credential", "password", "token", "jwt", "oauth", "sso", "session"},
		"credential": {"password", "secret", "key", "token", "auth", "login", "credential"},
		"admin":      {"admin", "panel", "management", "console", "dashboard", "cms"},
		"database":   {"sql", "database", "db", "mysql", "postgres", "oracle", "mongodb"},
		"rce":        {"command", "exec", "shell", "rce", "code-exec", "php-eval"},
		"xss":        {"xss", "cross-site", "script", "cookie", "session"},
		"sqli":       {"sql", "injection", "database", "blind", "union"},
		"lfi":        {"lfi", "file-inclusion", "path-traversal", "directory"},
		"api":        {"api", "rest", "graphql", "endpoint", "swagger"},
		"cloud":      {"aws", "azure", "gcp", "s3", "bucket", "iam", "metadata"},
	}

	for _, post := range postconditions {
		postLower := strings.ToLower(post)
		// Check direct match
		for _, pre := range preconditions {
			preLower := strings.ToLower(pre)
			if post == pre || strings.Contains(post, pre) || strings.Contains(pre, post) {
				return true
			}
			// Check semantic groups
			for _, groupTerms := range semanticGroups {
				inPost := false
				inPre := false
				for _, term := range groupTerms {
					if strings.Contains(postLower, term) {
						inPost = true
					}
					if strings.Contains(preLower, term) {
						inPre = true
					}
				}
				if inPost && inPre {
					return true
				}
			}
		}
	}
	return false
}

// isSameHostScope checks if two vulnerabilities are in the same host scope.
// Returns true if: same host, same base domain, same parent domain, or infrastructure-level finding.
func isSameHostScope(src, dst vulnscan.Vulnerability) bool {
	srcHost := extractHost(src.Host)
	dstHost := extractHost(dst.Host)

	// Empty hosts - allow chaining
	if srcHost == "" || dstHost == "" {
		return true
	}

	// Same host
	if srcHost == dstHost {
		return true
	}

	// Same base domain (e.g., testphp.vulnweb.com and rest.vulnweb.com)
	if getBaseDomain(srcHost) == getBaseDomain(dstHost) && getBaseDomain(srcHost) != "" {
		return true
	}

	// Same parent domain (e.g., api.example.com and admin.example.com) - relaxed check
	if getParentDomain(srcHost) == getParentDomain(dstHost) && getParentDomain(srcHost) != "" {
		return true
	}

	// Infrastructure-level findings are org-wide (cloud buckets, DNS, subdomain takeover)
	srcCombined := strings.ToLower(src.Name + " " + src.TemplateID + " " + src.Type)
	dstCombined := strings.ToLower(dst.Name + " " + dst.TemplateID + " " + dst.Type)
	infraPatterns := []string{"bucket", "s3", "gcs", "azure blob", "dns", "zone transfer", "takeover", "cloud", "storage", "blob"}
	for _, p := range infraPatterns {
		if strings.Contains(srcCombined, p) || strings.Contains(dstCombined, p) {
			return true
		}
	}

	// Cross-site scripting can chain from any XSS on same parent domain
	if strings.Contains(srcCombined, "xss") || strings.Contains(srcCombined, "cross-site") {
		if getParentDomain(srcHost) == getParentDomain(dstHost) {
			return true
		}
	}

	// Auth-related vulns can chain across parent domain
	authPatterns := []string{"auth", "login", "session", "token", "jwt", "oauth", "sso", "credential"}
	for _, p := range authPatterns {
		if strings.Contains(srcCombined, p) || strings.Contains(dstCombined, p) {
			if getParentDomain(srcHost) == getParentDomain(dstHost) {
				return true
			}
		}
	}

	return false
}

// extractHost gets the hostname from a URL or host string
func extractHost(hostOrURL string) string {
	if hostOrURL == "" {
		return ""
	}
	// Try parsing as URL first
	if strings.Contains(hostOrURL, "://") {
		if u, err := url.Parse(hostOrURL); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// Strip port if present
	host := strings.ToLower(hostOrURL)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

// getBaseDomain extracts the base domain (last two parts) from a hostname
func getBaseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// getParentDomain extracts the parent domain (last three parts for subdomains) from a hostname
// e.g., api.rest.vulnweb.com -> rest.vulnweb.com
func getParentDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return getBaseDomain(host)
}

// isExploitableEntryPoint checks if a vulnerability represents an actual exploitable
// entry point, not just a version detection or outdated software finding
func isExploitableEntryPoint(node *Node) bool {
	combined := strings.ToLower(node.Vuln.Name + " " + node.Vuln.TemplateID + " " + node.Vuln.Type)

	// Skip generic outdated software / version detection findings
	skipPatterns := []string{"outdated", "eol", "end of life", "end-of-life", "version detected", "version disclosure"}
	for _, p := range skipPatterns {
		if strings.Contains(combined, p) {
			return false
		}
	}

	// For initial_access, require actual exploit types
	if node.Category == "initial_access" {
		exploitPatterns := []string{"xss", "sqli", "sql injection", "ssrf", "lfi", "rce",
			"command injection", "code execution", "deserialization", "upload",
			"template injection", "xxe", "path traversal", "rfi", "cross-site"}
		for _, p := range exploitPatterns {
			if strings.Contains(combined, p) {
				return true
			}
		}
		// If it's initial_access but doesn't match any exploit pattern, skip
		return false
	}

	// credential_access entries are fine
	return true
}

// FindPaths finds all attack paths in the graph and returns them scored
func (a *Analyzer) FindPaths(graph *AttackGraph) []ScoredPath {
	var allPaths []ScoredPath

	// Find entry point nodes - only exploitable initial_access or credential_access
	entryNodes := make([]*Node, 0)
	for _, node := range graph.Nodes {
		if (node.Category == "initial_access" || node.Category == "credential_access") && isExploitableEntryPoint(node) {
			entryNodes = append(entryNodes, node)
		}
	}

	// DFS from each entry point to find paths
	pathID := 1
	for _, entry := range entryNodes {
		visited := make(map[string]bool)
		currentPath := []string{entry.ID}
		visited[entry.ID] = true

		a.dfs(graph, entry.ID, visited, currentPath, &allPaths, &pathID, 5) // Max depth 5
	}

	// Also create single-node paths for standalone critical/high vulns not in any path
	for _, node := range graph.Nodes {
		if (node.Vuln.Severity == "critical" || node.Vuln.Severity == "high") && isExploitableEntryPoint(node) && !a.nodeInAnyPath(node.ID, allPaths) {
			path := a.buildScoredPath(graph, []string{node.ID}, pathID)
			if path.Score > 0 {
				allPaths = append(allPaths, path)
				pathID++
			}
		}
	}

	// Deduplicate and sort by score
	allPaths = a.deduplicatePaths(allPaths)
	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].Score > allPaths[j].Score
	})

	// Cap at 20 paths
	if len(allPaths) > 20 {
		allPaths = allPaths[:20]
	}

	return allPaths
}

func (a *Analyzer) nodeInAnyPath(nodeID string, paths []ScoredPath) bool {
	for _, p := range paths {
		for _, n := range p.Nodes {
			if n.ID == nodeID {
				return true
			}
		}
	}
	return false
}

func (a *Analyzer) dfs(graph *AttackGraph, currentID string, visited map[string]bool, path []string, allPaths *[]ScoredPath, pathID *int, maxDepth int) {
	if len(path) > maxDepth {
		return
	}

	// If path has at least 2 nodes, it's a valid path
	if len(path) >= 2 {
		scored := a.buildScoredPath(graph, path, *pathID)
		*allPaths = append(*allPaths, scored)
		*pathID++
	}

	// Continue DFS - prevent same-category consecutive steps
	currentNode := graph.Nodes[currentID]
	for _, edge := range graph.Edges {
		if edge.From == currentID && !visited[edge.To] {
			nextNode := graph.Nodes[edge.To]

			// Prevent same MITRE category appearing consecutively
			// (e.g., data_exfiltration -> data_exfiltration is parallel findings, not a chain)
			if currentNode != nil && nextNode != nil && currentNode.Category == nextNode.Category {
				continue
			}

			visited[edge.To] = true
			path = append(path, edge.To)

			a.dfs(graph, edge.To, visited, path, allPaths, pathID, maxDepth)

			path = path[:len(path)-1]
			visited[edge.To] = false
		}
	}
}

func (a *Analyzer) buildScoredPath(graph *AttackGraph, nodeIDs []string, pathID int) ScoredPath {
	var nodes []Node
	var edges []Edge
	var mitreIDs []string
	var mitigations []string
	mitreSet := make(map[string]bool)
	mitigationSet := make(map[string]bool)

	for _, id := range nodeIDs {
		if node, ok := graph.Nodes[id]; ok {
			nodes = append(nodes, *node)
			for _, m := range node.MitreIDs {
				if !mitreSet[m] {
					mitreIDs = append(mitreIDs, m)
					mitreSet[m] = true
				}
			}
		}
	}

	// Collect edges along the path
	for i := 0; i < len(nodeIDs)-1; i++ {
		for _, edge := range graph.Edges {
			if edge.From == nodeIDs[i] && edge.To == nodeIDs[i+1] {
				edges = append(edges, *edge)
				// Get mitigations from the rule
				for _, rule := range a.Rules {
					if rule.ID == edge.PatternID {
						for _, m := range rule.Mitigations {
							if !mitigationSet[m] {
								mitigations = append(mitigations, m)
								mitigationSet[m] = true
							}
						}
					}
				}
				break
			}
		}
	}

	score := a.ScorePath(nodes, edges)
	impact := scoreToImpact(score)
	likelihood := scoreToLikelihood(score)

	// Build descriptive name from the attack narrative
	name := ""
	if len(edges) > 0 {
		// Use the last edge label (attack outcome) + entry vuln
		name = fmt.Sprintf("%s via %s", edges[len(edges)-1].Label, nodes[0].Vuln.Name)
	} else if len(nodes) == 1 {
		name = nodes[0].Vuln.Name
	} else {
		name = fmt.Sprintf("%s leading to %s", nodes[0].Vuln.Name, nodes[len(nodes)-1].Vuln.Name)
	}
	if len(name) > 120 {
		name = name[:117] + "..."
	}

	// Primary category is the entry node's category
	category := ""
	if len(nodes) > 0 {
		category = nodes[0].Category
	}

	description := fmt.Sprintf("Attack chain with %d steps starting from %s", len(nodes), category)
	if len(nodes) >= 2 {
		description = fmt.Sprintf("%s leading to %s", nodes[0].Vuln.Name, nodes[len(nodes)-1].Vuln.Name)
	}

	return ScoredPath{
		ID:          fmt.Sprintf("path-%d", pathID),
		Name:        name,
		Description: description,
		Nodes:       nodes,
		Edges:       edges,
		Score:       score,
		Impact:      impact,
		Category:    category,
		MitreIDs:    mitreIDs,
		Mitigations: mitigations,
		Likelihood:  likelihood,
	}
}

// ScorePath calculates the composite score for a path
// Score(p) = w_impact * Impact + w_likelihood * Likelihood + w_exploitability * Exploitability
func (a *Analyzer) ScorePath(nodes []Node, edges []Edge) float64 {
	if len(nodes) == 0 {
		return 0
	}

	// Impact: based on highest severity in the chain
	impactScore := 0.0
	for _, n := range nodes {
		switch strings.ToLower(n.Vuln.Severity) {
		case "critical":
			impactScore = math.Max(impactScore, 10.0)
		case "high":
			impactScore = math.Max(impactScore, 7.5)
		case "medium":
			impactScore = math.Max(impactScore, 5.0)
		case "low":
			impactScore = math.Max(impactScore, 2.5)
		}
	}

	// Likelihood: based on edge weights (average)
	likelihoodScore := 5.0 // Default for single-node paths
	if len(edges) > 0 {
		totalWeight := 0.0
		for _, e := range edges {
			totalWeight += e.Weight
		}
		likelihoodScore = (totalWeight / float64(len(edges))) * 10.0
	}

	// Exploitability: based on CVSS and vuln characteristics
	exploitabilityScore := 0.0
	for _, n := range nodes {
		if n.Vuln.CVSS > 0 {
			exploitabilityScore = math.Max(exploitabilityScore, n.Vuln.CVSS)
		} else {
			// Estimate from severity
			switch strings.ToLower(n.Vuln.Severity) {
			case "critical":
				exploitabilityScore = math.Max(exploitabilityScore, 9.0)
			case "high":
				exploitabilityScore = math.Max(exploitabilityScore, 7.0)
			case "medium":
				exploitabilityScore = math.Max(exploitabilityScore, 5.0)
			case "low":
				exploitabilityScore = math.Max(exploitabilityScore, 3.0)
			}
		}
	}

	// Chain length bonus (longer chains that work are more impactful)
	chainBonus := math.Min(float64(len(nodes)-1)*0.5, 2.0)

	score := WeightImpact*impactScore + WeightLikelihood*likelihoodScore + WeightExploitability*exploitabilityScore + chainBonus

	// Cap at 10
	if score > 10.0 {
		score = 10.0
	}

	return math.Round(score*100) / 100 // 2 decimal places
}

func scoreToImpact(score float64) string {
	switch {
	case score >= 8.0:
		return "critical"
	case score >= 6.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func scoreToLikelihood(score float64) string {
	switch {
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// deduplicatePaths removes paths that have identical node sets
func (a *Analyzer) deduplicatePaths(paths []ScoredPath) []ScoredPath {
	seen := make(map[string]bool)
	var unique []ScoredPath

	for _, p := range paths {
		// Create a key from sorted node IDs
		var ids []string
		for _, n := range p.Nodes {
			ids = append(ids, n.ID)
		}
		sort.Strings(ids)
		key := strings.Join(ids, ",")

		if !seen[key] {
			seen[key] = true
			unique = append(unique, p)
		}
	}

	return unique
}

// Analyze is the main entry point - builds graph and finds paths from vulnerabilities
func (a *Analyzer) Analyze(vulns []vulnscan.Vulnerability) ([]ScoredPath, *AttackGraph) {
	graph := a.BuildGraph(vulns)
	paths := a.FindPaths(graph)
	return paths, graph
}
