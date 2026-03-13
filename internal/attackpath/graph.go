package attackpath

import (
	"github.com/rootsploit/reconator/internal/vulnscan"
)

// Node represents a vulnerability in the attack graph
type Node struct {
	ID             string                 `json:"id"`
	Vuln           vulnscan.Vulnerability `json:"vulnerability"`
	Category       string                 `json:"category"`       // MITRE-aligned category
	MitreIDs       []string               `json:"mitre_ids"`      // Associated MITRE ATT&CK IDs
	Preconditions  []string               `json:"preconditions"`  // What must be true for this to be exploitable
	Postconditions []string               `json:"postconditions"` // What becomes true after exploitation
}

// Edge represents a connection between vulnerabilities in the attack graph
type Edge struct {
	From      string  `json:"from"`       // Source node ID
	To        string  `json:"to"`         // Target node ID
	PatternID string  `json:"pattern_id"` // Which pattern rule created this edge
	Weight    float64 `json:"weight"`     // Edge weight (0.0-1.0, higher = more likely)
	Label     string  `json:"label"`      // Human-readable edge description
}

// AttackGraph represents the full attack graph
type AttackGraph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []*Edge          `json:"edges"`
}

// NewAttackGraph creates an empty attack graph
func NewAttackGraph() *AttackGraph {
	return &AttackGraph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}
}

// AddNode adds a node to the graph
func (g *AttackGraph) AddNode(node *Node) {
	g.Nodes[node.ID] = node
}

// AddEdge adds an edge to the graph
func (g *AttackGraph) AddEdge(edge *Edge) {
	g.Edges = append(g.Edges, edge)
}

// GetNeighbors returns all nodes reachable from the given node
func (g *AttackGraph) GetNeighbors(nodeID string) []*Node {
	var neighbors []*Node
	for _, edge := range g.Edges {
		if edge.From == nodeID {
			if node, ok := g.Nodes[edge.To]; ok {
				neighbors = append(neighbors, node)
			}
		}
	}
	return neighbors
}

// ScoredPath represents a complete attack path with scoring
type ScoredPath struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Nodes       []Node   `json:"nodes"`
	Edges       []Edge   `json:"edges"`
	Score       float64  `json:"score"`       // Composite score (0-10)
	Impact      string   `json:"impact"`      // critical/high/medium/low
	Category    string   `json:"category"`    // Primary MITRE category
	MitreIDs    []string `json:"mitre_ids"`   // All MITRE IDs in the path
	Mitigations []string `json:"mitigations"` // Recommended mitigations
	Likelihood  string   `json:"likelihood"`  // high/medium/low
}
