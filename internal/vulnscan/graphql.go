package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

// GraphQLEndpoint represents a discovered GraphQL endpoint
type GraphQLEndpoint struct {
	URL               string   `json:"url"`
	Type              string   `json:"type"` // graphql, graphiql, playground, voyager
	IntrospectionEnabled bool  `json:"introspection_enabled"`
	SchemaAvailable   bool     `json:"schema_available"`
	Vulnerabilities   []string `json:"vulnerabilities,omitempty"`
	Types             int      `json:"types_count,omitempty"`
	Queries           int      `json:"queries_count,omitempty"`
	Mutations         int      `json:"mutations_count,omitempty"`
}

// GraphQLResult contains all GraphQL findings
type GraphQLResult struct {
	Endpoints    []GraphQLEndpoint `json:"endpoints"`
	TotalFound   int               `json:"total_found"`
	Introspectable int             `json:"introspectable"`
	Duration     time.Duration     `json:"duration"`
}

// GraphQL endpoint paths to check
var graphqlPaths = []string{
	"/graphql",
	"/graphiql",
	"/playground",
	"/console",
	"/voyager",
	"/v1/graphql",
	"/v2/graphql",
	"/api/graphql",
	"/api/v1/graphql",
	"/query",
	"/gql",
	"/graphql/console",
	"/graphql/playground",
	"/altair",
	"/__graphql",
	"/graphql-explorer",
}

// Introspection query
const introspectionQuery = `{"query":"query{__schema{types{name}}}"}`

// GraphQLScanner detects and tests GraphQL endpoints
type GraphQLScanner struct {
	cfg    *config.Config
	c      *tools.Checker
	client *http.Client
}

// NewGraphQLScanner creates a new GraphQL scanner
func NewGraphQLScanner(cfg *config.Config, checker *tools.Checker) *GraphQLScanner {
	return &GraphQLScanner{
		cfg: cfg,
		c:   checker,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ScanGraphQL discovers and tests GraphQL endpoints
func (s *GraphQLScanner) ScanGraphQL(ctx context.Context, hosts []string) (*GraphQLResult, error) {
	start := time.Now()
	result := &GraphQLResult{
		Endpoints: []GraphQLEndpoint{},
	}

	fmt.Printf("    [*] Scanning %d hosts for GraphQL endpoints...\n", len(hosts))

	// Use reasonable concurrency for GraphQL scanning (default 10 if Threads is 0)
	threads := s.cfg.Threads
	if threads == 0 {
		threads = 10
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, host := range hosts {
		for _, path := range graphqlPaths {
			wg.Add(1)
			go func(h, p string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				url := normalizeGraphQLURL(h) + p
				endpoint := s.testGraphQLEndpoint(ctx, url)
				if endpoint != nil {
					mu.Lock()
					result.Endpoints = append(result.Endpoints, *endpoint)
					if endpoint.IntrospectionEnabled {
						result.Introspectable++
					}
					mu.Unlock()
				}
			}(host, path)
		}
	}

	wg.Wait()
	result.TotalFound = len(result.Endpoints)
	result.Duration = time.Since(start)

	// Run nuclei GraphQL templates if endpoints found
	if result.TotalFound > 0 && s.c.IsInstalled("nuclei") {
		fmt.Printf("    [*] Found %d GraphQL endpoints, running security checks...\n", result.TotalFound)
		s.runNucleiGraphQL(ctx, result)
	}

	fmt.Printf("    [*] GraphQL: %d endpoints found, %d with introspection enabled\n",
		result.TotalFound, result.Introspectable)

	return result, nil
}

func normalizeGraphQLURL(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimSuffix(host, "/")
	}
	return "https://" + strings.TrimSuffix(host, "/")
}

func (s *GraphQLScanner) testGraphQLEndpoint(ctx context.Context, url string) *GraphQLEndpoint {
	// Test with introspection query
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(introspectionQuery))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Also try GET for GraphiQL/Playground detection
	if resp.StatusCode == 405 {
		return s.testGraphQLGET(ctx, url)
	}

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check if it's a GraphQL response
	if !strings.Contains(bodyStr, "data") && !strings.Contains(bodyStr, "__schema") && !strings.Contains(bodyStr, "errors") {
		return nil
	}

	endpoint := &GraphQLEndpoint{
		URL:  url,
		Type: detectGraphQLType(url),
	}

	// Check introspection response
	if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "types") {
		endpoint.IntrospectionEnabled = true
		endpoint.SchemaAvailable = true

		// Parse schema info
		var result struct {
			Data struct {
				Schema struct {
					Types []struct {
						Name string `json:"name"`
					} `json:"types"`
				} `json:"__schema"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &result) == nil {
			endpoint.Types = len(result.Data.Schema.Types)
		}
	} else if strings.Contains(bodyStr, "errors") && strings.Contains(bodyStr, "introspection") {
		// Introspection disabled but endpoint exists
		endpoint.IntrospectionEnabled = false
	}

	return endpoint
}

func (s *GraphQLScanner) testGraphQLGET(ctx context.Context, url string) *GraphQLEndpoint {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	bodyStr := strings.ToLower(string(body))

	// Check for GraphiQL/Playground HTML
	if strings.Contains(bodyStr, "graphiql") ||
		strings.Contains(bodyStr, "graphql playground") ||
		strings.Contains(bodyStr, "graphql-playground") ||
		strings.Contains(bodyStr, "voyager") ||
		strings.Contains(bodyStr, "altair") {

		endpoint := &GraphQLEndpoint{
			URL:  url,
			Type: detectGraphQLType(url),
		}

		if strings.Contains(bodyStr, "graphiql") {
			endpoint.Type = "graphiql"
		} else if strings.Contains(bodyStr, "playground") {
			endpoint.Type = "playground"
		} else if strings.Contains(bodyStr, "voyager") {
			endpoint.Type = "voyager"
		} else if strings.Contains(bodyStr, "altair") {
			endpoint.Type = "altair"
		}

		return endpoint
	}

	return nil
}

func detectGraphQLType(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "graphiql"):
		return "graphiql"
	case strings.Contains(lower, "playground"):
		return "playground"
	case strings.Contains(lower, "voyager"):
		return "voyager"
	case strings.Contains(lower, "altair"):
		return "altair"
	case strings.Contains(lower, "console"):
		return "console"
	default:
		return "graphql"
	}
}

// runNucleiGraphQL runs nuclei with GraphQL-specific templates
func (s *GraphQLScanner) runNucleiGraphQL(ctx context.Context, result *GraphQLResult) {
	// Create temp file with GraphQL endpoints
	var urls []string
	for _, ep := range result.Endpoints {
		urls = append(urls, ep.URL)
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(urls, "\n"), "-graphql.txt")
	if err != nil {
		return
	}
	defer cleanup()

	// Run nuclei with graphql tag
	args := []string{
		"-l", tmp,
		"-tags", "graphql",
		"-severity", "low,medium,high,critical",
		"-silent", "-jsonl",
	}

	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}

	r := exec.Run("nuclei", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return
	}

	// Parse results and add vulnerabilities to endpoints
	vulnsByURL := make(map[string][]string)
	for _, line := range exec.Lines(r.Stdout) {
		if line == "" {
			continue
		}
		var entry struct {
			MatchedAt  string `json:"matched-at"`
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.MatchedAt != "" {
			vuln := fmt.Sprintf("[%s] %s", entry.Info.Severity, entry.Info.Name)
			vulnsByURL[entry.MatchedAt] = append(vulnsByURL[entry.MatchedAt], vuln)
		}
	}

	// Update endpoints with vulnerabilities
	for i := range result.Endpoints {
		if vulns, ok := vulnsByURL[result.Endpoints[i].URL]; ok {
			result.Endpoints[i].Vulnerabilities = vulns
		}
	}
}

// SaveGraphQLResults saves results to JSON and text files
func (r *GraphQLResult) SaveGraphQLResults(dir string) error {
	os.MkdirAll(dir, 0755)

	// Save JSON
	data, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(dir, "graphql.json"), data, 0644)

	// Save endpoints to text
	f, err := os.Create(filepath.Join(dir, "graphql_endpoints.txt"))
	if err != nil {
		return err
	}
	defer f.Close()

	for _, ep := range r.Endpoints {
		status := "introspection-disabled"
		if ep.IntrospectionEnabled {
			status = "INTROSPECTION-ENABLED"
		}
		fmt.Fprintf(f, "[%s] %s (%s)\n", status, ep.URL, ep.Type)
		for _, vuln := range ep.Vulnerabilities {
			fmt.Fprintf(f, "  -> %s\n", vuln)
		}
	}

	return nil
}
