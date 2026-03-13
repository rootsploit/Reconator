package aiguided

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"
)

// GenerateAdaptiveWordlist creates technology-specific directory paths for bruteforcing.
// Uses AI when available, falls back to a comprehensive static mapping.
func GenerateAdaptiveWordlist(ctx context.Context, technologies []string) []string {
	if len(technologies) == 0 {
		return nil
	}

	// Try AI-based generation
	pm := NewProviderManager()
	pm.LoadFromEnv()
	configPath := GetDefaultConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		pm.LoadFromFile(configPath)
	}

	if len(pm.GetAvailableProviders()) > 0 {
		words := aiWordlistGen(ctx, pm, technologies)
		if len(words) > 0 {
			return words
		}
	}

	// Rule-based fallback
	return ruleBasedWordlist(technologies)
}

// aiWordlistGen uses AI to generate tech-specific directory paths
func aiWordlistGen(ctx context.Context, pm *ProviderManager, technologies []string) []string {
	// Simple compact prompt using TOON
	prompt := "Tech: " + strings.Join(technologies, ", ") + "\n\nGenerate 15 paths to check (admin, config, debug). JSON array only."

	timeoutCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
		return parseWordlistResponse(result)
	case <-errCh:
		return nil
	case <-timeoutCtx.Done():
		return nil
	}
}

// parseWordlistResponse extracts paths from AI response
func parseWordlistResponse(response string) []string {
	// Try to find JSON array
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
		return nil
	}

	var paths []string
	if err := json.Unmarshal([]byte(jsonStr), &paths); err != nil {
		return nil
	}

	// Sanitize and deduplicate
	seen := make(map[string]bool)
	var result []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		// Ensure paths start with /
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		seen[p] = true
		result = append(result, p)
	}
	return result
}

// ruleBasedWordlist generates wordlist entries from a static tech-to-path mapping
func ruleBasedWordlist(technologies []string) []string {
	techWordlistMap := map[string][]string{
		"wordpress":     {"/wp-admin/", "/wp-content/uploads/", "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-login.php", "/wp-config.php.bak", "/wp-includes/"},
		"drupal":        {"/admin/", "/sites/default/files/", "/CHANGELOG.txt", "/core/install.php", "/user/login", "/node/1"},
		"joomla":        {"/administrator/", "/configuration.php", "/api/index.php", "/language/en-GB/", "/plugins/"},
		"django":        {"/admin/", "/__debug__/", "/api/schema/", "/static/", "/media/", "/api/v1/", "/api/v2/"},
		"flask":         {"/admin/", "/api/", "/static/", "/debug/", "/console/"},
		"spring":        {"/actuator/", "/actuator/env", "/actuator/health", "/actuator/info", "/actuator/beans", "/swagger-ui/", "/swagger-ui/index.html", "/v2/api-docs", "/v3/api-docs", "/h2-console/", "/jolokia/"},
		"laravel":       {"/.env", "/telescope/", "/horizon/", "/storage/logs/", "/vendor/", "/artisan", "/_debugbar/open"},
		"express":       {"/.env", "/api/", "/api/docs", "/api/swagger", "/graphql", "/debug/", "/status"},
		"rails":         {"/rails/info/routes", "/rails/info/properties", "/admin/", "/sidekiq/", "/api/"},
		"asp.net":       {"/web.config", "/elmah.axd", "/trace.axd", "/admin/", "/api/"},
		"php":           {"/info.php", "/phpinfo.php", "/phpmyadmin/", "/adminer.php", "/server-status", "/.env"},
		"nginx":         {"/nginx_status", "/.well-known/", "/server-status"},
		"apache":        {"/.htaccess", "/server-status", "/server-info", "/.well-known/"},
		"tomcat":        {"/manager/html", "/host-manager/html", "/manager/status", "/WEB-INF/web.xml"},
		"iis":           {"/web.config", "/_vti_bin/", "/aspnet_client/"},
		"node":          {"/.env", "/api/", "/graphql", "/socket.io/", "/package.json"},
		"react":         {"/static/js/", "/manifest.json", "/asset-manifest.json", "/service-worker.js"},
		"angular":       {"/assets/", "/ngsw.json", "/api/"},
		"vue":           {"/static/", "/api/", "/manifest.json"},
		"grafana":       {"/api/dashboards", "/api/org", "/api/users", "/api/datasources"},
		"jenkins":       {"/script", "/api/json", "/manage", "/configuration-as-code/"},
		"gitlab":        {"/api/v4/", "/users/sign_in", "/-/graphql-explorer"},
		"elasticsearch": {"/_cat/indices", "/_cluster/health", "/_nodes"},
		"kibana":        {"/api/status", "/app/kibana"},
		"redis":         {"/info"},
		"mongodb":       {"/serverStatus"},
		"docker":        {"/v2/", "/v2/_catalog"},
		"kubernetes":    {"/api/", "/api/v1/", "/healthz", "/metrics"},
	}

	seen := make(map[string]bool)
	var result []string

	for _, tech := range technologies {
		techLower := strings.ToLower(tech)
		for key, paths := range techWordlistMap {
			if strings.Contains(techLower, key) {
				for _, p := range paths {
					if !seen[p] {
						seen[p] = true
						result = append(result, p)
					}
				}
			}
		}
	}

	// Always add common paths
	commonPaths := []string{"/.env", "/robots.txt", "/sitemap.xml", "/.git/config", "/.well-known/security.txt", "/api/", "/admin/", "/backup/", "/config/", "/.DS_Store"}
	for _, p := range commonPaths {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}

	return result
}
