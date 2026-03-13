package vulnscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
)

// AdminPanel represents a discovered admin panel
type AdminPanel struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	HasLogin   bool   `json:"has_login"`
	AuthType   string `json:"auth_type,omitempty"` // form, basic, none
}

// AdminPanelResult contains all discovered admin panels
type AdminPanelResult struct {
	Panels   []AdminPanel   `json:"panels"`
	ByHost   map[string]int `json:"by_host"`
	Total    int            `json:"total"`
	Duration time.Duration  `json:"duration"`
}

// AdminPanelScanner discovers admin panels across hosts
type AdminPanelScanner struct {
	cfg    *config.Config
	client *http.Client
	paths  []string
	ports  []int
}

// NewAdminPanelScanner creates a new admin panel scanner
func NewAdminPanelScanner(cfg *config.Config) *AdminPanelScanner {
	return &AdminPanelScanner{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		paths:  adminPaths,
		ports:  adminPorts,
	}
}

// 80+ admin panel paths
var adminPaths = []string{
	"/admin", "/admin/", "/administrator", "/administrator/",
	"/admin/login", "/admin/index", "/admin/admin", "/admin/home",
	"/adminpanel", "/admin-panel", "/admin_panel", "/admincp",
	"/admin.php", "/admin.html", "/admin.asp", "/admin.aspx",
	"/login", "/login/", "/login.php", "/login.html", "/signin",
	"/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-login",
	"/manager", "/manager/", "/manager/html", "/manage",
	"/cpanel", "/cpanel/", "/controlpanel", "/control",
	"/dashboard", "/dashboard/", "/dash", "/panel",
	"/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin",
	"/adminer", "/adminer.php", "/dbadmin", "/db",
	"/backend", "/backend/", "/backoffice", "/back",
	"/console", "/console/", "/system", "/system/admin",
	"/cms", "/cms/admin", "/cms/login", "/content",
	"/config", "/config/", "/configuration", "/settings",
	"/maintenance", "/setup", "/install", "/installer",
	"/user", "/user/login", "/users", "/users/login",
	"/account", "/account/login", "/accounts", "/auth",
	"/secure", "/secure/", "/secured", "/security",
	"/portal", "/portal/", "/member", "/members",
	"/customer", "/customer/login", "/client", "/clients",
	"/staff", "/staff/login", "/employee", "/internal",
	"/intranet", "/private", "/restricted", "/secret",
	"/api/admin", "/api/v1/admin", "/api/console",
	"/webadmin", "/siteadmin", "/site-admin", "/admin-site",
	"/modcp", "/moderator", "/mod", "/supervisor",
	"/root", "/superuser", "/super", "/master",
}

// 15 common admin ports
var adminPorts = []int{
	80, 443, 8080, 8443, 8000, 8888,
	3000, 4000, 5000, 9000, 9090,
	2082, 2083, 2086, 2087, // cPanel
}

// hostBaseline stores the baseline (canary) response for a host to detect catch-all/SPA responses
type hostBaseline struct {
	bodyHash   string
	statusCode int
	bodyLen    int
}

// ScanAdminPanels discovers admin panels on given hosts
func (s *AdminPanelScanner) ScanAdminPanels(ctx context.Context, hosts []string) (*AdminPanelResult, error) {
	start := time.Now()
	result := &AdminPanelResult{
		Panels: []AdminPanel{},
		ByHost: make(map[string]int),
	}

	fmt.Printf("    [*] Scanning %d hosts for admin panels (%d paths)...\n", len(hosts), len(s.paths))

	// Phase 1: Collect baseline (canary) responses for each host
	// This detects SPAs and catch-all reverse proxies that return 200 for any path
	baselines := s.collectBaselines(ctx, hosts)
	baselineCount := 0
	for _, b := range baselines {
		if b != nil {
			baselineCount++
		}
	}
	if baselineCount > 0 {
		fmt.Printf("    [*] Collected %d/%d host baselines for soft-404 detection\n", baselineCount, len(hosts))
	}

	// Use reasonable concurrency for admin panel scanning (default 20 if Threads is 0)
	threads := s.cfg.Threads
	if threads == 0 {
		threads = 20
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	totalChecks := len(hosts) * len(s.paths)
	checked := 0
	for _, host := range hosts {
		baseline := baselines[normalizeURL(host)]
		for _, path := range s.paths {
			wg.Add(1)
			go func(h, p string, bl *hostBaseline) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				url := normalizeURL(h) + p
				panel := s.checkAdminPanel(ctx, url, bl)
				if panel != nil {
					mu.Lock()
					result.Panels = append(result.Panels, *panel)
					result.ByHost[h]++
					mu.Unlock()
				}

				mu.Lock()
				checked++
				if checked%500 == 0 {
					fmt.Printf("        Progress: %d/%d checked, %d found\n", checked, totalChecks, len(result.Panels))
				}
				mu.Unlock()
			}(host, path, baseline)
		}
	}

	wg.Wait()
	result.Total = len(result.Panels)
	result.Duration = time.Since(start)

	fmt.Printf("    [*] Found %d admin panels\n", result.Total)
	return result, nil
}

// collectBaselines requests a random non-existent path on each host to get the default response.
// Any admin path response matching this baseline is a catch-all/SPA soft-404.
func (s *AdminPanelScanner) collectBaselines(ctx context.Context, hosts []string) map[string]*hostBaseline {
	baselines := make(map[string]*hostBaseline)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Generate 2 random canary paths to compare
	canary1 := fmt.Sprintf("/reconator_canary_%s_%d", randomString(8), rand.Intn(99999))
	canary2 := fmt.Sprintf("/zz_nonexist_%s_%d", randomString(8), rand.Intn(99999))

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			base := normalizeURL(h)

			// Fetch two canary responses
			hash1, status1, len1 := s.fetchBodyHash(ctx, base+canary1)
			hash2, status2, len2 := s.fetchBodyHash(ctx, base+canary2)

			// Both canaries must return the same status and similar body to confirm catch-all behavior
			if hash1 != "" && hash2 != "" && hash1 == hash2 && status1 == status2 {
				mu.Lock()
				baselines[base] = &hostBaseline{
					bodyHash:   hash1,
					statusCode: status1,
					bodyLen:    len1,
				}
				mu.Unlock()
			} else if hash1 != "" && hash2 != "" && status1 == status2 && abs(len1-len2) < 200 {
				// Bodies differ slightly (e.g., CSRF tokens, nonces) but same status and similar length
				// Use length-based comparison as fallback
				mu.Lock()
				baselines[base] = &hostBaseline{
					bodyHash:   "", // empty hash = use length-based comparison
					statusCode: status1,
					bodyLen:    (len1 + len2) / 2,
				}
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return baselines
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func randomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// fetchBodyHash fetches a URL and returns the SHA256 hash of the body, status code, and body length
func (s *AdminPanelScanner) fetchBodyHash(ctx context.Context, url string) (string, int, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if err != nil {
		return "", resp.StatusCode, 0
	}

	// Normalize body: lowercase, strip whitespace variations for more stable comparison
	normalized := strings.ToLower(string(body))
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:]), resp.StatusCode, len(body)
}

func normalizeURL(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimSuffix(host, "/")
	}
	return "https://" + strings.TrimSuffix(host, "/")
}

func (s *AdminPanelScanner) checkAdminPanel(ctx context.Context, url string, baseline *hostBaseline) *AdminPanel {
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

	// Only interested in 200, 401, 403 (access denied but exists)
	if resp.StatusCode != 200 && resp.StatusCode != 401 && resp.StatusCode != 403 {
		return nil
	}

	// Read limited body for analysis
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	body := strings.ToLower(string(rawBody))

	// Baseline comparison: if response matches the host's catch-all/SPA response, it's a soft-404
	if resp.StatusCode == 200 && baseline != nil && baseline.statusCode == 200 {
		if baseline.bodyHash != "" {
			// Exact hash comparison
			h := sha256.Sum256([]byte(body))
			if hex.EncodeToString(h[:]) == baseline.bodyHash {
				return nil
			}
		} else if baseline.bodyLen > 0 {
			// Length-based comparison (for SPAs with dynamic tokens)
			if abs(len(rawBody)-baseline.bodyLen) < 200 {
				return nil
			}
		}
	}

	// Soft-404 detection: many reverse proxies (Envoy, Cloudflare) return HTTP 200
	// with "Page not found" / "404" in the body for non-existent paths
	if resp.StatusCode == 200 && isSoft404(body) {
		return nil
	}

	// SPA detection: if the response is an SPA app shell without admin-specific content, skip it
	if resp.StatusCode == 200 && isSPAShell(body) {
		return nil
	}

	panel := &AdminPanel{
		URL:        url,
		StatusCode: resp.StatusCode,
	}

	// Check for login indicators
	panel.HasLogin = strings.Contains(body, "password") ||
		strings.Contains(body, "login") ||
		strings.Contains(body, "sign in") ||
		strings.Contains(body, "username") ||
		resp.StatusCode == 401

	// Determine auth type
	if resp.StatusCode == 401 {
		panel.AuthType = "basic"
	} else if strings.Contains(body, "<form") && panel.HasLogin {
		panel.AuthType = "form"
	} else {
		panel.AuthType = "none"
	}

	// Extract title
	if idx := strings.Index(body, "<title>"); idx >= 0 {
		end := strings.Index(body[idx:], "</title>")
		if end > 7 {
			panel.Title = strings.TrimSpace(body[idx+7 : idx+end])
		}
	}

	// Final validation: for 200 responses without auth, require admin-specific content
	// A generic HTML page without admin keywords is not an admin panel
	if resp.StatusCode == 200 && !panel.HasLogin && panel.AuthType == "none" {
		if !hasAdminContent(body) {
			return nil
		}
	}

	return panel
}

// isSoft404 detects soft-404 responses where the server returns HTTP 200
// but the body indicates the page doesn't exist (common with reverse proxies like Envoy, Cloudflare)
func isSoft404(body string) bool {
	soft404Patterns := []string{
		"page not found",
		"not found",
		"does not exist",
		"no longer available",
		"cannot be found",
		"could not be found",
		"404 -",
		"404:",
		"error 404",
		"404 error",
		"404 page",
		"the request could not be satisfied",
		"request blocked",
		"access denied",
	}

	for _, pattern := range soft404Patterns {
		if strings.Contains(body, pattern) {
			// Don't flag as soft-404 if the page also has login form indicators
			// (a real login page might mention "404" in an error message)
			if strings.Contains(body, "password") &&
				strings.Contains(body, "<form") {
				return false
			}
			return true
		}
	}
	return false
}

// isSPAShell detects SPA (Single Page Application) shells that serve the same HTML for all routes.
// These typically contain a root div and JS bundle references but no server-rendered admin content.
func isSPAShell(body string) bool {
	spaMarkers := 0

	// Check for SPA framework markers
	spaPatterns := []string{
		"<div id=\"root\"",
		"<div id=\"app\"",
		"<div id=\"__next\"",
		"<div id=\"__nuxt\"",
		"window.__initial_state__",
		"window.__nuxt__",
		"window.__next_data__",
		"__react_root__",
		"ng-app",
		"ng-version",
		"data-reactroot",
	}

	for _, p := range spaPatterns {
		if strings.Contains(body, p) {
			spaMarkers++
		}
	}

	// Check for bundled JS (common SPA pattern)
	if strings.Contains(body, ".chunk.js") || strings.Contains(body, "bundle.js") ||
		strings.Contains(body, "/static/js/") || strings.Contains(body, "/_next/") ||
		strings.Contains(body, "/__nuxt/") {
		spaMarkers++
	}

	// If we see SPA markers and the body has very little visible text content, it's likely an app shell
	if spaMarkers >= 1 {
		// SPA shells typically have minimal text between tags
		// Check that there's no actual admin-specific content rendered server-side
		return !hasAdminContent(body)
	}

	return false
}

// hasAdminContent checks if the response body contains actual admin panel content
// (not just a generic page that happens to be served at an admin path)
func hasAdminContent(body string) bool {
	adminKeywords := []string{
		"admin panel",
		"administration",
		"control panel",
		"dashboard",
		"phpmyadmin",
		"wp-admin",
		"cpanel",
		"webmail",
		"file manager",
		"server status",
		"system settings",
		"manage users",
		"admin console",
		"site administration",
	}

	for _, kw := range adminKeywords {
		if strings.Contains(body, kw) {
			return true
		}
	}
	return false
}

// SaveAdminPanelResults saves results to JSON and text files
func (r *AdminPanelResult) SaveAdminPanelResults(dir string) error {
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(dir, "admin_panels.json"), data, 0644)

	f, err := os.Create(filepath.Join(dir, "admin_panels.txt"))
	if err != nil {
		return err
	}
	defer f.Close()
	for _, p := range r.Panels {
		fmt.Fprintf(f, "[%d] %s (auth: %s, login: %v)\n", p.StatusCode, p.URL, p.AuthType, p.HasLogin)
	}
	return nil
}
