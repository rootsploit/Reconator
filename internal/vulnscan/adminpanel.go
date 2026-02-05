package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
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
	Panels    []AdminPanel   `json:"panels"`
	ByHost    map[string]int `json:"by_host"`
	Total     int            `json:"total"`
	Duration  time.Duration  `json:"duration"`
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

// ScanAdminPanels discovers admin panels on given hosts
func (s *AdminPanelScanner) ScanAdminPanels(ctx context.Context, hosts []string) (*AdminPanelResult, error) {
	start := time.Now()
	result := &AdminPanelResult{
		Panels: []AdminPanel{},
		ByHost: make(map[string]int),
	}

	totalChecks := len(hosts) * len(s.paths)
	fmt.Printf("    [*] Scanning %d hosts for admin panels (%d paths)...\n", len(hosts), len(s.paths))

	// Use reasonable concurrency for admin panel scanning (default 20 if Threads is 0)
	threads := s.cfg.Threads
	if threads == 0 {
		threads = 20
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	checked := 0
	for _, host := range hosts {
		for _, path := range s.paths {
			wg.Add(1)
			go func(h, p string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				url := normalizeURL(h) + p
				panel := s.checkAdminPanel(ctx, url)
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
			}(host, path)
		}
	}

	wg.Wait()
	result.Total = len(result.Panels)
	result.Duration = time.Since(start)

	fmt.Printf("    [*] Found %d admin panels\n", result.Total)
	return result, nil
}

func normalizeURL(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimSuffix(host, "/")
	}
	return "https://" + strings.TrimSuffix(host, "/")
}

func (s *AdminPanelScanner) checkAdminPanel(ctx context.Context, url string) *AdminPanel {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
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
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := strings.ToLower(string(buf[:n]))

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

	return panel
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
