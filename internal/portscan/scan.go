package portscan

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Result struct {
	TotalScanned int                  `json:"total_scanned"`
	TotalPorts   int                  `json:"total_ports"`
	AliveHosts   []string             `json:"alive_hosts"`        // URLs (http://host:port) - may have multiple per host
	AliveCount   int                  `json:"alive_count"`        // Unique host count (for accurate stats)
	OpenPorts    map[string][]int     `json:"open_ports"`
	Services     map[string][]Service `json:"services"`
	TLSInfo      map[string]TLSData   `json:"tls_info,omitempty"`
	Duration     time.Duration        `json:"duration"`
	// CDN filtering (BB-10): Non-CDN hosts have 3x more vulnerabilities
	CDNHosts    []string `json:"cdn_hosts,omitempty"`     // Hosts behind CDN/WAF
	NonCDNHosts []string `json:"non_cdn_hosts,omitempty"` // Direct hosts (priority targets)
}

type Service struct {
	Port       int    `json:"port"`
	Title      string `json:"title,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Tech       string `json:"tech,omitempty"`
	IP         string `json:"ip,omitempty"`
	ASN        string `json:"asn,omitempty"`
	WebServer  string `json:"web_server,omitempty"`
	JARM       string `json:"jarm,omitempty"`       // JARM TLS fingerprint
	Favicon    string `json:"favicon,omitempty"`    // Favicon hash
	CDN        bool   `json:"cdn,omitempty"`        // Is behind CDN/WAF
	CDNName    string `json:"cdn_name,omitempty"`   // CDN provider name
}

type TLSData struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Version   string   `json:"version,omitempty"`
	Cipher    string   `json:"cipher,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	SANs      []string `json:"sans,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	DaysLeft  int      `json:"days_left,omitempty"`
}

type Scanner struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewScanner(cfg *config.Config, checker *tools.Checker) *Scanner {
	return &Scanner{cfg: cfg, c: checker}
}

func (s *Scanner) Scan(hosts []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		TotalScanned: len(hosts),
		OpenPorts:    make(map[string][]int),
		Services:     make(map[string][]Service),
		AliveHosts:   []string{},
		TLSInfo:      make(map[string]TLSData),
	}

	if len(hosts) == 0 {
		return result, nil
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Step 1: Run naabu to discover open ports
	var httpxURLs []string // URLs for httpx (http://host:port or https://host:port)
	if s.c.IsInstalled("naabu") {
		fmt.Println("        Running naabu...")
		ports, urls := s.naabu(tmp)
		for h, p := range ports {
			result.OpenPorts[h] = p
			result.TotalPorts += len(p)
		}
		httpxURLs = urls
		fmt.Printf("        naabu: %d open ports\n", result.TotalPorts)
	}

	// Step 2: Run httpx and tlsx in parallel
	// httpx uses naabu output (URLs) if available, otherwise falls back to hostnames
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Httpx - use naabu output for better accuracy
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !s.c.IsInstalled("httpx") {
			fmt.Println("        httpx: SKIPPED (not installed)")
			return
		}
		fmt.Printf("        Running httpx (input: %d host:port entries)...\n", len(httpxURLs))

		var httpxInput string
		var httpxCleanup func()
		var httpxErr error

		if len(httpxURLs) > 0 {
			// Use naabu output (host:port format)
			httpxInput, httpxCleanup, httpxErr = exec.TempFile(strings.Join(httpxURLs, "\n"), ".txt")
		} else {
			// Fallback to original hosts
			httpxInput = tmp
		}

		if httpxErr != nil {
			fmt.Printf("        httpx temp file error: %v\n", httpxErr)
			return
		}
		if httpxCleanup != nil {
			defer httpxCleanup()
		}

		httpxRes := s.httpx(httpxInput)
		mu.Lock()
		result.AliveHosts = httpxRes.Alive
		result.AliveCount = httpxRes.AliveCount
		result.CDNHosts = httpxRes.CDNHosts
		result.NonCDNHosts = httpxRes.NonCDN
		for h, svc := range httpxRes.Services {
			result.Services[h] = svc
		}
		mu.Unlock()
		fmt.Printf("        httpx: %d unique hosts alive (%d URLs, %d non-CDN, %d CDN)\n",
			httpxRes.AliveCount, len(httpxRes.Alive), len(httpxRes.NonCDN), len(httpxRes.CDNHosts))
	}()

	// TLSx
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !s.c.IsInstalled("tlsx") {
			return
		}
		fmt.Println("        Running tlsx...")
		tls := s.tlsx(tmp)
		mu.Lock()
		for h, t := range tls {
			result.TLSInfo[h] = t
		}
		mu.Unlock()
		fmt.Printf("        tlsx: %d TLS hosts\n", len(tls))
	}()

	wg.Wait()
	result.Duration = time.Since(start)
	return result, nil
}

func (s *Scanner) naabu(input string) (map[string][]int, []string) {
	ports := make(map[string][]int)
	var hostPorts []string // host:port format - httpx auto-detects protocol
	args := []string{"-l", input, "-p", "80,443,8080,8443,8000,3000,5000,9000,9443,4443", "-c", fmt.Sprintf("%d", s.cfg.Threads), "-silent", "-json"}
	if s.cfg.RateLimit > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", s.cfg.RateLimit))
	}
	r := exec.Run("naabu", args, &exec.Options{Timeout: 15 * time.Minute})
	if r.Error != nil {
		return ports, hostPorts
	}
	for _, line := range exec.Lines(r.Stdout) {
		var e struct {
			Host string `json:"host"`
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		h := e.Host
		if h == "" {
			h = e.IP
		}
		if h != "" && e.Port > 0 {
			ports[h] = append(ports[h], e.Port)
			hostPorts = append(hostPorts, fmt.Sprintf("%s:%d", h, e.Port))
		}
	}
	return ports, hostPorts
}

// httpxResult holds parsed httpx output with CDN classification
type httpxResult struct {
	Alive      []string             // URLs (http://host:port)
	AliveCount int                  // Unique host count
	Services   map[string][]Service
	CDNHosts   []string // Hosts behind CDN (lower vuln priority)
	NonCDN     []string // Direct hosts (3x more vulns - priority targets)
}

func (s *Scanner) httpx(input string) httpxResult {
	result := httpxResult{
		Services: make(map[string][]Service),
	}

	// Core httpx flags - keep it simple for reliability
	// Heavy flags like -jarm, -tls-grab, -favicon can cause timeouts on CDN-protected hosts
	args := []string{
		"-l", input,
		"-silent", "-follow-redirects",
		"-status-code", "-title", "-tech-detect",
		"-ip", "-asn", "-web-server",
		"-cdn", // CDN detection (lightweight)
		"-json",
		"-timeout", "10", // 10 second timeout per host
		"-retries", "2",  // Retry failed requests
	}
	// Use fewer threads for httpx to avoid rate limiting
	threads := s.cfg.Threads
	if threads > 25 {
		threads = 25 // Cap at 25 to avoid CDN rate limiting
	}
	if threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", threads))
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		fmt.Printf("        httpx error: %v\n", r.Error)
		if r.Stderr != "" {
			stderr := r.Stderr
			if len(stderr) > 200 {
				stderr = stderr[:200]
			}
			fmt.Printf("        httpx stderr: %s\n", stderr)
		}
		return result
	}

	// Debug: show raw output length
	fmt.Printf("        httpx stdout: %d bytes, stderr: %d bytes\n", len(r.Stdout), len(r.Stderr))

	lines := exec.Lines(r.Stdout)
	seen := make(map[string]bool)
	cdnSeen := make(map[string]bool)

	// Debug: log if httpx returned no output
	if len(lines) == 0 {
		fmt.Println("        httpx: no output lines (all hosts may be unreachable or blocked by WAF)")
		if r.Stderr != "" {
			stderr := r.Stderr
			if len(stderr) > 500 {
				stderr = stderr[:500]
			}
			fmt.Printf("        httpx stderr: %s\n", stderr)
		}
		// Show first 500 bytes of stdout in case it's not line-delimited
		if len(r.Stdout) > 0 {
			stdout := r.Stdout
			if len(stdout) > 500 {
				stdout = stdout[:500]
			}
			fmt.Printf("        httpx raw stdout: %s\n", stdout)
		}
	} else {
		fmt.Printf("        httpx output lines: %d\n", len(lines))
	}

	parseErrors := 0
	for _, line := range lines {
		// httpx can return .a as string or array depending on version/host
		var e struct {
			URL        string          `json:"url"`
			Host       string          `json:"host"`
			Port       string          `json:"port"`
			StatusCode int             `json:"status_code"`
			Title      string          `json:"title"`
			Tech       []string        `json:"tech"`
			IP         json.RawMessage `json:"a"` // Can be string or []string
			ASN        json.RawMessage `json:"asn"` // Can be string or object
			WebServer  string          `json:"webserver"`
			// BB-1: New fields
			JARM    string `json:"jarm"`
			Favicon string `json:"favicon"`
			CDN     bool   `json:"cdn"`
			CDNName string `json:"cdn_name"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			parseErrors++
			if parseErrors <= 3 {
				fmt.Printf("        httpx JSON parse error: %v (line: %.100s...)\n", err, line)
			}
			continue
		}

		// Parse IP field (can be string or []string)
		var ipStr string
		if len(e.IP) > 0 {
			// Try as string first
			if e.IP[0] == '"' {
				json.Unmarshal(e.IP, &ipStr)
			} else if e.IP[0] == '[' {
				// Array of IPs - take first one
				var ips []string
				if json.Unmarshal(e.IP, &ips) == nil && len(ips) > 0 {
					ipStr = ips[0]
				}
			}
		}

		// Parse ASN field (can be string or object)
		var asnStr string
		if len(e.ASN) > 0 {
			if e.ASN[0] == '"' {
				json.Unmarshal(e.ASN, &asnStr)
			} else if e.ASN[0] == '{' {
				// ASN object - extract the string representation
				var asnObj map[string]interface{}
				if json.Unmarshal(e.ASN, &asnObj) == nil {
					if as, ok := asnObj["as"].(string); ok {
						asnStr = as
					} else if asNum, ok := asnObj["as_number"].(float64); ok {
						asnStr = fmt.Sprintf("AS%.0f", asNum)
					}
				}
			}
		}
		if e.URL == "" || seen[e.URL] {
			continue
		}
		seen[e.URL] = true
		result.Alive = append(result.Alive, e.URL)

		h := e.Host
		if h == "" {
			h = e.URL
		}

		// BB-10: Classify by CDN status for prioritization
		// Track unique hosts (not URLs) for accurate alive count
		if !cdnSeen[h] {
			cdnSeen[h] = true
			result.AliveCount++ // Increment unique host counter
			if e.CDN {
				result.CDNHosts = append(result.CDNHosts, e.URL)
			} else {
				result.NonCDN = append(result.NonCDN, e.URL)
			}
		}

		port := 0
		fmt.Sscanf(e.Port, "%d", &port)
		result.Services[h] = append(result.Services[h], Service{
			Port:       port,
			Title:      e.Title,
			StatusCode: e.StatusCode,
			Tech:       strings.Join(e.Tech, ","),
			IP:         ipStr,  // Use parsed IP string
			ASN:        asnStr, // Use parsed ASN string
			WebServer:  e.WebServer,
			JARM:       e.JARM,
			Favicon:    e.Favicon,
			CDN:        e.CDN,
			CDNName:    e.CDNName,
		})
	}

	// Summary logging for debugging
	if parseErrors > 0 {
		fmt.Printf("        httpx: %d JSON parse errors (total lines: %d)\n", parseErrors, len(lines))
	}

	return result
}

func (s *Scanner) tlsx(input string) map[string]TLSData {
	tls := make(map[string]TLSData)
	// tlsx needs port specification - scan common TLS ports
	// Removed -so (subject only) flag to get full JSON output
	args := []string{"-l", input, "-p", "443,8443,9443,4443", "-silent", "-json"}
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}
	r := exec.Run("tlsx", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return tls
	}
	for _, line := range exec.Lines(r.Stdout) {
		// tlsx JSON output format:
		// {"host":"example.com","port":"443","tls_version":"tls13","cipher":"...","subject_cn":"...","subject_an":["..."],...}
		var e struct {
			Host      string   `json:"host"`
			Port      string   `json:"port"`        // tlsx outputs port as string
			Version   string   `json:"tls_version"` // tlsx uses tls_version not version
			Cipher    string   `json:"cipher"`
			Subject   string   `json:"subject_cn"`
			Issuer    string   `json:"issuer_cn"`
			SANs      []string `json:"subject_an"` // tlsx uses subject_an not san
			NotBefore string   `json:"not_before"`
			NotAfter  string   `json:"not_after"`
			Expired   bool     `json:"expired"`
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.Host == "" {
			continue
		}
		// Parse port as integer
		port := 443 // default
		if e.Port != "" {
			fmt.Sscanf(e.Port, "%d", &port)
		}
		// Calculate days left until expiry
		daysLeft := 0
		if e.NotAfter != "" {
			// Try RFC3339 format first (tlsx uses this: 2026-03-01T23:52:05Z)
			if t, err := time.Parse(time.RFC3339, e.NotAfter); err == nil {
				daysLeft = int(time.Until(t).Hours() / 24)
			} else if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", e.NotAfter); err == nil {
				daysLeft = int(time.Until(t).Hours() / 24)
			}
		}
		tls[e.Host] = TLSData{
			Host:      e.Host,
			Port:      port,
			Version:   e.Version,
			Cipher:    e.Cipher,
			Subject:   e.Subject,
			Issuer:    e.Issuer,
			SANs:      e.SANs,
			NotBefore: e.NotBefore,
			NotAfter:  e.NotAfter,
			DaysLeft:  daysLeft,
		}
	}
	return tls
}
