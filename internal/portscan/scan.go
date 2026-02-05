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

	// Step 1 & 2: Run naabu and httpx with pipelining (2-3 min savings)
	// Stream naabu output to httpx as ports are discovered instead of waiting for completion
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Create channel for streaming discovered ports from naabu to httpx
	portsChan := make(chan string, 100) // Buffered channel for host:port entries

	// Start naabu port scanning (producer)
	if s.c.IsInstalled("naabu") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(portsChan) // Signal completion to httpx

			fmt.Println("        Running naabu (streaming mode)...")
			ports := s.naabuStreaming(tmp, portsChan)

			mu.Lock()
			for h, p := range ports {
				result.OpenPorts[h] = p
				result.TotalPorts += len(p)
			}
			mu.Unlock()

			fmt.Printf("        naabu: %d open ports discovered\n", result.TotalPorts)
		}()
	} else {
		close(portsChan) // No naabu, close immediately
	}

	// Start httpx probe (consumer - processes ports as they arrive)
	if s.c.IsInstalled("httpx") {
		wg.Add(1)
		go func() {
			defer wg.Done()

			fmt.Println("        Running httpx (pipelined mode)...")

			// Collect ports as they arrive from naabu
			var discoveredPorts []string
			for port := range portsChan {
				discoveredPorts = append(discoveredPorts, port)

				// Process in batches of 50 for efficiency
				if len(discoveredPorts) >= 50 {
					httpxRes := s.httpxBatch(discoveredPorts)
					mu.Lock()
					result.AliveHosts = append(result.AliveHosts, httpxRes.Alive...)
					result.AliveCount += httpxRes.AliveCount
					result.CDNHosts = append(result.CDNHosts, httpxRes.CDNHosts...)
					result.NonCDNHosts = append(result.NonCDNHosts, httpxRes.NonCDN...)
					for h, svc := range httpxRes.Services {
						result.Services[h] = append(result.Services[h], svc...)
					}
					mu.Unlock()

					discoveredPorts = nil // Reset batch
				}
			}

			// Process remaining ports
			if len(discoveredPorts) > 0 {
				httpxRes := s.httpxBatch(discoveredPorts)
				mu.Lock()
				result.AliveHosts = append(result.AliveHosts, httpxRes.Alive...)
				result.AliveCount += httpxRes.AliveCount
				result.CDNHosts = append(result.CDNHosts, httpxRes.CDNHosts...)
				result.NonCDNHosts = append(result.NonCDNHosts, httpxRes.NonCDN...)
				for h, svc := range httpxRes.Services {
					result.Services[h] = append(result.Services[h], svc...)
				}
				mu.Unlock()
			}

			fmt.Printf("        httpx: %d unique hosts alive (%d URLs, %d non-CDN, %d CDN)\n",
				result.AliveCount, len(result.AliveHosts), len(result.NonCDNHosts), len(result.CDNHosts))
		}()
	}

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

// naabuStreaming runs naabu and streams discovered ports to a channel
// This enables httpx to start probing ports before naabu completes (pipelining)
func (s *Scanner) naabuStreaming(input string, portsChan chan<- string) map[string][]int {
	ports := make(map[string][]int)
	args := []string{"-l", input, "-p", "80,443,8080,8443,8000,3000,5000,9000,9443,4443", "-c", fmt.Sprintf("%d", s.cfg.Threads), "-silent", "-json", "-stream"}
	if s.cfg.RateLimit > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", s.cfg.RateLimit))
	}
	r := exec.Run("naabu", args, &exec.Options{Timeout: 15 * time.Minute})
	if r.Error != nil {
		return ports
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
			hostPort := fmt.Sprintf("%s:%d", h, e.Port)

			// Stream to httpx immediately
			select {
			case portsChan <- hostPort:
			default:
				// Channel full, continue (httpx will catch up)
			}
		}
	}
	return ports
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
	// BB-1: Enhanced httpx flags for better asset correlation
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

	// BB-1: Add enhanced fingerprinting flags if not in fast mode
	// These help with asset correlation and infrastructure mapping
	// Only add if DeepScan is enabled to avoid timeouts on CDN hosts
	if s.cfg.DeepScan {
		args = append(args,
			"-jarm",    // JARM TLS fingerprinting for server identification
			"-favicon", // Favicon hash for asset correlation across domains
			"-tls-grab", // Additional TLS certificate details
		)
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

// httpxBatch processes a batch of host:port entries with httpx (for pipelined scanning)
func (s *Scanner) httpxBatch(hostPorts []string) httpxResult {
	result := httpxResult{
		Services: make(map[string][]Service),
	}

	if len(hostPorts) == 0 {
		fmt.Println("        [httpxBatch] Called with 0 host:ports, returning empty result")
		return result
	}

	fmt.Printf("        [httpxBatch] Processing %d host:port entries\n", len(hostPorts))

	// Create temp file for batch input
	input, cleanup, err := exec.TempFile(strings.Join(hostPorts, "\n"), ".txt")
	if err != nil {
		fmt.Printf("        [httpxBatch] Failed to create temp file: %v\n", err)
		return result
	}
	defer cleanup()

	// Use same args as httpx method but optimized for batch processing
	args := []string{
		"-l", input,
		"-silent", "-follow-redirects",
		"-status-code", "-title", "-tech-detect",
		"-ip", "-asn", "-web-server",
		"-cdn",
		"-json",
		"-timeout", "8", // Slightly faster timeout for batches
		"-retries", "1", // Fewer retries for batches
	}

	// Reduce threads for batch processing to avoid overwhelming network
	threads := s.cfg.Threads / 2
	if threads < 5 {
		threads = 5
	}
	if threads > 15 {
		threads = 15
	}
	args = append(args, "-threads", fmt.Sprintf("%d", threads))

	r := exec.Run("httpx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		fmt.Printf("        [httpxBatch] httpx error: %v\n", r.Error)
		return result
	}

	fmt.Printf("        [httpxBatch] httpx stdout: %d bytes, stderr: %d bytes\n", len(r.Stdout), len(r.Stderr))

	lines := exec.Lines(r.Stdout)
	fmt.Printf("        [httpxBatch] Parsed %d output lines\n", len(lines))
	seen := make(map[string]bool)
	cdnSeen := make(map[string]bool)

	unmarshalErrors := 0
	emptyURLs := 0

	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry struct {
			URL        string   `json:"url"`
			Host       string   `json:"host"`
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			Tech       []string `json:"tech"` // httpx v1.8+ outputs array
			HostIP     string   `json:"host_ip"` // Changed from "ip"
			ASN        struct {
				ASNumber  string `json:"as_number"`
				ASName    string `json:"as_name"`
				ASCountry string `json:"as_country"`
			} `json:"asn"` // httpx v1.8+ outputs object
			WebServer string `json:"webserver"`
			CDN       bool   `json:"cdn"`
			CDNName   string `json:"cdn_name"`
			JARM      string `json:"jarm"`
			Favicon   string `json:"favicon"`
			Port      string `json:"port"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			unmarshalErrors++
			if unmarshalErrors <= 3 {
				preview := line
				if len(line) > 100 {
					preview = line[:100]
				}
				fmt.Printf("        [httpxBatch] JSON unmarshal error (line preview): %s\n", preview)
			}
			continue
		}

		if entry.URL == "" {
			emptyURLs++
			continue
		}

		if entry.URL != "" {
			host := entry.Host
			if !seen[host] {
				seen[host] = true
				result.AliveCount++
			}
			result.Alive = append(result.Alive, entry.URL)

			// Track CDN hosts separately
			if entry.CDN {
				if !cdnSeen[host] {
					cdnSeen[host] = true
					result.CDNHosts = append(result.CDNHosts, host)
				}
			} else {
				result.NonCDN = append(result.NonCDN, host)
			}

			// Convert tech array to comma-separated string for Service struct
			techStr := strings.Join(entry.Tech, ",")

			// Extract ASN string from object (format: "AS16509 (amazon-02)")
			asnStr := ""
			if entry.ASN.ASNumber != "" {
				asnStr = entry.ASN.ASNumber
				if entry.ASN.ASName != "" {
					asnStr += " (" + entry.ASN.ASName + ")"
				}
			}

			// Add service info
			svc := Service{
				StatusCode: entry.StatusCode,
				Title:      entry.Title,
				Tech:       techStr,
				IP:         entry.HostIP,
				ASN:        asnStr,
				WebServer:  entry.WebServer,
				CDN:        entry.CDN,
				CDNName:    entry.CDNName,
				JARM:       entry.JARM,
				Favicon:    entry.Favicon,
			}
			if entry.Port != "" {
				fmt.Sscanf(entry.Port, "%d", &svc.Port)
			}
			result.Services[host] = append(result.Services[host], svc)
		}
	}

	fmt.Printf("        [httpxBatch] Result: %d alive hosts, %d unmarshal errors, %d empty URLs\n",
		result.AliveCount, unmarshalErrors, emptyURLs)

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
