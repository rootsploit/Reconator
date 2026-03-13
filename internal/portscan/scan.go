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
	AliveHosts   []string             `json:"alive_hosts"` // URLs (http://host:port) - may have multiple per host
	AliveCount   int                  `json:"alive_count"` // Unique host count (for accurate stats)
	OpenPorts    map[string][]int     `json:"open_ports"`
	Services     map[string][]Service `json:"services"`
	TLSInfo      map[string]TLSData   `json:"tls_info,omitempty"`
	Duration     time.Duration        `json:"duration"`
	// CDN filtering (BB-10): Non-CDN hosts have 3x more vulnerabilities
	CDNHosts    []string `json:"cdn_hosts,omitempty"`     // Hosts behind CDN/WAF
	NonCDNHosts []string `json:"non_cdn_hosts,omitempty"` // Direct hosts (priority targets)
	// CDN pre-classification details (from cdncheck + httpx reconciliation)
	CDNDetails  map[string]string `json:"cdn_details,omitempty"`  // host → CDN provider name
	CDNFallback bool              `json:"cdn_fallback,omitempty"` // true if cdncheck was unavailable
}

// CDNPreClassification holds results from cdncheck pre-scan classification
// This runs BEFORE port scanning to split hosts into CDN vs Direct paths
type CDNPreClassification struct {
	CDNHosts    []string          // Hosts identified as behind CDN/WAF
	DirectHosts []string          // Hosts identified as direct (non-CDN)
	CDNDetails  map[string]string // host → CDN provider name
	Fallback    bool              // true if cdncheck unavailable, all hosts treated as direct
}

type Service struct {
	Port       int    `json:"port"`
	Title      string `json:"title,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Tech       string `json:"tech,omitempty"`
	IP         string `json:"ip,omitempty"`
	ASN        string `json:"asn,omitempty"`
	WebServer  string `json:"web_server,omitempty"`
	JARM       string `json:"jarm,omitempty"`     // JARM TLS fingerprint
	Favicon    string `json:"favicon,omitempty"`  // Favicon hash
	CDN        bool   `json:"cdn,omitempty"`      // Is behind CDN/WAF
	CDNName    string `json:"cdn_name,omitempty"` // CDN provider name
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
		CDNDetails:   make(map[string]string),
	}

	if len(hosts) == 0 {
		return result, nil
	}

	// Step 1: CDN Pre-Classification (DNS-only, ~5-10s)
	// Run cdncheck on raw subdomains BEFORE port scanning
	// CDN hosts get gentle httpx-only; Direct hosts get full naabu+httpx
	preCDN := s.preclassifyCDN(hosts)
	result.CDNFallback = preCDN.Fallback

	fmt.Printf("        CDN pre-classification: %d CDN, %d direct (fallback=%v)\n",
		len(preCDN.CDNHosts), len(preCDN.DirectHosts), preCDN.Fallback)

	// Create temp file for TLS scanning (all hosts)
	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), ".txt")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Step 2: Parallel scan paths
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Track results from each path
	var directHttpx httpxResult
	var cdnHttpx httpxResult

	// Path A: Direct hosts → naabu (full ports) + httpx (all discovered ports)
	if len(preCDN.DirectHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("        [Direct Path] Scanning %d direct hosts (naabu + httpx)...\n", len(preCDN.DirectHosts))

			ports, httpxRes := s.scanDirectHosts(preCDN.DirectHosts)

			mu.Lock()
			for h, p := range ports {
				result.OpenPorts[h] = p
				result.TotalPorts += len(p)
			}
			directHttpx = httpxRes
			mu.Unlock()

			fmt.Printf("        [Direct Path] Done: %d ports, %d alive hosts\n",
				result.TotalPorts, httpxRes.AliveCount)
		}()
	}

	// Path B: CDN hosts → httpx ONLY (80/443, gentle settings)
	if len(preCDN.CDNHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("        [CDN Path] Probing %d CDN hosts (httpx 80/443 only)...\n", len(preCDN.CDNHosts))

			httpxRes := s.httpxCDN(preCDN.CDNHosts)

			mu.Lock()
			cdnHttpx = httpxRes
			mu.Unlock()

			fmt.Printf("        [CDN Path] Done: %d alive hosts\n", httpxRes.AliveCount)
		}()
	}

	// Path C: TLS scanning on ALL hosts (parallel with A and B)
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

	// Step 3: Reconciliation — httpx -cdn tag validates/corrects cdncheck classification
	cdnHosts, nonCDNHosts, cdnDetails := s.reconcileCDN(preCDN, &directHttpx, &cdnHttpx)
	result.CDNHosts = cdnHosts
	result.NonCDNHosts = nonCDNHosts
	result.CDNDetails = cdnDetails

	// Step 4: Merge alive hosts and services from both paths
	result.AliveHosts = append(result.AliveHosts, directHttpx.Alive...)
	result.AliveHosts = append(result.AliveHosts, cdnHttpx.Alive...)
	result.AliveCount = directHttpx.AliveCount + cdnHttpx.AliveCount

	for h, svc := range directHttpx.Services {
		result.Services[h] = append(result.Services[h], svc...)
	}
	for h, svc := range cdnHttpx.Services {
		result.Services[h] = append(result.Services[h], svc...)
	}

	fmt.Printf("        Final: %d alive hosts (%d URLs), %d CDN, %d direct, %d ports\n",
		result.AliveCount, len(result.AliveHosts), len(result.CDNHosts),
		len(result.NonCDNHosts), result.TotalPorts)

	result.Duration = time.Since(start)
	return result, nil
}

// preclassifyCDN runs cdncheck on raw subdomains to classify CDN vs Direct hosts
// This is DNS-only (no HTTP needed), runs in ~5-10s, and enables split scanning paths
func (s *Scanner) preclassifyCDN(hosts []string) *CDNPreClassification {
	result := &CDNPreClassification{
		CDNDetails: make(map[string]string),
	}

	// Check if cdncheck is installed
	if !s.c.IsInstalled("cdncheck") {
		fmt.Println("        [CDN Pre-Classification] cdncheck not installed, treating all hosts as direct")
		result.DirectHosts = hosts
		result.Fallback = true
		return result
	}

	// Write hosts to temp file
	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-cdncheck.txt")
	if err != nil {
		fmt.Printf("        [CDN Pre-Classification] temp file error: %v, treating all as direct\n", err)
		result.DirectHosts = hosts
		result.Fallback = true
		return result
	}
	defer cleanup()

	fmt.Println("        [CDN Pre-Classification] Running cdncheck on raw subdomains...")
	r := exec.Run("cdncheck", []string{"-i", tmp, "-j", "-silent", "-resp"}, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		fmt.Printf("        [CDN Pre-Classification] cdncheck failed: %v, treating all as direct\n", r.Error)
		result.DirectHosts = hosts
		result.Fallback = true
		return result
	}

	// Parse cdncheck JSON output
	checked := make(map[string]bool)
	for _, line := range exec.Lines(r.Stdout) {
		var e struct {
			Input     string `json:"input"`
			CDN       bool   `json:"cdn"`
			CDNName   string `json:"cdn_name,omitempty"`
			WAF       bool   `json:"waf"`
			WAFName   string `json:"waf_name,omitempty"`
			Cloud     bool   `json:"cloud"`
			CloudName string `json:"cloud_name,omitempty"`
		}
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		checked[e.Input] = true

		if e.CDN || e.WAF || e.Cloud {
			result.CDNHosts = append(result.CDNHosts, e.Input)
			// Pick the most specific provider name
			provider := e.CDNName
			if provider == "" {
				provider = e.WAFName
			}
			if provider == "" {
				provider = e.CloudName
			}
			if provider != "" {
				result.CDNDetails[e.Input] = provider
			}
		} else {
			result.DirectHosts = append(result.DirectHosts, e.Input)
		}
	}

	// Hosts not in cdncheck output default to direct
	for _, h := range hosts {
		if !checked[h] {
			result.DirectHosts = append(result.DirectHosts, h)
		}
	}

	// Print provider summary
	counts := make(map[string]int)
	for _, p := range result.CDNDetails {
		counts[p]++
	}
	for p, c := range counts {
		fmt.Printf("        [CDN Pre-Classification] %s: %d hosts\n", p, c)
	}

	return result
}

// scanDirectHosts runs full naabu+httpx pipeline on direct (non-CDN) hosts
// This is the same streaming pipeline as the original Scan() but only for direct hosts
func (s *Scanner) scanDirectHosts(hosts []string) (map[string][]int, httpxResult) {
	allPorts := make(map[string][]int)
	finalHttpx := httpxResult{
		Services: make(map[string][]Service),
	}

	if len(hosts) == 0 {
		return allPorts, finalHttpx
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(hosts, "\n"), "-direct.txt")
	if err != nil {
		return allPorts, finalHttpx
	}
	defer cleanup()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Channel for streaming naabu→httpx
	portsChan := make(chan string, 100)

	// naabu (producer)
	if s.c.IsInstalled("naabu") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(portsChan)

			ports := s.naabuStreaming(tmp, portsChan)
			mu.Lock()
			for h, p := range ports {
				allPorts[h] = p
			}
			mu.Unlock()
		}()
	} else {
		close(portsChan)
	}

	// httpx (consumer)
	if s.c.IsInstalled("httpx") {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var discoveredPorts []string
			for port := range portsChan {
				discoveredPorts = append(discoveredPorts, port)

				if len(discoveredPorts) >= 50 {
					httpxRes := s.httpxBatch(discoveredPorts)
					mu.Lock()
					finalHttpx.Alive = append(finalHttpx.Alive, httpxRes.Alive...)
					finalHttpx.AliveCount += httpxRes.AliveCount
					finalHttpx.CDNHosts = append(finalHttpx.CDNHosts, httpxRes.CDNHosts...)
					finalHttpx.NonCDN = append(finalHttpx.NonCDN, httpxRes.NonCDN...)
					for h, svc := range httpxRes.Services {
						finalHttpx.Services[h] = append(finalHttpx.Services[h], svc...)
					}
					mu.Unlock()
					discoveredPorts = nil
				}
			}

			if len(discoveredPorts) > 0 {
				httpxRes := s.httpxBatch(discoveredPorts)
				mu.Lock()
				finalHttpx.Alive = append(finalHttpx.Alive, httpxRes.Alive...)
				finalHttpx.AliveCount += httpxRes.AliveCount
				finalHttpx.CDNHosts = append(finalHttpx.CDNHosts, httpxRes.CDNHosts...)
				finalHttpx.NonCDN = append(finalHttpx.NonCDN, httpxRes.NonCDN...)
				for h, svc := range httpxRes.Services {
					finalHttpx.Services[h] = append(finalHttpx.Services[h], svc...)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return allPorts, finalHttpx
}

// httpxCDN runs httpx with gentle settings on CDN hosts (80/443 only, no naabu)
// Avoids triggering WAF rate limiting by using reduced threads and timeouts
func (s *Scanner) httpxCDN(hosts []string) httpxResult {
	result := httpxResult{
		Services: make(map[string][]Service),
	}

	if len(hosts) == 0 || !s.c.IsInstalled("httpx") {
		return result
	}

	// Generate host:80 and host:443 entries for httpx
	var targets []string
	for _, h := range hosts {
		targets = append(targets, h+":80", h+":443")
	}

	tmp, cleanup, err := exec.TempFile(strings.Join(targets, "\n"), "-cdn-httpx.txt")
	if err != nil {
		return result
	}
	defer cleanup()

	// Gentle httpx settings for CDN hosts:
	// - Lower threads (20) to avoid WAF rate limiting
	// - Shorter timeout (5s) since CDN responses are fast
	// - Fewer retries (1) to avoid hammering
	// - No -jarm/-favicon/-tls-grab (avoid extra probes on CDN)
	// - -cdn flag to validate CDN classification
	args := []string{
		"-l", tmp,
		"-silent", "-follow-redirects",
		"-status-code", "-title", "-tech-detect",
		"-ip", "-asn", "-web-server",
		"-cdn",
		"-json",
		"-timeout", "5",
		"-retries", "1",
		"-threads", "20",
	}

	r := exec.Run("httpx", args, &exec.Options{Timeout: 5 * time.Minute})
	if r.Error != nil {
		fmt.Printf("        [CDN httpx] error: %v\n", r.Error)
		return result
	}

	// Parse httpx output (same format as httpxBatch)
	lines := exec.Lines(r.Stdout)
	seen := make(map[string]bool)
	cdnSeen := make(map[string]bool)

	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry struct {
			URL        string   `json:"url"`
			Host       string   `json:"host"`
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			Tech       []string `json:"tech"`
			HostIP     string   `json:"host_ip"`
			ASN        struct {
				ASNumber string `json:"as_number"`
				ASName   string `json:"as_name"`
			} `json:"asn"`
			WebServer string `json:"webserver"`
			CDN       bool   `json:"cdn"`
			CDNName   string `json:"cdn_name"`
			Port      string `json:"port"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil || entry.URL == "" {
			continue
		}

		host := entry.Host
		if !seen[host] {
			seen[host] = true
			result.AliveCount++
		}
		result.Alive = append(result.Alive, entry.URL)

		if entry.CDN {
			if !cdnSeen[host] {
				cdnSeen[host] = true
				result.CDNHosts = append(result.CDNHosts, host)
			}
		} else {
			result.NonCDN = append(result.NonCDN, host)
		}

		asnStr := ""
		if entry.ASN.ASNumber != "" {
			asnStr = entry.ASN.ASNumber
			if entry.ASN.ASName != "" {
				asnStr += " (" + entry.ASN.ASName + ")"
			}
		}

		svc := Service{
			StatusCode: entry.StatusCode,
			Title:      entry.Title,
			Tech:       strings.Join(entry.Tech, ","),
			IP:         entry.HostIP,
			ASN:        asnStr,
			WebServer:  entry.WebServer,
			CDN:        entry.CDN,
			CDNName:    entry.CDNName,
		}
		if entry.Port != "" {
			fmt.Sscanf(entry.Port, "%d", &svc.Port)
		}
		result.Services[host] = append(result.Services[host], svc)
	}

	return result
}

// reconcileCDN merges cdncheck pre-classification with httpx -cdn tag results
// httpx is authoritative for reclassification — no host is ever dropped
func (s *Scanner) reconcileCDN(preCDN *CDNPreClassification, directResult, cdnResult *httpxResult) (cdnHosts, nonCDNHosts []string, cdnDetails map[string]string) {
	cdnDetails = make(map[string]string)
	cdnSet := make(map[string]bool)
	directSet := make(map[string]bool)

	// Start with cdncheck pre-classification as base
	for host, provider := range preCDN.CDNDetails {
		cdnDetails[host] = provider
	}
	for _, h := range preCDN.CDNHosts {
		cdnSet[h] = true
	}
	for _, h := range preCDN.DirectHosts {
		directSet[h] = true
	}

	reclassifiedToCDN := 0
	reclassifiedToDirect := 0

	// Check httpx results from the DIRECT path
	// If httpx says a "direct" host is actually CDN → reclassify to CDN
	for host, services := range directResult.Services {
		for _, svc := range services {
			if svc.CDN && !cdnSet[host] {
				cdnSet[host] = true
				delete(directSet, host)
				if svc.CDNName != "" {
					cdnDetails[host] = svc.CDNName
				}
				reclassifiedToCDN++
				break
			}
		}
	}

	// Check httpx results from the CDN path
	// If httpx says a "CDN" host is actually direct → reclassify to direct
	for host, services := range cdnResult.Services {
		allNonCDN := true
		for _, svc := range services {
			if svc.CDN {
				allNonCDN = false
				break
			}
		}
		if allNonCDN && cdnSet[host] {
			delete(cdnSet, host)
			directSet[host] = true
			delete(cdnDetails, host)
			reclassifiedToDirect++
		}
	}

	if reclassifiedToCDN > 0 || reclassifiedToDirect > 0 {
		fmt.Printf("        [Reconciliation] Reclassified: %d→CDN, %d→Direct\n",
			reclassifiedToCDN, reclassifiedToDirect)
	}

	// Build final lists
	for h := range cdnSet {
		cdnHosts = append(cdnHosts, h)
	}
	for h := range directSet {
		nonCDNHosts = append(nonCDNHosts, h)
	}

	return cdnHosts, nonCDNHosts, cdnDetails
}

// naabuStreaming runs naabu and streams discovered ports to a channel
// This enables httpx to start probing ports before naabu completes (pipelining)
func (s *Scanner) naabuStreaming(input string, portsChan chan<- string) map[string][]int {
	ports := make(map[string][]int)
	args := []string{"-l", input, "-p", "80,443,8080,8443,8000,3000,5000,9000,9443,4443", "-c", fmt.Sprintf("%d", s.cfg.Threads), "-silent", "-json", "-stream"}

	// Add SYN or CONNECT mode based on config
	// -sS = SYN scan (faster, requires root)
	// -sT = CONNECT scan (default, more reliable)
	if s.cfg.PortScanMode == "syn" {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}

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

	// Add SYN or CONNECT mode based on config
	// -sS = SYN scan (faster, requires root)
	// -sT = CONNECT scan (default, more reliable)
	if s.cfg.PortScanMode == "syn" {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}

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
	Alive      []string // URLs (http://host:port)
	AliveCount int      // Unique host count
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
		"-retries", "2", // Retry failed requests
	}

	// BB-1: Add enhanced fingerprinting flags if not in fast mode
	// These help with asset correlation and infrastructure mapping
	// Only add if DeepScan is enabled to avoid timeouts on CDN hosts
	if s.cfg.DeepScan {
		args = append(args,
			"-jarm",     // JARM TLS fingerprinting for server identification
			"-favicon",  // Favicon hash for asset correlation across domains
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
			IP         json.RawMessage `json:"a"`   // Can be string or []string
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
			Tech       []string `json:"tech"`    // httpx v1.8+ outputs array
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
