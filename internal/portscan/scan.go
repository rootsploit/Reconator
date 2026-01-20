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
	AliveHosts   []string             `json:"alive_hosts"`
	OpenPorts    map[string][]int     `json:"open_ports"`
	Services     map[string][]Service `json:"services"`
	TLSInfo      map[string]TLSData   `json:"tls_info,omitempty"`
	Duration     time.Duration        `json:"duration"`
}

type Service struct {
	Port       int    `json:"port"`
	Title      string `json:"title,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Tech       string `json:"tech,omitempty"`
	IP         string `json:"ip,omitempty"`
	ASN        string `json:"asn,omitempty"`
	WebServer  string `json:"web_server,omitempty"`
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

		alive, svcs := s.httpx(httpxInput)
		mu.Lock()
		result.AliveHosts = alive
		for h, svc := range svcs {
			result.Services[h] = svc
		}
		mu.Unlock()
		fmt.Printf("        httpx: %d alive\n", len(alive))
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
	var hostPorts []string // host:port format for httpx
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

func (s *Scanner) httpx(input string) ([]string, map[string][]Service) {
	var alive []string
	svcs := make(map[string][]Service)
	// Enhanced httpx flags: IP, ASN, web-server for richer data
	args := []string{"-l", input, "-silent", "-follow-redirects", "-status-code", "-title", "-tech-detect", "-ip", "-asn", "-web-server", "-json"}
	if s.cfg.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", s.cfg.Threads))
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
		return alive, svcs
	}
	lines := exec.Lines(r.Stdout)
	seen := make(map[string]bool)
	for _, line := range lines {
		var e struct {
			URL        string   `json:"url"`
			Host       string   `json:"host"`
			Port       string   `json:"port"` // httpx outputs port as string
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			Tech       []string `json:"tech"`
			IP         string   `json:"a"`          // IP address (A record)
			ASN        string   `json:"asn"`        // ASN info (AS12345, Cloudflare)
			WebServer  string   `json:"webserver"`  // Web server header
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.URL == "" || seen[e.URL] {
			continue
		}
		seen[e.URL] = true
		alive = append(alive, e.URL)
		h := e.Host
		if h == "" {
			h = e.URL
		}
		port := 0
		fmt.Sscanf(e.Port, "%d", &port)
		svcs[h] = append(svcs[h], Service{
			Port:       port,
			Title:      e.Title,
			StatusCode: e.StatusCode,
			Tech:       strings.Join(e.Tech, ","),
			IP:         e.IP,
			ASN:        e.ASN,
			WebServer:  e.WebServer,
		})
	}
	return alive, svcs
}

func (s *Scanner) tlsx(input string) map[string]TLSData {
	tls := make(map[string]TLSData)
	// tlsx needs port specification - scan common TLS ports
	// Added -expired flag to check expiry info
	args := []string{"-l", input, "-p", "443,8443,9443,4443", "-silent", "-json", "-so", "-ve"}
	if s.cfg.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.cfg.Threads))
	}
	r := exec.Run("tlsx", args, &exec.Options{Timeout: 10 * time.Minute})
	if r.Error != nil {
		return tls
	}
	for _, line := range exec.Lines(r.Stdout) {
		var e struct {
			Host      string   `json:"host"`
			Port      int      `json:"port"`
			Version   string   `json:"version"`
			Cipher    string   `json:"cipher"`
			Subject   string   `json:"subject_cn"`
			Issuer    string   `json:"issuer_cn"`
			SANs      []string `json:"san"`
			NotBefore string   `json:"not_before"`
			NotAfter  string   `json:"not_after"`
			Expired   bool     `json:"expired"`
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.Host == "" {
			continue
		}
		// Calculate days left until expiry
		daysLeft := 0
		if e.NotAfter != "" {
			if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", e.NotAfter); err == nil {
				daysLeft = int(time.Until(t).Hours() / 24)
			} else if t, err := time.Parse(time.RFC3339, e.NotAfter); err == nil {
				daysLeft = int(time.Until(t).Hours() / 24)
			}
		}
		tls[e.Host] = TLSData{
			Host:      e.Host,
			Port:      e.Port,
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
