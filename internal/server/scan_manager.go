package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/database"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/jsanalysis"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/report"
	"github.com/rootsploit/reconator/internal/runner"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// ScanStatus represents the state of a scan
type ScanStatus string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusPaused    ScanStatus = "paused"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// Scan represents a scan instance
type Scan struct {
	ID           string     `json:"id"`
	Target       string     `json:"target"`
	Status       ScanStatus `json:"status"`
	Phases       []string   `json:"phases"`
	CurrentPhase string     `json:"current_phase,omitempty"`
	Progress     int        `json:"progress"` // 0-100
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Duration     string     `json:"duration,omitempty"`
	Error        string     `json:"error,omitempty"`
	OutputDir    string     `json:"output_dir"`

	// Internal state
	cancel    context.CancelFunc `json:"-"`
	pauseCh   chan bool          `json:"-"`
	resumeCh  chan bool          `json:"-"`
	config    *config.Config     `json:"-"`
	isPaused  bool               `json:"-"`
	pausedAt  *time.Time         `json:"-"`
}

// ScanManager manages scan lifecycle
type ScanManager struct {
	scans      map[string]*Scan
	mu         sync.RWMutex
	baseConfig *config.Config
	baseDir    string
	wsHub      *WebSocketHub // WebSocket hub for broadcasting updates
	db         *database.DB  // Database for persistence
}

// NewScanManager creates a new scan manager
func NewScanManager(cfg *config.Config) *ScanManager {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Initialize database
	dbPath := filepath.Join(cfg.OutputDir, "reconator.db")
	if cfg.Debug {
		log.Printf("[DEBUG] Initializing ScanManager with OutputDir=%s", cfg.OutputDir)
		log.Printf("[DEBUG] Database path: %s", dbPath)
	}

	db, err := database.New(dbPath)
	if err != nil {
		log.Printf("[WARNING] Failed to initialize database: %v. Scans will not persist.", err)
	} else {
		log.Printf("[INFO] Database initialized successfully at %s", dbPath)
	}

	mgr := &ScanManager{
		scans:      make(map[string]*Scan),
		baseConfig: cfg,
		baseDir:    cfg.OutputDir,
		db:         db,
	}

	// Load existing scans from database
	if db != nil {
		mgr.loadScansFromDB()
	} else {
		log.Printf("[WARNING] Database is nil, skipping scan load")
	}

	return mgr
}

// loadScansFromDB loads existing scans from the database on startup
func (m *ScanManager) loadScansFromDB() {
	if m.baseConfig.Debug {
		log.Printf("[DEBUG] Loading scans from database...")
	}
	records, err := m.db.ListScans()
	if err != nil {
		log.Printf("[WARNING] Failed to load scans from database: %v", err)
		return
	}

	if m.baseConfig.Debug {
		log.Printf("[DEBUG] Database returned %d scan records", len(records))
	}
	for _, record := range records {
		if m.baseConfig.Debug {
			log.Printf("[DEBUG] Loading scan: ID=%s, Target=%s, Status=%s, Phases=%s",
				record.ID, record.Target, record.Status, record.Phases)
		}

		scan := &Scan{
			ID:           record.ID,
			Target:       record.Target,
			Status:       ScanStatus(record.Status),
			Phases:       database.UnmarshalPhases(record.Phases),
			CurrentPhase: record.CurrentPhase,
			Progress:     record.Progress,
			StartedAt:    record.StartedAt,
			CompletedAt:  record.CompletedAt,
			Duration:     record.Duration,
			Error:        record.Error,
			OutputDir:    record.OutputDir,
		}
		m.scans[scan.ID] = scan
		if m.baseConfig.Debug {
			log.Printf("[DEBUG] Added scan %s to in-memory map", scan.ID)
		}
	}

	log.Printf("[INFO] Loaded %d scans from database", len(records))
	log.Printf("[DEBUG] ScanManager now has %d scans in memory map", len(m.scans))
	for scanID := range m.scans {
		log.Printf("[DEBUG] Scan in map: %s", scanID)
	}
}

// SetWebSocketHub sets the WebSocket hub for broadcasting updates
func (m *ScanManager) SetWebSocketHub(hub *WebSocketHub) {
	m.wsHub = hub
}

// StartScan initiates a new scan
func (m *ScanManager) StartScan(target string, phases []string, threads int, deepScan, passiveMode bool) (*Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate unique ID
	id := uuid.New().String()[:8]

	// Create output directory with scan ID to prevent conflicts between repeat scans
	outputDir := filepath.Join(m.baseDir, fmt.Sprintf("%s_%s", id, target))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create scan config
	cfg := *m.baseConfig
	cfg.Target = target
	cfg.OutputDir = outputDir
	if len(phases) > 0 {
		cfg.Phases = phases
	} else {
		cfg.Phases = []string{"all"}
	}
	if threads > 0 {
		cfg.Threads = threads
	}
	cfg.DeepScan = deepScan
	cfg.PassiveMode = passiveMode

	// Passive mode skips generative subdomain methods (DNS brute, permutations)
	// but keeps API-based discovery and DNS validation
	if passiveMode {
		cfg.SkipDNSBrute = true // Skips DNS bruteforce, alterx, mksub permutations

		// Warn if user selected active phases with passive mode
		hasActivePhases := false
		for _, phase := range cfg.Phases {
			if phase == "screenshot" || phase == "tech" || phase == "ports" {
				hasActivePhases = true
				break
			}
		}
		if hasActivePhases {
			fmt.Println("\n⚠️  Warning: Passive mode enabled with active scanning phases (screenshot/tech/ports)")
			fmt.Println("   These phases will actively interact with target assets during the scan.")
		}
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	scan := &Scan{
		ID:        id,
		Target:    target,
		Status:    StatusPending,
		Phases:    cfg.Phases,
		Progress:  0,
		StartedAt: time.Now(),
		OutputDir: outputDir,
		cancel:    cancel,
		pauseCh:   make(chan bool, 1),
		resumeCh:  make(chan bool, 1),
		config:    &cfg,
		isPaused:  false,
	}

	m.scans[id] = scan

	// Save to database
	if m.db != nil {
		record := &database.ScanRecord{
			ID:        scan.ID,
			Target:    scan.Target,
			Status:    string(scan.Status),
			Phases:    database.MarshalPhases(scan.Phases),
			Progress:  scan.Progress,
			StartedAt: scan.StartedAt,
			OutputDir: scan.OutputDir,
		}
		if err := m.db.SaveScan(record); err != nil {
			log.Printf("[WARNING] Failed to save scan to database: %v", err)
		}
	}

	// Start scan in background
	go m.runScan(ctx, scan)

	return scan, nil
}

// runScan executes the scan in background
func (m *ScanManager) runScan(ctx context.Context, scan *Scan) {
	m.mu.Lock()
	scan.Status = StatusRunning
	m.mu.Unlock()

	// Broadcast scan started
	m.broadcastScanUpdate("scan_started", scan)

	// Create runner
	r := runner.New(scan.config)

	// Create progress callback
	progressCh := make(chan runner.ProgressUpdate, 100)

	// Start progress listener
	go func() {
		lastSavedProgress := 0
		lastSavedPhase := ""
		for update := range progressCh {
			// Check for pause signal
			select {
			case <-scan.pauseCh:
				m.mu.Lock()
				scan.isPaused = true
				scan.Status = StatusPaused
				m.mu.Unlock()

				// Wait for resume signal
				<-scan.resumeCh

				m.mu.Lock()
				scan.isPaused = false
				scan.Status = StatusRunning
				m.mu.Unlock()
			default:
				// Continue normally
			}

			m.mu.Lock()
			scan.CurrentPhase = update.Phase
			scan.Progress = update.Progress

			// Save to database periodically (every 10% or on phase change)
			shouldSave := (scan.Progress-lastSavedProgress >= 10) || (scan.CurrentPhase != lastSavedPhase)
			if m.db != nil && shouldSave {
				record := &database.ScanRecord{
					ID:           scan.ID,
					Target:       scan.Target,
					Status:       string(scan.Status),
					Phases:       database.MarshalPhases(scan.Phases),
					CurrentPhase: scan.CurrentPhase,
					Progress:     scan.Progress,
					StartedAt:    scan.StartedAt,
					OutputDir:    scan.OutputDir,
				}
				if err := m.db.SaveScan(record); err != nil {
					log.Printf("[WARNING] Failed to save scan progress to database: %v", err)
				} else {
					lastSavedProgress = scan.Progress
					lastSavedPhase = scan.CurrentPhase
				}
			}
			m.mu.Unlock()

			// Broadcast progress update to WebSocket clients
			m.broadcastScanUpdate("scan_progress", scan)
		}
	}()

	// Run scan with context
	err := r.RunWithContext(ctx, progressCh)

	// Update scan status
	m.mu.Lock()
	now := time.Now()
	scan.CompletedAt = &now
	scan.Duration = now.Sub(scan.StartedAt).Round(time.Second).String()

	if ctx.Err() == context.Canceled {
		scan.Status = StatusCancelled
	} else if err != nil {
		scan.Status = StatusFailed
		scan.Error = err.Error()
	} else {
		scan.Status = StatusCompleted
		scan.Progress = 100
	}

	// Save final state to database
	if m.db != nil {
		record := &database.ScanRecord{
			ID:           scan.ID,
			Target:       scan.Target,
			Status:       string(scan.Status),
			Phases:       database.MarshalPhases(scan.Phases),
			CurrentPhase: scan.CurrentPhase,
			Progress:     scan.Progress,
			StartedAt:    scan.StartedAt,
			CompletedAt:  scan.CompletedAt,
			Duration:     scan.Duration,
			Error:        scan.Error,
			OutputDir:    scan.OutputDir,
		}
		if err := m.db.SaveScan(record); err != nil {
			log.Printf("[WARNING] Failed to save scan completion to database: %v", err)
		}

		// Save vulnerabilities to database if scan completed successfully
		if scan.Status == StatusCompleted {
			m.saveVulnerabilitiesToDB(scan.ID, scan.OutputDir, scan.Target)
		}
	}
	m.mu.Unlock()

	close(progressCh)

	// Broadcast scan completed/stopped/failed
	eventType := "scan_completed"
	if scan.Status == StatusCancelled {
		eventType = "scan_stopped"
	} else if scan.Status == StatusFailed {
		eventType = "scan_failed"
	}
	m.broadcastScanUpdate(eventType, scan)
}

// broadcastScanUpdate sends scan updates to WebSocket clients
func (m *ScanManager) broadcastScanUpdate(eventType string, scan *Scan) {
	if m.wsHub == nil {
		return
	}

	m.mu.RLock()
	scanData := map[string]interface{}{
		"id":            scan.ID,
		"target":        scan.Target,
		"status":        scan.Status,
		"progress":      scan.Progress,
		"current_phase": scan.CurrentPhase,
		"started_at":    scan.StartedAt,
	}
	if scan.CompletedAt != nil {
		scanData["completed_at"] = scan.CompletedAt
		scanData["duration"] = scan.Duration
	}
	if scan.Error != "" {
		scanData["error"] = scan.Error
	}
	m.mu.RUnlock()

	m.wsHub.BroadcastToScan(scan.ID, WebSocketMessage{
		Type: eventType,
		Data: scanData,
	})
}

// saveVulnerabilitiesToDB reads vulnerability results and saves them to the database
func (m *ScanManager) saveVulnerabilitiesToDB(scanID, outputDir, target string) {
	// The runner creates an additional target directory inside OutputDir
	scanResultsDir := filepath.Join(outputDir, target)
	vulnPath := filepath.Join(scanResultsDir, "8-vulnscan", "vulnerabilities.json")

	data, err := os.ReadFile(vulnPath)
	if err != nil {
		log.Printf("[INFO] No vulnerabilities file found for scan %s: %v", scanID, err)
		return
	}

	var vulnResult vulnscan.Result
	if err := json.Unmarshal(data, &vulnResult); err != nil {
		log.Printf("[WARNING] Failed to parse vulnerabilities for scan %s: %v", scanID, err)
		return
	}

	savedCount := 0
	for _, v := range vulnResult.Vulnerabilities {
		// Generate stable vulnerability ID based on scan, host, and template
		vulnID := database.GenerateVulnID(scanID, v.Host, v.TemplateID)

		record := &database.VulnerabilityRecord{
			ID:          vulnID,
			ScanID:      scanID,
			Host:        v.Host,
			URL:         v.URL,
			TemplateID:  v.TemplateID,
			Name:        v.Name,
			Severity:    v.Severity,
			Type:        v.Type,
			Description: v.Description,
			Tool:        v.Tool,
			CreatedAt:   time.Now(),
		}

		if err := m.db.SaveVulnerability(record); err != nil {
			log.Printf("[WARNING] Failed to save vulnerability %s: %v", vulnID, err)
		} else {
			savedCount++
		}
	}

	log.Printf("[INFO] Saved %d vulnerabilities for scan %s to database", savedCount, scanID)
}

// GetScan returns a scan by ID
func (m *ScanManager) GetScan(id string) (*Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scan, ok := m.scans[id]
	if !ok {
		return nil, fmt.Errorf("scan not found: %s", id)
	}

	return scan, nil
}

// ListScans returns all scans
func (m *ScanManager) ListScans() []*Scan {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scans := make([]*Scan, 0, len(m.scans))
	for _, scan := range m.scans {
		scans = append(scans, scan)
	}

	return scans
}

// StopScan cancels a running scan
func (m *ScanManager) StopScan(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scan, ok := m.scans[id]
	if !ok {
		return fmt.Errorf("scan not found: %s", id)
	}

	if scan.Status != StatusRunning && scan.Status != StatusPending && scan.Status != StatusPaused {
		return fmt.Errorf("scan is not running")
	}

	if scan.cancel != nil {
		scan.cancel()
	}

	// Immediately update status so UI sees the change
	scan.Status = StatusCancelled
	now := time.Now()
	scan.CompletedAt = &now
	scan.Duration = now.Sub(scan.StartedAt).Round(time.Second).String()

	// Update in database if available
	if m.db != nil {
		record := &database.ScanRecord{
			ID:           scan.ID,
			Target:       scan.Target,
			Status:       string(scan.Status),
			Phases:       database.MarshalPhases(scan.Phases),
			CurrentPhase: scan.CurrentPhase,
			Progress:     scan.Progress,
			OutputDir:    scan.OutputDir,
			StartedAt:    scan.StartedAt,
			CompletedAt:  scan.CompletedAt,
			Duration:     scan.Duration,
			Error:        scan.Error,
		}
		m.db.SaveScan(record)
	}

	return nil
}

// PauseScan pauses a running scan
func (m *ScanManager) PauseScan(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scan, ok := m.scans[id]
	if !ok {
		return fmt.Errorf("scan not found: %s", id)
	}

	if scan.Status != StatusRunning {
		return fmt.Errorf("scan is not running")
	}

	if scan.isPaused {
		return fmt.Errorf("scan is already paused")
	}

	// Signal pause
	select {
	case scan.pauseCh <- true:
		scan.isPaused = true
		scan.Status = StatusPaused
		now := time.Now()
		scan.pausedAt = &now

		// Update in database
		if m.db != nil {
			record := &database.ScanRecord{
				ID:           scan.ID,
				Target:       scan.Target,
				Status:       string(scan.Status),
				Phases:       database.MarshalPhases(scan.Phases),
				CurrentPhase: scan.CurrentPhase,
				Progress:     scan.Progress,
				OutputDir:    scan.OutputDir,
				StartedAt:    scan.StartedAt,
			}
			m.db.SaveScan(record)
		}

		// Broadcast pause event
		m.broadcastScanUpdate("scan_paused", scan)
		return nil
	default:
		return fmt.Errorf("failed to pause scan")
	}
}

// ResumeScan resumes a paused scan
func (m *ScanManager) ResumeScan(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scan, ok := m.scans[id]
	if !ok {
		return fmt.Errorf("scan not found: %s", id)
	}

	if scan.Status != StatusPaused {
		return fmt.Errorf("scan is not paused")
	}

	// Ensure isPaused is synced with Status (handles cases where scan was loaded from DB)
	if scan.Status == StatusPaused {
		scan.isPaused = true
	}

	// Signal resume
	select {
	case scan.resumeCh <- true:
		scan.isPaused = false
		scan.Status = StatusRunning
		scan.pausedAt = nil

		// Update in database
		if m.db != nil {
			record := &database.ScanRecord{
				ID:           scan.ID,
				Target:       scan.Target,
				Status:       string(scan.Status),
				Phases:       database.MarshalPhases(scan.Phases),
				CurrentPhase: scan.CurrentPhase,
				Progress:     scan.Progress,
				OutputDir:    scan.OutputDir,
				StartedAt:    scan.StartedAt,
			}
			m.db.SaveScan(record)
		}

		// Broadcast resume event
		m.broadcastScanUpdate("scan_resumed", scan)
		return nil
	default:
		return fmt.Errorf("failed to resume scan")
	}
}

// LoadFindings loads vulnerability findings from scan results
func (m *ScanManager) LoadFindings(scan *Scan) ([]Finding, error) {
	var findings []Finding

	// The runner creates an additional target directory inside OutputDir
	scanResultsDir := filepath.Join(scan.OutputDir, scan.Target)

	// Load vulnerabilities from vulnscan results
	vulnPath := filepath.Join(scanResultsDir, "8-vulnscan", "vulnerabilities.json")
	if data, err := os.ReadFile(vulnPath); err == nil {
		var vulnResult vulnscan.Result
		if json.Unmarshal(data, &vulnResult) == nil {
			for _, v := range vulnResult.Vulnerabilities {
				findings = append(findings, Finding{
					Severity:    v.Severity,
					Name:        v.Name,
					TemplateID:  v.TemplateID,
					Host:        v.Host,
					URL:         v.URL,
					Type:        v.Type,
					Tool:        v.Tool,
					Description: v.Description,
				})
			}
		}
	}

	// Load takeover vulnerabilities
	takeoverPath := filepath.Join(scanResultsDir, "4-takeover", "takeover.json")
	if data, err := os.ReadFile(takeoverPath); err == nil {
		var takeoverResult takeover.Result
		if json.Unmarshal(data, &takeoverResult) == nil {
			for _, t := range takeoverResult.Vulnerable {
				findings = append(findings, Finding{
					Severity:    "critical",
					Name:        "Subdomain Takeover",
					Host:        t.Subdomain,
					Type:        "takeover",
					Tool:        "dnstake",
					Description: fmt.Sprintf("Subdomain vulnerable to takeover via %s", t.Service),
				})
			}
		}
	}

	return findings, nil
}

// LoadReport loads full report data from scan results
func (m *ScanManager) LoadReport(scan *Scan) (*report.Data, error) {
	if m.baseConfig.Debug {
		log.Printf("[DEBUG] LoadReport called for scan %s", scan.ID)
		log.Printf("[DEBUG] Scan.OutputDir = %s", scan.OutputDir)
		log.Printf("[DEBUG] Scan.Target = %s", scan.Target)
	}

	data := &report.Data{
		Target:  scan.Target,
		Version: version.Version,
		Date:    scan.StartedAt.Format(time.RFC1123),
	}

	// The runner creates an additional target directory inside OutputDir
	// So actual files are at: OutputDir/Target/phase-dirs/files.json
	scanResultsDir := filepath.Join(scan.OutputDir, scan.Target)
	if m.baseConfig.Debug {
		log.Printf("[DEBUG] scanResultsDir = %s", scanResultsDir)
	}

	// Load subdomain results
	subdomainPath := filepath.Join(scanResultsDir, "1-subdomains", "subdomains.json")
	if m.baseConfig.Debug {
		log.Printf("[DEBUG] Loading subdomains from: %s", subdomainPath)
	}
	if d := loadJSON[subdomain.Result](subdomainPath, m.baseConfig.Debug); d != nil {
		data.Subdomain = d
		if m.baseConfig.Debug {
			log.Printf("[DEBUG] Loaded %d subdomains", len(d.Subdomains))
		}
	} else {
		if m.baseConfig.Debug {
			log.Printf("[DEBUG] Failed to load subdomains from %s", subdomainPath)
		}
	}

	// Load WAF results
	if d := loadJSON[waf.Result](filepath.Join(scanResultsDir, "2-waf", "waf_detection.json"), m.baseConfig.Debug); d != nil {
		data.WAF = d
	}

	// Load port results
	if d := loadJSON[portscan.Result](filepath.Join(scanResultsDir, "3-ports", "port_scan.json"), m.baseConfig.Debug); d != nil {
		data.Ports = d
	}

	// Load takeover results
	if d := loadJSON[takeover.Result](filepath.Join(scanResultsDir, "4-takeover", "takeover.json"), m.baseConfig.Debug); d != nil {
		data.Takeover = d
	}

	// Load historic results
	if d := loadJSON[historic.Result](filepath.Join(scanResultsDir, "5-historic", "historic_urls.json"), m.baseConfig.Debug); d != nil {
		data.Historic = d
	}

	// Load tech results
	if d := loadJSON[techdetect.Result](filepath.Join(scanResultsDir, "6-tech", "tech_detection.json"), m.baseConfig.Debug); d != nil {
		data.Tech = d
	}

	// Load security headers results
	if d := loadJSON[secheaders.Result](filepath.Join(scanResultsDir, "6b-secheaders", "security_headers.json"), m.baseConfig.Debug); d != nil {
		data.SecHeaders = d
	}

	// Load dirbrute results
	if d := loadJSON[dirbrute.Result](filepath.Join(scanResultsDir, "7-dirbrute", "dirbrute.json"), m.baseConfig.Debug); d != nil {
		data.DirBrute = d
	}

	// Load JS analysis results
	if d := loadJSON[jsanalysis.Result](filepath.Join(scanResultsDir, "7b-jsanalysis", "js_analysis.json"), m.baseConfig.Debug); d != nil {
		data.JSAnalysis = d
	}

	// Load vulnscan results
	if d := loadJSON[vulnscan.Result](filepath.Join(scanResultsDir, "8-vulnscan", "vulnerabilities.json"), m.baseConfig.Debug); d != nil {
		data.VulnScan = d
	}

	// Load AI-guided results
	if d := loadJSON[aiguided.Result](filepath.Join(scanResultsDir, "10-aiguided", "ai_guided.json"), m.baseConfig.Debug); d != nil {
		data.AIGuided = d
	}

	// Load screenshot results (try both paths for compatibility)
	if d := loadJSON[screenshot.Result](filepath.Join(scanResultsDir, "9-screenshots", "screenshot_results.json"), m.baseConfig.Debug); d != nil {
		data.Screenshot = d
	} else if d := loadJSON[screenshot.Result](filepath.Join(scanResultsDir, "screenshots", "screenshot_clusters.json"), m.baseConfig.Debug); d != nil {
		// Legacy path fallback
		data.Screenshot = d
	}

	// Load IP range results
	if d := loadJSON[iprange.Result](filepath.Join(scanResultsDir, "0-iprange", "ip_discovery.json"), m.baseConfig.Debug); d != nil {
		data.IPRange = d
	}

	// Update AI summary with accurate vulnerability counts (same fix as HTML report)
	updateAISummaryWithVulnCounts(data)

	return data, nil
}

// updateAISummaryWithVulnCounts updates the AI Summary with accurate vulnerability counts
// This ensures the web dashboard displays the same accurate counts as the HTML report
func updateAISummaryWithVulnCounts(data *report.Data) {
	// Skip if no AI summary or no vulnscan results
	if data.AIGuided == nil || data.AIGuided.ExecutiveSummary == nil {
		return
	}
	if data.VulnScan == nil || len(data.VulnScan.Vulnerabilities) == 0 {
		return
	}

	// Count vulnerabilities by severity from VulnScan
	critCount := data.VulnScan.BySeverity["critical"]
	highCount := data.VulnScan.BySeverity["high"]
	medCount := data.VulnScan.BySeverity["medium"]
	lowCount := data.VulnScan.BySeverity["low"]

	// Update OneLiner with accurate counts
	target := data.Target
	if critCount > 0 || highCount > 0 {
		data.AIGuided.ExecutiveSummary.OneLiner = fmt.Sprintf("%s requires attention: %d critical, %d high, %d medium, %d low severity issues identified.",
			target, critCount, highCount, medCount, lowCount)
	} else if medCount > 0 || lowCount > 0 {
		data.AIGuided.ExecutiveSummary.OneLiner = fmt.Sprintf("%s has %d medium and %d low severity issues to review.",
			target, medCount, lowCount)
	}

	// Update KeyFindings with accurate counts
	var findings []string
	if critCount > 0 {
		findings = append(findings, fmt.Sprintf("%d critical vulnerabilities require immediate attention", critCount))
	}
	if highCount > 0 {
		findings = append(findings, fmt.Sprintf("%d high severity issues detected", highCount))
	}
	if medCount > 0 {
		findings = append(findings, fmt.Sprintf("%d medium severity issues detected", medCount))
	}
	if lowCount > 0 {
		findings = append(findings, fmt.Sprintf("%d low severity issues detected", lowCount))
	}

	// Preserve non-count findings from original AI summary (tech stack, security headers, etc.)
	for _, f := range data.AIGuided.ExecutiveSummary.KeyFindings {
		if strings.Contains(f, "Technology stack") || strings.Contains(f, "security headers") ||
			strings.Contains(f, "hosts directly accessible") || strings.Contains(f, "indicators detected") {
			findings = append(findings, f)
		}
	}

	if len(findings) > 0 {
		data.AIGuided.ExecutiveSummary.KeyFindings = findings
	}

	// Update risk assessment based on actual counts
	if critCount > 0 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("CRITICAL - %d critical and %d high severity vulnerabilities require immediate attention", critCount, highCount)
	} else if highCount > 3 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("HIGH - %d high severity vulnerabilities detected, prioritize remediation", highCount)
	} else if highCount > 0 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("MEDIUM - %d high severity vulnerabilities detected", highCount)
	} else if medCount > 0 {
		data.AIGuided.ExecutiveSummary.RiskAssessment = fmt.Sprintf("LOW - %d medium severity issues to address", medCount)
	}
}

// GetStats returns overall statistics
func (m *ScanManager) GetStats() map[string]interface{} {
	// Try to get stats from database first (more accurate for persistence)
	if m.db != nil {
		if stats, err := m.db.GetStats(); err == nil {
			return stats
		}
	}

	// Fallback to in-memory calculation
	m.mu.RLock()
	defer m.mu.RUnlock()

	var running, completed, failed int
	for _, scan := range m.scans {
		switch scan.Status {
		case StatusRunning:
			running++
		case StatusCompleted:
			completed++
		case StatusFailed:
			failed++
		}
	}

	return map[string]interface{}{
		"total_scans":     len(m.scans),
		"running_scans":   running,
		"completed_scans": completed,
		"failed_scans":    failed,
	}
}

// loadJSON is a helper to load JSON files
func loadJSON[T any](path string, debug bool) *T {
	data, err := os.ReadFile(path)
	if err != nil {
		if debug {
			log.Printf("[DEBUG] loadJSON: Failed to read file %s: %v", path, err)
		}
		return nil
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		if debug {
			log.Printf("[DEBUG] loadJSON: Failed to unmarshal JSON from %s: %v", path, err)
		}
		return nil
	}

	if debug {
		log.Printf("[DEBUG] loadJSON: Successfully loaded %s", path)
	}
	return &result
}
