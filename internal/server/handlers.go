package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rootsploit/reconator/internal/database"
	"github.com/rootsploit/reconator/internal/export"
	"github.com/rootsploit/reconator/internal/report"
	"github.com/rootsploit/reconator/internal/version"
)

// sanitizeFilename removes path separators and control characters from filenames
// to prevent path traversal attacks in export functionality
func sanitizeFilename(filename string) string {
	// Remove path separators
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "..", "_")

	// Remove control characters and potentially dangerous characters
	var sb strings.Builder
	for _, r := range filename {
		// Skip control characters (0-31, 127)
		if r < 32 || r == 127 {
			continue
		}
		// Skip potentially dangerous characters
		if r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			sb.WriteRune('_')
			continue
		}
		sb.WriteRune(r)
	}

	result := sb.String()

	// Limit length to prevent filesystem issues
	if len(result) > 200 {
		result = result[:200]
	}

	// Ensure we don't have an empty filename
	if result == "" {
		result = "scan"
	}

	return result
}

// healthCheck returns server health status
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// getVersion returns version information
func (s *Server) getVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version":   version.Version,
		"commit":    version.Commit,
		"buildDate": version.BuildDate,
	})
}

// StartScanRequest represents the request body for starting a scan
type StartScanRequest struct {
	Target      string   `json:"target" binding:"required"`
	Phases      []string `json:"phases,omitempty"`
	Threads     int      `json:"threads,omitempty"`
	DeepScan    bool     `json:"deep_scan,omitempty"`
	PassiveMode bool     `json:"passive_mode,omitempty"`
}

// startScan initiates a new scan
func (s *Server) startScan(c *gin.Context) {
	var req StartScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate target (basic validation)
	target := strings.TrimSpace(req.Target)
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Target is required",
		})
		return
	}

	// Sanitize target - prevent command injection
	if strings.ContainsAny(target, ";|&$`\\\"'<>") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid characters in target",
		})
		return
	}

	// Create scan
	scan, err := s.scanMgr.StartScan(target, req.Phases, req.Threads, req.DeepScan, req.PassiveMode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start scan: " + err.Error(),
		})
		return
	}

	// Notify WebSocket clients
	s.wsHub.Broadcast(WebSocketMessage{
		Type: "scan_started",
		Data: scan,
	})

	c.JSON(http.StatusCreated, gin.H{
		"id":      scan.ID,
		"target":  scan.Target,
		"status":  scan.Status,
		"message": "Scan started successfully",
	})
}

// listScans returns all scans
func (s *Server) listScans(c *gin.Context) {
	scans := s.scanMgr.ListScans()
	log.Printf("[DEBUG] listScans handler called - returning %d scans", len(scans))
	for i, scan := range scans {
		log.Printf("[DEBUG] Scan %d: ID=%s, Target=%s, Status=%s", i, scan.ID, scan.Target, scan.Status)
	}
	c.JSON(http.StatusOK, gin.H{
		"scans": scans,
		"total": len(scans),
	})
}

// getScan returns a specific scan by ID
func (s *Server) getScan(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// getScanStatus returns the current status of a scan
func (s *Server) getScanStatus(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           scan.ID,
		"status":       scan.Status,
		"phase":        scan.CurrentPhase,
		"progress":     scan.Progress,
		"started_at":   scan.StartedAt,
		"completed_at": scan.CompletedAt,
		"duration":     scan.Duration,
		"error":        scan.Error,
	})
}

// stopScan cancels a running scan
func (s *Server) stopScan(c *gin.Context) {
	id := c.Param("id")

	if err := s.scanMgr.StopScan(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Notify WebSocket clients
	s.wsHub.Broadcast(WebSocketMessage{
		Type: "scan_stopped",
		Data: gin.H{"id": id},
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "Scan stopped successfully",
	})
}

// getScanFindings returns vulnerabilities found in a scan with optional filtering
func (s *Server) getScanFindings(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	// Check if database is available for filtering
	if s.scanMgr.db != nil {
		// Parse filter parameters
		filters := database.VulnFilters{
			IncludeFP: c.Query("include_fp") == "true",
		}

		// Parse severities (comma-separated or multiple query params)
		if sevs := c.QueryArray("severity"); len(sevs) > 0 {
			filters.Severities = sevs
		} else if sev := c.Query("severity"); sev != "" {
			filters.Severities = strings.Split(sev, ",")
		}

		// Parse types (comma-separated or multiple query params)
		if types := c.QueryArray("type"); len(types) > 0 {
			filters.Types = types
		} else if typ := c.Query("type"); typ != "" {
			filters.Types = strings.Split(typ, ",")
		}

		// Parse host filter
		filters.Host = c.Query("host")

		// Parse search text
		filters.SearchText = c.Query("search")

		// Get filtered vulnerabilities from database
		log.Printf("[DEBUG] getScanFindings - calling GetFilteredVulnerabilities for scan %s with filters: %+v", id, filters)
		vulns, err := s.scanMgr.db.GetFilteredVulnerabilities(id, filters)
		if err != nil {
			log.Printf("[ERROR] getScanFindings - GetFilteredVulnerabilities failed for scan %s: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to load findings: " + err.Error(),
			})
			return
		}
		log.Printf("[DEBUG] getScanFindings - loaded %d vulnerabilities for scan %s", len(vulns), id)

		// Convert to Finding format
		findings := make([]Finding, 0, len(vulns))
		for _, vuln := range vulns {
			findings = append(findings, Finding{
				Severity:    vuln.Severity,
				Name:        vuln.Name,
				TemplateID:  vuln.TemplateID,
				Host:        vuln.Host,
				URL:         vuln.URL,
				Type:        vuln.Type,
				Tool:        vuln.Tool,
				Description: vuln.Description,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"scan_id":  id,
			"findings": findings,
			"total":    len(findings),
		})
		return
	}

	// Fallback: Load findings from scan results directory (legacy)
	findings, err := s.scanMgr.LoadFindings(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load findings: " + err.Error(),
		})
		return
	}

	// Apply simple filters (for backward compatibility)
	severity := c.Query("severity")
	vulnType := c.Query("type")

	filtered := findings
	if severity != "" {
		filtered = filterBySeverity(filtered, severity)
	}
	if vulnType != "" {
		filtered = filterByType(filtered, vulnType)
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  id,
		"findings": filtered,
		"total":    len(filtered),
	})
}

// getScanReport returns the full report for a scan
func (s *Server) getScanReport(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	// Load full report data
	reportData, err := s.scanMgr.LoadReport(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load report: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, reportData)
}

// exportCSV exports scan results to CSV and downloads directly
func (s *Server) exportCSV(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	reportData, err := s.scanMgr.LoadReport(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load report"})
		return
	}

	exporter := export.NewExporter(reportData, scan.OutputDir)
	content, err := exporter.GenerateCSVContent()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed: " + err.Error()})
		return
	}

	// Generate filename with scan ID and timestamp for uniqueness
	timestamp := scan.StartedAt.Format("20060102-150405") // YYYYMMDD-HHMMSS format
	safeTarget := sanitizeFilename(scan.Target)
	filename := fmt.Sprintf("reconator_%s_%s_%s.csv", safeTarget, scan.ID, timestamp)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", "text/csv")
	c.Data(http.StatusOK, "text/csv", content)
}

// exportJSON exports scan results to JSON and downloads directly
func (s *Server) exportJSON(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	reportData, err := s.scanMgr.LoadReport(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load report"})
		return
	}

	exporter := export.NewExporter(reportData, scan.OutputDir)
	content, err := exporter.GenerateJSONContent()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed: " + err.Error()})
		return
	}

	// Generate filename with scan ID and timestamp for uniqueness
	timestamp := scan.StartedAt.Format("20060102-150405") // YYYYMMDD-HHMMSS format
	safeTarget := sanitizeFilename(scan.Target)
	filename := fmt.Sprintf("reconator_%s_%s_%s.json", safeTarget, scan.ID, timestamp)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", "application/json")
	c.Data(http.StatusOK, "application/json", content)
}

// exportSARIF exports scan results to SARIF format and downloads directly
func (s *Server) exportSARIF(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	reportData, err := s.scanMgr.LoadReport(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load report"})
		return
	}

	exporter := export.NewExporter(reportData, scan.OutputDir)
	content, err := exporter.GenerateSARIFContent()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed: " + err.Error()})
		return
	}

	// Generate filename with scan ID and timestamp for uniqueness
	timestamp := scan.StartedAt.Format("20060102-150405") // YYYYMMDD-HHMMSS format
	safeTarget := sanitizeFilename(scan.Target)
	filename := fmt.Sprintf("reconator_%s_%s_%s.sarif", safeTarget, scan.ID, timestamp)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", "application/json")
	c.Data(http.StatusOK, "application/json", content)
}

// exportHTML exports scan results to HTML format and downloads directly
func (s *Server) exportHTML(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.scanMgr.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	reportData, err := s.scanMgr.LoadReport(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load report"})
		return
	}

	// Generate HTML report to temporary directory
	tmpDir := filepath.Join(os.TempDir(), "reconator-html-"+id)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tmpDir)

	// Generate HTML report
	if err := report.Generate(reportData, tmpDir); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed: " + err.Error()})
		return
	}

	// Sanitize target name for safe filesystem operations
	safeTarget := sanitizeFilename(scan.Target)
	htmlFilename := fmt.Sprintf("report_%s.html", safeTarget)
	htmlPath := filepath.Join(tmpDir, htmlFilename)

	// Verify path is within tmpDir (defense in depth)
	cleanPath := filepath.Clean(htmlPath)
	cleanTmpDir := filepath.Clean(tmpDir)
	if !strings.HasPrefix(cleanPath, cleanTmpDir) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid file path"})
		return
	}

	// Read generated HTML file
	content, err := os.ReadFile(htmlPath)
	if err != nil {
		// Try with generic filename as fallback
		htmlPath = filepath.Join(tmpDir, "report.html")
		content, err = os.ReadFile(htmlPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read HTML file"})
			return
		}
	}

	// Generate safe download filename with timestamp
	timestamp := scan.StartedAt.Format("20060102-150405")
	filename := fmt.Sprintf("reconator_%s_%s_%s.html", safeTarget, scan.ID, timestamp)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Data(http.StatusOK, "text/html", content)
}

// getStats returns overall statistics
func (s *Server) getStats(c *gin.Context) {
	stats := s.scanMgr.GetStats()
	c.JSON(http.StatusOK, stats)
}

// Finding represents a vulnerability finding
type Finding struct {
	Severity    string `json:"severity"`
	Name        string `json:"name"`
	TemplateID  string `json:"template_id,omitempty"`
	Host        string `json:"host,omitempty"`
	URL         string `json:"url,omitempty"`
	Type        string `json:"type"`
	Tool        string `json:"tool"`
	Description string `json:"description,omitempty"`
}

// Helper to filter findings by severity
func filterBySeverity(findings []Finding, severity string) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if strings.EqualFold(f.Severity, severity) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// Helper to filter findings by type
func filterByType(findings []Finding, vulnType string) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if strings.EqualFold(f.Type, vulnType) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// markVulnAsFalsePositive marks a vulnerability as false positive
func (s *Server) markVulnAsFalsePositive(c *gin.Context) {
	vulnID := c.Param("id")
	if vulnID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Vulnerability ID required"})
		return
	}

	var req struct {
		Reason   string `json:"reason"`
		MarkedBy string `json:"marked_by"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if s.scanMgr.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}

	if err := s.scanMgr.db.MarkAsFalsePositive(vulnID, req.Reason, req.MarkedBy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Marked as false positive"})
}

// unmarkVulnAsFalsePositive removes false positive marking
func (s *Server) unmarkVulnAsFalsePositive(c *gin.Context) {
	vulnID := c.Param("id")
	if vulnID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Vulnerability ID required"})
		return
	}

	if s.scanMgr.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}

	if err := s.scanMgr.db.UnmarkFalsePositive(vulnID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "False positive marking removed"})
}

// addVulnNote adds or updates a note for a vulnerability
func (s *Server) addVulnNote(c *gin.Context) {
	vulnID := c.Param("id")
	if vulnID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Vulnerability ID required"})
		return
	}

	var req struct {
		Note string `json:"note"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if s.scanMgr.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}

	if err := s.scanMgr.db.AddVulnNote(vulnID, req.Note); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Note added"})
}

// Placeholder report loading (used by handlers)
func loadReportPlaceholder() *report.Data {
	return &report.Data{}
}
