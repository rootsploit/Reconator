package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database connection
type DB struct {
	conn *sql.DB
}

// ScanRecord represents a scan stored in the database
type ScanRecord struct {
	ID           string
	Target       string
	Status       string
	Phases       string // JSON array
	CurrentPhase string
	Progress     int
	StartedAt    time.Time
	CompletedAt  *time.Time
	Duration     string
	Error        string
	OutputDir    string
}

// New creates a new database connection
func New(dbPath string) (*DB, error) {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		// Directory creation would happen here in production
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &DB{conn: conn}

	// Initialize schema
	if err := db.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Apply migrations for backward compatibility
	if err := db.applyMigrations(); err != nil {
		return nil, fmt.Errorf("failed to apply migrations: %w", err)
	}

	return db, nil
}

// initSchema creates the database tables
func (db *DB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		status TEXT NOT NULL,
		phases TEXT,
		current_phase TEXT,
		progress INTEGER DEFAULT 0,
		started_at DATETIME NOT NULL,
		completed_at DATETIME,
		duration TEXT,
		error TEXT,
		output_dir TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		url TEXT,
		template_id TEXT NOT NULL,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		type TEXT,
		description TEXT,
		tool TEXT,
		is_false_positive INTEGER DEFAULT 0,
		fp_reason TEXT,
		notes TEXT,
		marked_at DATETIME,
		marked_by TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_vulns_is_fp ON vulnerabilities(is_false_positive);
	CREATE INDEX IF NOT EXISTS idx_vulns_template_id ON vulnerabilities(template_id);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// applyMigrations handles schema updates for existing databases
func (db *DB) applyMigrations() error {
	// Check if started_at column exists in scans table
	var count int
	err := db.conn.QueryRow("SELECT count(*) FROM pragma_table_info('scans') WHERE name='started_at'").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		// Add started_at column if it's missing (happens when upgrading from older versions)
		_, err = db.conn.Exec("ALTER TABLE scans ADD COLUMN started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP")
		if err != nil {
			return fmt.Errorf("failed to add started_at column: %w", err)
		}
	}

	return nil
}

// SaveScan saves or updates a scan in the database
func (db *DB) SaveScan(scan *ScanRecord) error {
	query := `
	INSERT INTO scans (id, target, status, phases, current_phase, progress, started_at, completed_at, duration, error, output_dir, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		current_phase = excluded.current_phase,
		progress = excluded.progress,
		completed_at = excluded.completed_at,
		duration = excluded.duration,
		error = excluded.error,
		updated_at = CURRENT_TIMESTAMP
	`

	_, err := db.conn.Exec(query,
		scan.ID,
		scan.Target,
		scan.Status,
		scan.Phases,
		scan.CurrentPhase,
		scan.Progress,
		scan.StartedAt,
		scan.CompletedAt,
		scan.Duration,
		scan.Error,
		scan.OutputDir,
	)

	return err
}

// GetScan retrieves a scan by ID
func (db *DB) GetScan(id string) (*ScanRecord, error) {
	query := `
	SELECT id, target, status, phases, current_phase, progress, started_at, completed_at, duration, error, output_dir
	FROM scans
	WHERE id = ?
	`

	var scan ScanRecord
	var completedAt sql.NullTime

	err := db.conn.QueryRow(query, id).Scan(
		&scan.ID,
		&scan.Target,
		&scan.Status,
		&scan.Phases,
		&scan.CurrentPhase,
		&scan.Progress,
		&scan.StartedAt,
		&completedAt,
		&scan.Duration,
		&scan.Error,
		&scan.OutputDir,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", id)
	}
	if err != nil {
		return nil, err
	}

	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	return &scan, nil
}

// ListScans retrieves all scans, ordered by start time (newest first)
func (db *DB) ListScans() ([]*ScanRecord, error) {
	query := `
	SELECT id, target, status, phases, current_phase, progress, started_at, completed_at, duration, error, output_dir
	FROM scans
	ORDER BY started_at DESC
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		fmt.Printf("[DEBUG] ListScans query error: %v\n", err)
		return nil, err
	}
	defer rows.Close()

	var scans []*ScanRecord
	rowCount := 0
	for rows.Next() {
		rowCount++
		var scan ScanRecord
		var completedAt sql.NullTime
		var currentPhase, duration, errorMsg sql.NullString

		err := rows.Scan(
			&scan.ID,
			&scan.Target,
			&scan.Status,
			&scan.Phases,
			&currentPhase,
			&scan.Progress,
			&scan.StartedAt,
			&completedAt,
			&duration,
			&errorMsg,
			&scan.OutputDir,
		)
		if err != nil {
			fmt.Printf("[DEBUG] ListScans row scan error: %v\n", err)
			return nil, err
		}

		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}
		if currentPhase.Valid {
			scan.CurrentPhase = currentPhase.String
		}
		if duration.Valid {
			scan.Duration = duration.String
		}
		if errorMsg.Valid {
			scan.Error = errorMsg.String
		}

		fmt.Printf("[DEBUG] ListScans found scan: ID=%s, Target=%s, OutputDir=%s\n",
			scan.ID, scan.Target, scan.OutputDir)
		scans = append(scans, &scan)
	}

	fmt.Printf("[DEBUG] ListScans processed %d rows, returning %d scans\n", rowCount, len(scans))
	return scans, rows.Err()
}

// DeleteScan removes a scan from the database
func (db *DB) DeleteScan(id string) error {
	query := `DELETE FROM scans WHERE id = ?`
	_, err := db.conn.Exec(query, id)
	return err
}

// GetStats returns aggregate statistics about scans
func (db *DB) GetStats() (map[string]interface{}, error) {
	query := `
	SELECT
		COUNT(*) as total,
		SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
		SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
		SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
		SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled
	FROM scans
	`

	var total, running, completed, failed, cancelled int
	err := db.conn.QueryRow(query).Scan(&total, &running, &completed, &failed, &cancelled)
	if err != nil {
		return nil, err
	}

	// Get vulnerability counts by severity
	vulnQuery := `
	SELECT
		COUNT(*) as total_vulns,
		SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
		SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) as high,
		SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) as medium,
		SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as low,
		SUM(CASE WHEN LOWER(severity) IN ('info', 'informational', 'informative') THEN 1 ELSE 0 END) as info
	FROM vulnerabilities
	WHERE is_false_positive = 0
	`

	var totalVulns, critical, high, medium, low, info int
	err = db.conn.QueryRow(vulnQuery).Scan(&totalVulns, &critical, &high, &medium, &low, &info)
	if err != nil {
		// If error (e.g., no vulnerabilities table), just continue without vuln stats
		totalVulns, critical, high, medium, low, info = 0, 0, 0, 0, 0, 0
	}

	return map[string]interface{}{
		"total_scans":     total,
		"running_scans":   running,
		"completed_scans": completed,
		"failed_scans":    failed,
		"cancelled_scans": cancelled,
		"total_vulns":     totalVulns,
		"vuln_critical":   critical,
		"vuln_high":       high,
		"vuln_medium":     medium,
		"vuln_low":        low,
		"vuln_info":       info,
	}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// GenerateVulnID creates a stable vulnerability ID from scan metadata
// Format: hash(scan_id + host + template_id) for consistent tracking
func GenerateVulnID(scanID, host, templateID string) string {
	data := scanID + "|" + host + "|" + templateID
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("vuln-%x", hash[:8]) // Use first 8 bytes for shorter ID
}

// Helper functions for JSON marshaling/unmarshaling

// MarshalPhases converts a slice of strings to JSON
func MarshalPhases(phases []string) string {
	data, _ := json.Marshal(phases)
	return string(data)
}

// UnmarshalPhases converts JSON to a slice of strings
func UnmarshalPhases(data string) []string {
	var phases []string
	json.Unmarshal([]byte(data), &phases)
	return phases
}

// VulnerabilityRecord represents a vulnerability finding
type VulnerabilityRecord struct {
	ID              string
	ScanID          string
	Host            string
	URL             string
	TemplateID      string
	Name            string
	Severity        string
	Type            string
	Description     string
	Tool            string
	IsFalsePositive bool
	FPReason        string
	Notes           string
	MarkedAt        *time.Time
	MarkedBy        string
	CreatedAt       time.Time
}

// SaveVulnerability saves a vulnerability to the database
func (db *DB) SaveVulnerability(vuln *VulnerabilityRecord) error {
	query := `
	INSERT INTO vulnerabilities (id, scan_id, host, url, template_id, name, severity, type, description, tool, is_false_positive, fp_reason, notes, marked_at, marked_by)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		is_false_positive = excluded.is_false_positive,
		fp_reason = excluded.fp_reason,
		notes = excluded.notes,
		marked_at = excluded.marked_at,
		marked_by = excluded.marked_by
	`

	_, err := db.conn.Exec(query,
		vuln.ID,
		vuln.ScanID,
		vuln.Host,
		vuln.URL,
		vuln.TemplateID,
		vuln.Name,
		vuln.Severity,
		vuln.Type,
		vuln.Description,
		vuln.Tool,
		vuln.IsFalsePositive,
		vuln.FPReason,
		vuln.Notes,
		vuln.MarkedAt,
		vuln.MarkedBy,
	)

	return err
}

// MarkAsFalsePositive marks a vulnerability as false positive
func (db *DB) MarkAsFalsePositive(vulnID, reason, markedBy string) error {
	query := `
	UPDATE vulnerabilities
	SET is_false_positive = 1,
	    fp_reason = ?,
	    marked_at = CURRENT_TIMESTAMP,
	    marked_by = ?
	WHERE id = ?
	`

	_, err := db.conn.Exec(query, reason, markedBy, vulnID)
	return err
}

// UnmarkFalsePositive removes false positive marking
func (db *DB) UnmarkFalsePositive(vulnID string) error {
	query := `
	UPDATE vulnerabilities
	SET is_false_positive = 0,
	    fp_reason = NULL,
	    marked_at = NULL,
	    marked_by = NULL
	WHERE id = ?
	`

	_, err := db.conn.Exec(query, vulnID)
	return err
}

// AddVulnNote adds or updates a note for a vulnerability
func (db *DB) AddVulnNote(vulnID, note string) error {
	query := `UPDATE vulnerabilities SET notes = ? WHERE id = ?`
	_, err := db.conn.Exec(query, note, vulnID)
	return err
}

// GetVulnerabilitiesByScan retrieves all vulnerabilities for a scan
func (db *DB) GetVulnerabilitiesByScan(scanID string, includeFP bool) ([]*VulnerabilityRecord, error) {
	query := `
	SELECT id, scan_id, host, url, template_id, name, severity, type, description, tool, is_false_positive, fp_reason, notes, marked_at, marked_by, created_at
	FROM vulnerabilities
	WHERE scan_id = ?
	`

	if !includeFP {
		query += " AND is_false_positive = 0"
	}

	query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, name"

	rows, err := db.conn.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []*VulnerabilityRecord
	for rows.Next() {
		var vuln VulnerabilityRecord
		var markedAt sql.NullTime
		var vulnType, description, fpReason, notes, markedBy sql.NullString

		err := rows.Scan(
			&vuln.ID,
			&vuln.ScanID,
			&vuln.Host,
			&vuln.URL,
			&vuln.TemplateID,
			&vuln.Name,
			&vuln.Severity,
			&vulnType,
			&description,
			&vuln.Tool,
			&vuln.IsFalsePositive,
			&fpReason,
			&notes,
			&markedAt,
			&markedBy,
			&vuln.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Convert sql.NullString to string
		if vulnType.Valid {
			vuln.Type = vulnType.String
		}
		if description.Valid {
			vuln.Description = description.String
		}
		if fpReason.Valid {
			vuln.FPReason = fpReason.String
		}
		if notes.Valid {
			vuln.Notes = notes.String
		}
		if markedBy.Valid {
			vuln.MarkedBy = markedBy.String
		}
		if markedAt.Valid {
			vuln.MarkedAt = &markedAt.Time
		}

		vulns = append(vulns, &vuln)
	}

	return vulns, rows.Err()
}

// VulnFilters represents filters for vulnerability queries
type VulnFilters struct {
	Severities []string // critical, high, medium, low
	Types      []string // xss, sqli, etc
	Host       string   // hostname filter (partial match)
	SearchText string   // full-text search in name and description
	IncludeFP  bool     // include false positives
}

// GetFilteredVulnerabilities retrieves vulnerabilities with filters applied
func (db *DB) GetFilteredVulnerabilities(scanID string, filters VulnFilters) ([]*VulnerabilityRecord, error) {
	query := `
	SELECT id, scan_id, host, url, template_id, name, severity, type, description, tool, is_false_positive, fp_reason, notes, marked_at, marked_by, created_at
	FROM vulnerabilities
	WHERE scan_id = ?
	`
	args := []interface{}{scanID}

	// Filter by false positives
	if !filters.IncludeFP {
		query += " AND is_false_positive = 0"
	}

	// Filter by severities
	if len(filters.Severities) > 0 {
		placeholders := make([]string, len(filters.Severities))
		for i, sev := range filters.Severities {
			placeholders[i] = "?"
			args = append(args, sev)
		}
		query += fmt.Sprintf(" AND severity IN (%s)", strings.Join(placeholders, ","))
	}

	// Filter by types
	if len(filters.Types) > 0 {
		placeholders := make([]string, len(filters.Types))
		for i, typ := range filters.Types {
			placeholders[i] = "?"
			args = append(args, typ)
		}
		query += fmt.Sprintf(" AND type IN (%s)", strings.Join(placeholders, ","))
	}

	// Filter by host (partial match)
	if filters.Host != "" {
		query += " AND host LIKE ?"
		// Escape SQL LIKE wildcards to prevent wildcard injection
		escapedHost := strings.ReplaceAll(filters.Host, "%", "\\%")
		escapedHost = strings.ReplaceAll(escapedHost, "_", "\\_")
		args = append(args, "%"+escapedHost+"%")
	}

	// Full-text search in name and description
	if filters.SearchText != "" {
		query += " AND (name LIKE ? OR description LIKE ?)"
		// Escape SQL LIKE wildcards to prevent wildcard injection
		escapedText := strings.ReplaceAll(filters.SearchText, "%", "\\%")
		escapedText = strings.ReplaceAll(escapedText, "_", "\\_")
		searchPattern := "%" + escapedText + "%"
		args = append(args, searchPattern, searchPattern)
	}

	// Order by severity and name
	query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, name"

	fmt.Printf("[DEBUG] GetFilteredVulnerabilities - scanID: %s\n", scanID)
	fmt.Printf("[DEBUG] GetFilteredVulnerabilities - query: %s\n", query)
	fmt.Printf("[DEBUG] GetFilteredVulnerabilities - args: %v\n", args)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		fmt.Printf("[ERROR] GetFilteredVulnerabilities - SQL query failed: %v\n", err)
		return nil, err
	}
	defer rows.Close()

	var vulns []*VulnerabilityRecord
	for rows.Next() {
		var vuln VulnerabilityRecord
		var markedAt sql.NullTime
		var vulnType, description, fpReason, notes, markedBy sql.NullString

		err := rows.Scan(
			&vuln.ID,
			&vuln.ScanID,
			&vuln.Host,
			&vuln.URL,
			&vuln.TemplateID,
			&vuln.Name,
			&vuln.Severity,
			&vulnType,
			&description,
			&vuln.Tool,
			&vuln.IsFalsePositive,
			&fpReason,
			&notes,
			&markedAt,
			&markedBy,
			&vuln.CreatedAt,
		)
		if err != nil {
			fmt.Printf("[ERROR] GetFilteredVulnerabilities - rows.Scan failed: %v\n", err)
			return nil, err
		}

		// Convert sql.NullString to string
		if vulnType.Valid {
			vuln.Type = vulnType.String
		}
		if description.Valid {
			vuln.Description = description.String
		}
		if fpReason.Valid {
			vuln.FPReason = fpReason.String
		}
		if notes.Valid {
			vuln.Notes = notes.String
		}
		if markedBy.Valid {
			vuln.MarkedBy = markedBy.String
		}
		if markedAt.Valid {
			vuln.MarkedAt = &markedAt.Time
		}

		vulns = append(vulns, &vuln)
	}

	fmt.Printf("[DEBUG] GetFilteredVulnerabilities - successfully scanned %d vulnerabilities\n", len(vulns))
	return vulns, rows.Err()
}
