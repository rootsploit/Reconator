package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver (no CGO)
)

// SQLiteStorage implements Storage interface with SQLite backend
// Enables complex queries like "Show me all new subdomains found in the last 24h"
type SQLiteStorage struct {
	db      *sql.DB
	baseDir string
	dbPath  string
}

// NewSQLiteStorage creates a new SQLite storage instance
// dbPath can be ":memory:" for testing or a file path for persistence
// The database is created in the scan-specific directory (e.g., ~/reconator/a1b2c3d4_target/reconator.db)
// This ensures each scan has its own isolated database for easy pull/import operations
func NewSQLiteStorage(baseDir string) (*SQLiteStorage, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	// Expand home directory if present
	if strings.HasPrefix(baseDir, "~/") {
		home, _ := os.UserHomeDir()
		baseDir = filepath.Join(home, baseDir[2:])
	}

	// Database is always in the scan directory
	dbPath := filepath.Join(baseDir, "reconator.db")

	// Use modernc.org/sqlite (pure Go, no CGO)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	s := &SQLiteStorage{
		db:      db,
		baseDir: baseDir,
		dbPath:  dbPath,
	}

	// Initialize schema
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Run migrations to handle schema changes from older versions
	if err := s.migrateSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return s, nil
}

// initSchema creates all required tables
func (s *SQLiteStorage) initSchema() error {
	schema := `
	-- Scans table: stores scan metadata (unified schema for CLI and web server)
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		version TEXT,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		started_at DATETIME,
		completed_at DATETIME,
		status TEXT DEFAULT 'running',
		config_json TEXT,
		phases TEXT DEFAULT '["all"]',
		current_phase TEXT,
		progress INTEGER DEFAULT 0,
		output_dir TEXT,
		error TEXT,
		duration TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
	CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time);
	-- Note: idx_scans_started_at is created in migrateSchema() after ensuring column exists

	-- Subdomains table: stores discovered subdomains
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		is_alive INTEGER DEFAULT 0,
		ip_address TEXT,
		source TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, subdomain)
	);
	CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain);
	CREATE INDEX IF NOT EXISTS idx_subdomains_first_seen ON subdomains(first_seen);

	-- Ports table: stores open ports per host
	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		service TEXT,
		tls_info TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, host, port, protocol)
	);
	CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host);

	-- Vulnerabilities table: stores found vulnerabilities (unified schema for CLI and web server)
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		url TEXT,
		template_id TEXT,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		type TEXT,
		description TEXT,
		tool TEXT,
		evidence TEXT,
		is_false_positive INTEGER DEFAULT 0,
		fp_reason TEXT,
		notes TEXT,
		marked_at DATETIME,
		marked_by TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host);
	CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(type);

	-- Technologies table: stores detected technologies
	CREATE TABLE IF NOT EXISTS technologies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		technology TEXT NOT NULL,
		version TEXT,
		category TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, host, technology)
	);
	CREATE INDEX IF NOT EXISTS idx_tech_scan ON technologies(scan_id);
	CREATE INDEX IF NOT EXISTS idx_tech_technology ON technologies(technology);

	-- URLs table: stores historic URLs
	CREATE TABLE IF NOT EXISTS urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		url TEXT NOT NULL,
		source TEXT,
		category TEXT,
		status_code INTEGER,
		content_length INTEGER,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, url)
	);
	CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
	CREATE INDEX IF NOT EXISTS idx_urls_category ON urls(category);

	-- Screenshots table: stores screenshot metadata
	CREATE TABLE IF NOT EXISTS screenshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		url TEXT NOT NULL,
		file_path TEXT NOT NULL,
		perceptual_hash TEXT,
		cluster_id TEXT,
		cluster_name TEXT,
		captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, url)
	);
	CREATE INDEX IF NOT EXISTS idx_screenshots_scan ON screenshots(scan_id);
	CREATE INDEX IF NOT EXISTS idx_screenshots_cluster ON screenshots(cluster_id);

	-- WAF detections table
	CREATE TABLE IF NOT EXISTS waf_detections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		is_cdn INTEGER DEFAULT 0,
		waf_provider TEXT,
		cdn_provider TEXT,
		detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, host)
	);
	CREATE INDEX IF NOT EXISTS idx_waf_scan ON waf_detections(scan_id);

	-- Takeover vulnerabilities table
	CREATE TABLE IF NOT EXISTS takeover_vulns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		service TEXT,
		severity TEXT,
		cname TEXT,
		tool TEXT,
		is_false_positive INTEGER DEFAULT 0,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_takeover_scan ON takeover_vulns(scan_id);

	-- Security headers table: stores HTTP security header analysis
	CREATE TABLE IF NOT EXISTS security_headers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		url TEXT NOT NULL,
		score INTEGER DEFAULT 0,
		missing_headers TEXT,
		weak_headers TEXT,
		present_headers TEXT,
		headers_json TEXT,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, url)
	);
	CREATE INDEX IF NOT EXISTS idx_secheaders_scan ON security_headers(scan_id);
	CREATE INDEX IF NOT EXISTS idx_secheaders_host ON security_headers(host);
	CREATE INDEX IF NOT EXISTS idx_secheaders_score ON security_headers(score);

	-- AI summary table: stores AI-generated scan summaries and recommendations
	CREATE TABLE IF NOT EXISTS ai_summaries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		ai_provider TEXT,
		target_summary TEXT,
		risk_score INTEGER,
		recommended_tags TEXT,
		recommended_templates TEXT,
		vulnerabilities_json TEXT,
		action_items TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id)
	);
	CREATE INDEX IF NOT EXISTS idx_ai_summaries_scan ON ai_summaries(scan_id);

	-- JSAnalysis table: stores JavaScript analysis results
	CREATE TABLE IF NOT EXISTS js_analysis (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		source_url TEXT NOT NULL,
		endpoint TEXT,
		endpoint_type TEXT,
		dom_xss_sink TEXT,
		sink_type TEXT,
		severity TEXT,
		prototype_pollution TEXT,
		pollution_type TEXT,
		secret_type TEXT,
		secret_value TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_js_analysis_scan ON js_analysis(scan_id);
	CREATE INDEX IF NOT EXISTS idx_js_analysis_severity ON js_analysis(severity);

	-- TruffleHog table: stores secret scanning results
	CREATE TABLE IF NOT EXISTS secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		detector_type TEXT NOT NULL,
		detector_name TEXT NOT NULL,
		raw_secret TEXT,
		verified INTEGER DEFAULT 0,
		source_url TEXT,
		source_line INTEGER,
		severity TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_secrets_scan ON secrets(scan_id);
	CREATE INDEX IF NOT EXISTS idx_secrets_verified ON secrets(verified);
	CREATE INDEX IF NOT EXISTS idx_secrets_detector ON secrets(detector_name);

	-- Phase outputs table: stores raw JSON output for compatibility
	CREATE TABLE IF NOT EXISTS phase_outputs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		phase TEXT NOT NULL,
		path TEXT NOT NULL,
		data_json TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, path)
	);
	CREATE INDEX IF NOT EXISTS idx_phase_outputs_scan ON phase_outputs(scan_id);
	CREATE INDEX IF NOT EXISTS idx_phase_outputs_path ON phase_outputs(path);

	-- Phase status table: tracks completion status of each phase for resume support
	CREATE TABLE IF NOT EXISTS phase_status (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		phase TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		start_time DATETIME,
		end_time DATETIME,
		duration_ms INTEGER,
		error_message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, phase)
	);
	CREATE INDEX IF NOT EXISTS idx_phase_status_scan ON phase_status(scan_id);
	CREATE INDEX IF NOT EXISTS idx_phase_status_status ON phase_status(status);
	`

	_, err := s.db.Exec(schema)
	return err
}

// migrateSchema handles schema migrations from older versions
// This ensures backward compatibility with existing databases
func (s *SQLiteStorage) migrateSchema() error {
	// Check which columns exist in the scans table
	rows, err := s.db.Query("PRAGMA table_info(scans)")
	if err != nil {
		return fmt.Errorf("failed to get table info: %w", err)
	}
	defer rows.Close()

	existingColumns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, dfltValue, pk interface{}
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			continue
		}
		existingColumns[name] = true
	}

	// Define required columns for the unified schema
	// These columns were added to support both CLI and web server
	requiredColumns := map[string]string{
		"started_at":   "DATETIME",
		"completed_at": "DATETIME",
		"duration":     "TEXT",
		"phases":       "TEXT DEFAULT '[\"all\"]'",
		"progress":     "INTEGER DEFAULT 0",
		"output_dir":   "TEXT",
	}

	// Add missing columns
	for column, colType := range requiredColumns {
		if !existingColumns[column] {
			alterSQL := fmt.Sprintf("ALTER TABLE scans ADD COLUMN %s %s", column, colType)
			if _, err := s.db.Exec(alterSQL); err != nil {
				// Ignore "duplicate column" errors in case of race conditions
				if !strings.Contains(err.Error(), "duplicate") {
					return fmt.Errorf("failed to add column %s: %w", column, err)
				}
			}
		}
	}

	// Migrate existing data: populate started_at from start_time if needed
	updateSQL := `
		UPDATE scans
		SET started_at = start_time
		WHERE started_at IS NULL AND start_time IS NOT NULL
	`
	if _, err := s.db.Exec(updateSQL); err != nil {
		// Non-fatal - just log it
		fmt.Printf("Warning: failed to migrate started_at column: %v\n", err)
	}

	// Migrate existing data: populate completed_at from end_time if needed
	updateSQL = `
		UPDATE scans
		SET completed_at = end_time
		WHERE completed_at IS NULL AND end_time IS NOT NULL
	`
	if _, err := s.db.Exec(updateSQL); err != nil {
		// Non-fatal - just log it
		fmt.Printf("Warning: failed to migrate completed_at column: %v\n", err)
	}

	// Create indexes for new columns (after ensuring columns exist)
	if existingColumns["started_at"] {
		if _, err := s.db.Exec("CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at)"); err != nil {
			// Non-fatal
			fmt.Printf("Warning: failed to create started_at index: %v\n", err)
		}
	}

	// Migrate vulnerabilities table (add missing columns)
	if err := s.migrateVulnerabilitiesTable(); err != nil {
		// Non-fatal - just log it
		fmt.Printf("Warning: failed to migrate vulnerabilities table: %v\n", err)
	}

	return nil
}

// migrateVulnerabilitiesTable adds missing columns to vulnerabilities table
func (s *SQLiteStorage) migrateVulnerabilitiesTable() error {
	// Check which columns exist in vulnerabilities table
	rows, err := s.db.Query("PRAGMA table_info(vulnerabilities)")
	if err != nil {
		// Table doesn't exist yet, that's OK
		return nil
	}
	defer rows.Close()

	existingCols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, dfltValue, pk interface{}
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			continue
		}
		existingCols[name] = true
	}

	// Add missing columns to vulnerabilities table
	vulnColumns := map[string]string{
		"type":              "TEXT",
		"tool":              "TEXT",
		"evidence":          "TEXT",
		"is_false_positive": "INTEGER DEFAULT 0",
		"fp_reason":         "TEXT",
		"notes":             "TEXT",
		"marked_at":         "DATETIME",
		"marked_by":         "TEXT",
		"created_at":        "DATETIME DEFAULT CURRENT_TIMESTAMP",
	}

	for column, colType := range vulnColumns {
		if !existingCols[column] {
			alterSQL := fmt.Sprintf("ALTER TABLE vulnerabilities ADD COLUMN %s %s", column, colType)
			if _, err := s.db.Exec(alterSQL); err != nil {
				// Ignore duplicate column errors
				if !strings.Contains(err.Error(), "duplicate") {
					return fmt.Errorf("failed to add column %s: %w", column, err)
				}
			}
		}
	}

	// Create indexes for vulnerabilities if they don't exist
	if existingCols["type"] {
		s.db.Exec("CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(type)")
	}

	return nil
}

// BaseDir returns the root storage directory
func (s *SQLiteStorage) BaseDir() string {
	return s.baseDir
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Write stores data at the given path (also stores in phase_outputs table)
func (s *SQLiteStorage) Write(ctx context.Context, path string, data []byte) error {
	// Also write to filesystem for compatibility
	fullPath := filepath.Join(s.baseDir, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return err
	}

	// Extract scan_id and phase from path
	scanID, phase := s.extractScanIDAndPhase(path)

	// Store in database
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO phase_outputs (scan_id, phase, path, data_json)
		VALUES (?, ?, ?, ?)
	`, scanID, phase, path, string(data))

	return err
}

// WriteJSON stores data as formatted JSON
func (s *SQLiteStorage) WriteJSON(ctx context.Context, path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return s.Write(ctx, path, jsonData)
}

// Read retrieves data from the given path
func (s *SQLiteStorage) Read(ctx context.Context, path string) ([]byte, error) {
	// Try database first
	var data string
	err := s.db.QueryRowContext(ctx, `
		SELECT data_json FROM phase_outputs WHERE path = ?
	`, path).Scan(&data)

	if err == nil {
		return []byte(data), nil
	}

	// Fall back to filesystem
	fullPath := filepath.Join(s.baseDir, path)
	return os.ReadFile(fullPath)
}

// Exists checks if a path exists
func (s *SQLiteStorage) Exists(ctx context.Context, path string) (bool, error) {
	// Check database
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM phase_outputs WHERE path = ?
	`, path).Scan(&count)

	if err == nil && count > 0 {
		return true, nil
	}

	// Check filesystem
	fullPath := filepath.Join(s.baseDir, path)
	_, err = os.Stat(fullPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// List returns all files under a prefix
func (s *SQLiteStorage) List(ctx context.Context, prefix string) ([]string, error) {
	// Query database
	rows, err := s.db.QueryContext(ctx, `
		SELECT path FROM phase_outputs WHERE path LIKE ?
	`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			continue
		}
		files = append(files, path)
	}

	// Also check filesystem for any files not in DB
	fullPath := filepath.Join(s.baseDir, prefix)
	filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		relPath, _ := filepath.Rel(s.baseDir, path)
		// Check if already in list
		found := false
		for _, f := range files {
			if f == relPath {
				found = true
				break
			}
		}
		if !found {
			files = append(files, relPath)
		}
		return nil
	})

	return files, nil
}

// extractScanIDAndPhase extracts scan ID and phase from a path
func (s *SQLiteStorage) extractScanIDAndPhase(path string) (string, string) {
	parts := strings.Split(path, string(filepath.Separator))
	scanID := "unknown"
	phase := "unknown"

	if len(parts) > 0 {
		// Phase directory is usually first (e.g., "1-subdomains/...")
		phase = parts[0]
	}

	return scanID, phase
}

// =============================================================================
// Advanced Query Methods for Dashboard
// =============================================================================

// CreateScan creates a new scan record
func (s *SQLiteStorage) CreateScan(ctx context.Context, scanID, target, version string, config interface{}) error {
	configJSON, _ := json.Marshal(config)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (id, target, version, start_time, config_json)
		VALUES (?, ?, ?, ?, ?)
	`, scanID, target, version, time.Now(), string(configJSON))
	return err
}

// UpdateScanStatus updates scan status and end time
func (s *SQLiteStorage) UpdateScanStatus(ctx context.Context, scanID, status string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status = ?, end_time = ? WHERE id = ?
	`, status, time.Now(), scanID)
	return err
}

// CompleteScan marks a scan as completed with duration
func (s *SQLiteStorage) CompleteScan(ctx context.Context, scanID string, duration time.Duration) error {
	durationStr := duration.Round(time.Second).String()
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status = 'completed', end_time = ?, completed_at = ?, duration = ? WHERE id = ?
	`, time.Now(), time.Now(), durationStr, scanID)
	return err
}

// UpdateScanDuration updates the duration and completion time for an imported scan
func (s *SQLiteStorage) UpdateScanDuration(ctx context.Context, scanID string, durationStr string, endTime time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET duration = ?, end_time = ?, completed_at = ? WHERE id = ?
	`, durationStr, endTime, endTime, scanID)
	return err
}

// SaveSubdomains bulk inserts subdomains
func (s *SQLiteStorage) SaveSubdomains(ctx context.Context, scanID string, subdomains []string, isAlive map[string]bool, sources map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO subdomains (scan_id, subdomain, is_alive, source, last_seen)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, sub := range subdomains {
		alive := 0
		if isAlive[sub] {
			alive = 1
		}
		source := sources[sub]
		if _, err := stmt.ExecContext(ctx, scanID, sub, alive, source); err != nil {
			continue // Skip errors for individual inserts
		}
	}

	return tx.Commit()
}

// SavePorts bulk inserts ports
func (s *SQLiteStorage) SavePorts(ctx context.Context, scanID string, openPorts map[string][]int, tlsInfo map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO ports (scan_id, host, port, tls_info)
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for host, ports := range openPorts {
		tls := tlsInfo[host]
		for _, port := range ports {
			stmt.ExecContext(ctx, scanID, host, port, tls)
		}
	}

	return tx.Commit()
}

// SaveVulnerabilities bulk inserts vulnerabilities
func (s *SQLiteStorage) SaveVulnerabilities(ctx context.Context, scanID string, vulns []VulnerabilityRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities (scan_id, host, url, template_id, name, severity, type, tool, description, evidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, v := range vulns {
		stmt.ExecContext(ctx, scanID, v.Host, v.URL, v.TemplateID, v.Name, v.Severity, v.Type, v.Tool, v.Description, v.Evidence)
	}

	return tx.Commit()
}

// SaveTechnologies bulk inserts technologies
func (s *SQLiteStorage) SaveTechnologies(ctx context.Context, scanID string, techByHost map[string][]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO technologies (scan_id, host, technology)
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for host, techs := range techByHost {
		for _, tech := range techs {
			stmt.ExecContext(ctx, scanID, host, tech)
		}
	}

	return tx.Commit()
}

// SaveURLs bulk inserts URLs
func (s *SQLiteStorage) SaveURLs(ctx context.Context, scanID string, urls []string, sources map[string]string, categories map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO urls (scan_id, url, source, category)
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, url := range urls {
		source := sources[url]
		category := categories[url]
		stmt.ExecContext(ctx, scanID, url, source, category)
	}

	return tx.Commit()
}

// SaveScreenshots bulk inserts screenshots
func (s *SQLiteStorage) SaveScreenshots(ctx context.Context, scanID string, screenshots []ScreenshotRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO screenshots (scan_id, url, file_path, perceptual_hash, cluster_id, cluster_name)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ss := range screenshots {
		stmt.ExecContext(ctx, scanID, ss.URL, ss.FilePath, ss.Hash, ss.ClusterID, ss.ClusterName)
	}

	return tx.Commit()
}

// SaveSecurityHeaders bulk inserts security header analysis
func (s *SQLiteStorage) SaveSecurityHeaders(ctx context.Context, scanID string, headers []SecurityHeaderRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO security_headers (scan_id, host, url, score, missing_headers, weak_headers, present_headers, headers_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, h := range headers {
		missingJSON, _ := json.Marshal(h.MissingHeaders)
		weakJSON, _ := json.Marshal(h.WeakHeaders)
		presentJSON, _ := json.Marshal(h.PresentHeaders)

		stmt.ExecContext(ctx, scanID, h.Host, h.URL, h.Score, string(missingJSON), string(weakJSON), string(presentJSON), h.HeadersJSON)
	}

	return tx.Commit()
}

// SaveAISummary saves AI-generated scan summary and recommendations
func (s *SQLiteStorage) SaveAISummary(ctx context.Context, scanID string, summary AISummaryRecord) error {
	tagsJSON, _ := json.Marshal(summary.RecommendedTags)
	templatesJSON, _ := json.Marshal(summary.RecommendedTemplates)
	actionItemsJSON, _ := json.Marshal(summary.ActionItems)

	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO ai_summaries (scan_id, ai_provider, target_summary, risk_score, recommended_tags, recommended_templates, vulnerabilities_json, action_items)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, scanID, summary.AIProvider, summary.TargetSummary, summary.RiskScore, string(tagsJSON), string(templatesJSON), summary.VulnerabilitiesJSON, string(actionItemsJSON))

	return err
}

// SaveJSAnalysis saves JavaScript analysis results
func (s *SQLiteStorage) SaveJSAnalysis(ctx context.Context, scanID string, records []JSAnalysisRecord) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO js_analysis (scan_id, source_url, endpoint, endpoint_type, dom_xss_sink, sink_type, severity, prototype_pollution, pollution_type, secret_type, secret_value)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, record := range records {
		_, err := stmt.ExecContext(ctx, scanID, record.SourceURL, record.Endpoint, record.EndpointType, record.DOMXSSSink, record.SinkType, record.Severity, record.PrototypePollution, record.PollutionType, record.SecretType, record.SecretValue)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SaveSecrets saves TruffleHog secret scanning results
func (s *SQLiteStorage) SaveSecrets(ctx context.Context, scanID string, secrets []SecretRecord) error {
	if len(secrets) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO secrets (scan_id, detector_type, detector_name, raw_secret, verified, source_url, source_line, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, secret := range secrets {
		verified := 0
		if secret.Verified {
			verified = 1
		}
		_, err := stmt.ExecContext(ctx, scanID, secret.DetectorType, secret.DetectorName, secret.RawSecret, verified, secret.SourceURL, secret.SourceLine, secret.Severity)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// =============================================================================
// Query Methods for Dashboard
// =============================================================================

// GetNewSubdomains returns subdomains discovered in the last N hours
func (s *SQLiteStorage) GetNewSubdomains(ctx context.Context, target string, hours int) ([]SubdomainRecord, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	rows, err := s.db.QueryContext(ctx, `
		SELECT sd.subdomain, sd.is_alive, sd.ip_address, sd.source, sd.first_seen
		FROM subdomains sd
		JOIN scans sc ON sd.scan_id = sc.id
		WHERE sc.target = ? AND sd.first_seen >= ?
		ORDER BY sd.first_seen DESC
	`, target, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SubdomainRecord
	for rows.Next() {
		var r SubdomainRecord
		var alive int
		if err := rows.Scan(&r.Subdomain, &alive, &r.IPAddress, &r.Source, &r.FirstSeen); err != nil {
			continue
		}
		r.IsAlive = alive == 1
		results = append(results, r)
	}

	return results, nil
}

// GetVulnerabilitiesBySeverity returns vulnerabilities grouped by severity
func (s *SQLiteStorage) GetVulnerabilitiesBySeverity(ctx context.Context, target string, severity string) ([]VulnerabilityRecord, error) {
	query := `
		SELECT v.host, v.url, v.template_id, v.name, v.severity, v.tool, v.evidence, v.discovered_at
		FROM vulnerabilities v
		JOIN scans s ON v.scan_id = s.id
		WHERE s.target = ?
	`
	args := []interface{}{target}

	if severity != "" && severity != "all" {
		query += " AND v.severity = ?"
		args = append(args, severity)
	}

	query += " ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []VulnerabilityRecord
	for rows.Next() {
		var r VulnerabilityRecord
		if err := rows.Scan(&r.Host, &r.URL, &r.TemplateID, &r.Name, &r.Severity, &r.Tool, &r.Evidence, &r.DiscoveredAt); err != nil {
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

// GetScanSummary returns a summary of a specific scan
func (s *SQLiteStorage) GetScanSummary(ctx context.Context, scanID string) (*ScanSummary, error) {
	summary := &ScanSummary{ScanID: scanID}

	// Get scan metadata
	err := s.db.QueryRowContext(ctx, `
		SELECT target, version, start_time, end_time, status
		FROM scans WHERE id = ?
	`, scanID).Scan(&summary.Target, &summary.Version, &summary.StartTime, &summary.EndTime, &summary.Status)
	if err != nil {
		return nil, err
	}

	// Get counts
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM subdomains WHERE scan_id = ?", scanID).Scan(&summary.TotalSubdomains)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM subdomains WHERE scan_id = ? AND is_alive = 1", scanID).Scan(&summary.AliveHosts)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", scanID).Scan(&summary.TotalVulns)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'critical'", scanID).Scan(&summary.CriticalVulns)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ? AND severity = 'high'", scanID).Scan(&summary.HighVulns)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM urls WHERE scan_id = ?", scanID).Scan(&summary.TotalURLs)

	return summary, nil
}

// GetRecentScans returns recent scans for a target
func (s *SQLiteStorage) GetRecentScans(ctx context.Context, target string, limit int) ([]ScanRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target, version, start_time, end_time, status
		FROM scans
		WHERE target = ? OR ? = ''
		ORDER BY start_time DESC
		LIMIT ?
	`, target, target, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.Target, &r.Version, &r.StartTime, &r.EndTime, &r.Status); err != nil {
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

// GetTechStack returns unique technologies for a target
func (s *SQLiteStorage) GetTechStack(ctx context.Context, target string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.technology, COUNT(DISTINCT t.host) as host_count
		FROM technologies t
		JOIN scans s ON t.scan_id = s.id
		WHERE s.target = ?
		GROUP BY t.technology
		ORDER BY host_count DESC
	`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[string]int)
	for rows.Next() {
		var tech string
		var count int
		if err := rows.Scan(&tech, &count); err != nil {
			continue
		}
		results[tech] = count
	}

	return results, nil
}

// GetScreenshotClusters returns screenshot clusters for a scan
func (s *SQLiteStorage) GetScreenshotClusters(ctx context.Context, scanID string) ([]ClusterSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cluster_id, cluster_name, COUNT(*) as count
		FROM screenshots
		WHERE scan_id = ? AND cluster_id IS NOT NULL
		GROUP BY cluster_id, cluster_name
		ORDER BY count DESC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []ClusterSummary
	for rows.Next() {
		var r ClusterSummary
		if err := rows.Scan(&r.ClusterID, &r.ClusterName, &r.Count); err != nil {
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

// DiffSubdomains compares subdomains between two scans
func (s *SQLiteStorage) DiffSubdomains(ctx context.Context, oldScanID, newScanID string) (*SubdomainDiff, error) {
	diff := &SubdomainDiff{}

	// New subdomains (in new but not in old)
	rows, err := s.db.QueryContext(ctx, `
		SELECT subdomain FROM subdomains WHERE scan_id = ?
		EXCEPT
		SELECT subdomain FROM subdomains WHERE scan_id = ?
	`, newScanID, oldScanID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sub string
		rows.Scan(&sub)
		diff.Added = append(diff.Added, sub)
	}
	rows.Close()

	// Removed subdomains (in old but not in new)
	rows, err = s.db.QueryContext(ctx, `
		SELECT subdomain FROM subdomains WHERE scan_id = ?
		EXCEPT
		SELECT subdomain FROM subdomains WHERE scan_id = ?
	`, oldScanID, newScanID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sub string
		rows.Scan(&sub)
		diff.Removed = append(diff.Removed, sub)
	}
	rows.Close()

	return diff, nil
}

// =============================================================================
// Record Types
// =============================================================================

// VulnerabilityRecord represents a vulnerability from the database
type VulnerabilityRecord struct {
	Host         string
	URL          string
	TemplateID   string
	Name         string
	Severity     string
	Type         string
	Tool         string
	Description  string
	Evidence     string
	DiscoveredAt time.Time
}

// SubdomainRecord represents a subdomain from the database
type SubdomainRecord struct {
	Subdomain string
	IsAlive   bool
	IPAddress sql.NullString
	Source    sql.NullString
	FirstSeen time.Time
}

// ScreenshotRecord represents screenshot data for bulk insert
type ScreenshotRecord struct {
	URL         string
	FilePath    string
	Hash        string
	ClusterID   string
	ClusterName string
}

// ScanRecord represents a scan from the database
type ScanRecord struct {
	ID        string
	Target    string
	Version   string
	StartTime time.Time
	EndTime   sql.NullTime
	Status    string
}

// ScanSummary represents a scan summary for dashboard
type ScanSummary struct {
	ScanID          string
	Target          string
	Version         string
	StartTime       time.Time
	EndTime         sql.NullTime
	Status          string
	TotalSubdomains int
	AliveHosts      int
	TotalVulns      int
	CriticalVulns   int
	HighVulns       int
	TotalURLs       int
}

// ClusterSummary represents a screenshot cluster summary
type ClusterSummary struct {
	ClusterID   string
	ClusterName string
	Count       int
}

// SubdomainDiff represents differences between two scans
type SubdomainDiff struct {
	Added   []string
	Removed []string
}

// TakeoverRecord represents a subdomain takeover vulnerability
type TakeoverRecord struct {
	Subdomain string
	Service   string
	Severity  string
	Tool      string
}

// SecurityHeaderRecord represents security header analysis for a URL
type SecurityHeaderRecord struct {
	Host           string
	URL            string
	Score          int
	MissingHeaders []string
	WeakHeaders    []string
	PresentHeaders []string
	HeadersJSON    string
}

// AISummaryRecord represents AI-generated scan analysis
type AISummaryRecord struct {
	AIProvider           string
	TargetSummary        string
	RiskScore            int
	RecommendedTags      []string
	RecommendedTemplates []string
	VulnerabilitiesJSON  string
	ActionItems          []string
}

type JSAnalysisRecord struct {
	SourceURL           string
	Endpoint            string
	EndpointType        string
	DOMXSSSink          string
	SinkType            string
	Severity            string
	PrototypePollution  string
	PollutionType       string
	SecretType          string
	SecretValue         string
}

type SecretRecord struct {
	DetectorType string
	DetectorName string
	RawSecret    string
	Verified     bool
	SourceURL    string
	SourceLine   int
	Severity     string
}

// ListScans returns recent scans for a target (alias for GetRecentScans)
func (s *SQLiteStorage) ListScans(ctx context.Context, target string, limit int) ([]ScanRecord, error) {
	return s.GetRecentScans(ctx, target, limit)
}

// GetSubdomains returns all subdomains for a specific scan
func (s *SQLiteStorage) GetSubdomains(ctx context.Context, scanID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT subdomain FROM subdomains
		WHERE scan_id = ?
		ORDER BY subdomain
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			continue
		}
		results = append(results, sub)
	}
	return results, nil
}

// GetAliveHosts returns all alive hosts (from ports table) for a specific scan
func (s *SQLiteStorage) GetAliveHosts(ctx context.Context, scanID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT host FROM ports
		WHERE scan_id = ?
		ORDER BY host
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			continue
		}
		results = append(results, host)
	}
	return results, nil
}

// GetVulnerabilities returns all vulnerabilities for a specific scan
func (s *SQLiteStorage) GetVulnerabilities(ctx context.Context, scanID string) ([]VulnerabilityRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, url, template_id, name, severity, tool
		FROM vulnerabilities
		WHERE scan_id = ?
		ORDER BY severity DESC, host
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []VulnerabilityRecord
	for rows.Next() {
		var r VulnerabilityRecord
		var url, templateID, tool sql.NullString
		if err := rows.Scan(&r.Host, &url, &templateID, &r.Name, &r.Severity, &tool); err != nil {
			continue
		}
		r.URL = url.String
		r.TemplateID = templateID.String
		r.Tool = tool.String
		results = append(results, r)
	}
	return results, nil
}

// GetTakeovers returns all subdomain takeover vulnerabilities for a specific scan
func (s *SQLiteStorage) GetTakeovers(ctx context.Context, scanID string) ([]TakeoverRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT subdomain, service, severity, tool
		FROM takeover_vulns
		WHERE scan_id = ?
		ORDER BY subdomain
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TakeoverRecord
	for rows.Next() {
		var r TakeoverRecord
		var service, severity, tool sql.NullString
		if err := rows.Scan(&r.Subdomain, &service, &severity, &tool); err != nil {
			continue
		}
		r.Service = service.String
		r.Severity = severity.String
		r.Tool = tool.String
		results = append(results, r)
	}
	return results, nil
}

// PhaseStatusRecord represents the status of a phase execution
type PhaseStatusRecord struct {
	Phase        string
	Status       string
	StartTime    time.Time
	EndTime      time.Time
	DurationMs   int64
	ErrorMessage string
}

// SavePhaseStatus saves or updates the status of a phase
func (s *SQLiteStorage) SavePhaseStatus(ctx context.Context, scanID, phase, status string, startTime, endTime time.Time, durationMs int64, errorMsg string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO phase_status (scan_id, phase, status, start_time, end_time, duration_ms, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, phase) DO UPDATE SET
			status = excluded.status,
			start_time = COALESCE(excluded.start_time, phase_status.start_time),
			end_time = excluded.end_time,
			duration_ms = excluded.duration_ms,
			error_message = excluded.error_message
	`, scanID, phase, status, startTime, endTime, durationMs, errorMsg)
	return err
}

// GetPhaseStatuses returns all phase statuses for a scan
func (s *SQLiteStorage) GetPhaseStatuses(ctx context.Context, scanID string) (map[string]PhaseStatusRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT phase, status, start_time, end_time, duration_ms, error_message
		FROM phase_status
		WHERE scan_id = ?
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[string]PhaseStatusRecord)
	for rows.Next() {
		var r PhaseStatusRecord
		var startTime, endTime sql.NullTime
		var durationMs sql.NullInt64
		var errorMsg sql.NullString
		if err := rows.Scan(&r.Phase, &r.Status, &startTime, &endTime, &durationMs, &errorMsg); err != nil {
			continue
		}
		if startTime.Valid {
			r.StartTime = startTime.Time
		}
		if endTime.Valid {
			r.EndTime = endTime.Time
		}
		if durationMs.Valid {
			r.DurationMs = durationMs.Int64
		}
		if errorMsg.Valid {
			r.ErrorMessage = errorMsg.String
		}
		results[r.Phase] = r
	}
	return results, nil
}

// GetCompletedPhases returns a list of completed phase names for a scan
func (s *SQLiteStorage) GetCompletedPhases(ctx context.Context, scanID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT phase FROM phase_status
		WHERE scan_id = ? AND status = 'completed'
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var phases []string
	for rows.Next() {
		var phase string
		if err := rows.Scan(&phase); err != nil {
			continue
		}
		phases = append(phases, phase)
	}
	return phases, nil
}

// GetIncompleteScan returns the most recent incomplete scan for a target
func (s *SQLiteStorage) GetIncompleteScan(ctx context.Context, target string) (*ScanRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, target, version, start_time, end_time, status
		FROM scans
		WHERE target = ? AND status IN ('running', 'interrupted')
		ORDER BY start_time DESC
		LIMIT 1
	`, target)

	var r ScanRecord
	if err := row.Scan(&r.ID, &r.Target, &r.Version, &r.StartTime, &r.EndTime, &r.Status); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// MarkScanInterrupted marks a scan as interrupted (for resume later)
func (s *SQLiteStorage) MarkScanInterrupted(ctx context.Context, scanID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status = 'interrupted' WHERE id = ?
	`, scanID)
	return err
}

// ImportFromDatabase imports data from another SQLite database file
func (s *SQLiteStorage) ImportFromDatabase(ctx context.Context, sourceDBPath string, scanID string) error {
	// Attach the source database
	_, err := s.db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE '%s' AS source_db", sourceDBPath))
	if err != nil {
		return fmt.Errorf("failed to attach source database: %w", err)
	}
	defer s.db.ExecContext(ctx, "DETACH DATABASE source_db")

	// List of tables to copy
	tables := []string{"subdomains", "ports", "vulnerabilities", "technologies", "urls", "screenshots", "waf_detections", "takeover_vulns", "security_headers", "js_analysis", "secrets"}

	for _, table := range tables {
		// Check if table exists in source DB
		var tableExists int
		err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM source_db.sqlite_master WHERE type='table' AND name='%s'", table)).Scan(&tableExists)
		if err != nil || tableExists == 0 {
			continue
		}

		// Get count of records for this scan in source DB
		var count int
		err = s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM source_db.%s WHERE scan_id = ?", table), scanID).Scan(&count)
		if err != nil || count == 0 {
			continue
		}

		// Copy data using INSERT OR REPLACE
		copyQuery := fmt.Sprintf("INSERT OR REPLACE INTO %s SELECT * FROM source_db.%s WHERE scan_id = ?", table, table)
		_, err = s.db.ExecContext(ctx, copyQuery, scanID)
		if err != nil {
			return fmt.Errorf("failed to copy %s: %w", table, err)
		}
	}

	return nil
}
