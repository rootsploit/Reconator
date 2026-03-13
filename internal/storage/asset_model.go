package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// AttackPathRecord represents an AI-identified attack path through the asset graph
type AttackPathRecord struct {
	Name        string   `json:"name"`
	RiskLevel   string   `json:"risk_level"`
	Probability float64  `json:"probability"`
	Steps       []string `json:"steps"`
	Mitigations []string `json:"mitigations"`
}

// InitAssetModelSchema creates all asset-model tables and indexes.
// This should be called from initSchema in sqlite.go or during migration.
func InitAssetModelSchema(db *sql.DB) error {
	schema := `
	-- Assets table: unified asset representation linking subdomains, IPs, and metadata
	CREATE TABLE IF NOT EXISTS assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		ip TEXT,
		is_alive INTEGER DEFAULT 0,
		is_cdn INTEGER DEFAULT 0,
		waf_provider TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, hostname)
	);
	CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
	CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);

	-- Asset ports table: ports associated with a specific asset
	CREATE TABLE IF NOT EXISTS asset_ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		service TEXT,
		FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
		UNIQUE(asset_id, port, protocol)
	);
	CREATE INDEX IF NOT EXISTS idx_asset_ports_asset_id ON asset_ports(asset_id);

	-- Asset technologies table: technologies detected on a specific asset
	CREATE TABLE IF NOT EXISTS asset_technologies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL,
		technology TEXT NOT NULL,
		version TEXT,
		category TEXT,
		FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
		UNIQUE(asset_id, technology)
	);
	CREATE INDEX IF NOT EXISTS idx_asset_technologies_asset_id ON asset_technologies(asset_id);

	-- Asset vulnerabilities table: vulnerabilities linked to a specific asset with AI validation
	CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL,
		vulnerability_id INTEGER,
		ai_validated INTEGER DEFAULT 0,
		ai_confidence REAL DEFAULT 0,
		ai_adjusted_risk TEXT,
		ai_reasoning TEXT,
		FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_asset_vulns_asset_id ON asset_vulnerabilities(asset_id);
	CREATE INDEX IF NOT EXISTS idx_asset_vulns_vuln_id ON asset_vulnerabilities(vulnerability_id);

	-- Attack paths table: AI-identified attack chains across assets
	CREATE TABLE IF NOT EXISTS attack_paths (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		name TEXT NOT NULL,
		risk_level TEXT NOT NULL,
		probability REAL DEFAULT 0,
		steps_json TEXT,
		mitigations_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_attack_paths_scan_id ON attack_paths(scan_id);
	CREATE INDEX IF NOT EXISTS idx_attack_paths_risk_level ON attack_paths(risk_level);

	-- Attack path edges: individual edges in attack paths (for graph visualization)
	CREATE TABLE IF NOT EXISTS attack_path_edges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		path_id TEXT NOT NULL,
		from_vuln_id TEXT NOT NULL,
		to_vuln_id TEXT NOT NULL,
		pattern_id TEXT NOT NULL,
		weight REAL DEFAULT 0,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_attack_path_edges_scan_id ON attack_path_edges(scan_id);
	CREATE INDEX IF NOT EXISTS idx_attack_path_edges_path_id ON attack_path_edges(path_id);

	-- AI decisions table: records of AI checkpoint decisions during guided scanning
	CREATE TABLE IF NOT EXISTS ai_decisions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		checkpoint TEXT NOT NULL,
		decisions_json TEXT NOT NULL,
		provider TEXT,
		duration_ms INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, checkpoint)
	);
	CREATE INDEX IF NOT EXISTS idx_ai_decisions_scan_id ON ai_decisions(scan_id);
	CREATE INDEX IF NOT EXISTS idx_ai_decisions_checkpoint ON ai_decisions(checkpoint);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to initialize asset model schema: %w", err)
	}
	return nil
}

// UpsertAsset inserts or updates an asset record and returns the asset ID.
// On conflict (same scan_id + hostname), the existing row is updated with new values.
func (s *SQLiteStorage) UpsertAsset(ctx context.Context, scanID, hostname, ip string, isAlive, isCDN bool, wafProvider string) (int64, error) {
	alive := 0
	if isAlive {
		alive = 1
	}
	cdn := 0
	if isCDN {
		cdn = 1
	}

	result, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (scan_id, hostname, ip, is_alive, is_cdn, waf_provider)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, hostname) DO UPDATE SET
			ip = excluded.ip,
			is_alive = excluded.is_alive,
			is_cdn = excluded.is_cdn,
			waf_provider = excluded.waf_provider
	`, scanID, hostname, ip, alive, cdn, wafProvider)
	if err != nil {
		return 0, fmt.Errorf("failed to upsert asset %s: %w", hostname, err)
	}

	// If the row was inserted, LastInsertId returns the new ID.
	// If the row was updated, we need to query for the existing ID.
	id, err := result.LastInsertId()
	if err != nil || id == 0 {
		return s.GetAssetID(ctx, scanID, hostname)
	}

	// Verify the ID is valid (LastInsertId may return the rowid even on update
	// in some SQLite drivers, but the value may not reflect the actual row).
	// To be safe, always confirm via lookup when the result is ambiguous.
	var rowCount int64
	rowCount, err = result.RowsAffected()
	if err != nil {
		return id, nil
	}
	// If rows affected > 0 and we got an id, it could be either insert or update.
	// On update, LastInsertId may not reflect the actual asset id, so look it up.
	if rowCount > 0 {
		existingID, lookupErr := s.GetAssetID(ctx, scanID, hostname)
		if lookupErr == nil {
			return existingID, nil
		}
	}

	return id, nil
}

// GetAssetID looks up the asset ID for a given scan and hostname.
func (s *SQLiteStorage) GetAssetID(ctx context.Context, scanID, hostname string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM assets WHERE scan_id = ? AND hostname = ?
	`, scanID, hostname).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to get asset ID for %s: %w", hostname, err)
	}
	return id, nil
}

// LinkAssetPort associates a port with an asset.
// On conflict (same asset_id + port + protocol), the service field is updated.
func (s *SQLiteStorage) LinkAssetPort(ctx context.Context, assetID int64, port int, protocol, service string) error {
	if protocol == "" {
		protocol = "tcp"
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_ports (asset_id, port, protocol, service)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
			service = excluded.service
	`, assetID, port, protocol, service)
	if err != nil {
		return fmt.Errorf("failed to link port %d/%s to asset %d: %w", port, protocol, assetID, err)
	}
	return nil
}

// LinkAssetTech associates a technology with an asset.
// On conflict (same asset_id + technology), the version and category are updated.
func (s *SQLiteStorage) LinkAssetTech(ctx context.Context, assetID int64, technology, version, category string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_technologies (asset_id, technology, version, category)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(asset_id, technology) DO UPDATE SET
			version = excluded.version,
			category = excluded.category
	`, assetID, technology, version, category)
	if err != nil {
		return fmt.Errorf("failed to link technology %s to asset %d: %w", technology, assetID, err)
	}
	return nil
}

// LinkAssetVuln associates a vulnerability with an asset.
func (s *SQLiteStorage) LinkAssetVuln(ctx context.Context, assetID int64, vulnID int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id)
		VALUES (?, ?)
	`, assetID, vulnID)
	if err != nil {
		return fmt.Errorf("failed to link vulnerability %d to asset %d: %w", vulnID, assetID, err)
	}
	return nil
}

// UpdateVulnValidation updates the AI validation fields on an asset-vulnerability link.
func (s *SQLiteStorage) UpdateVulnValidation(ctx context.Context, assetVulnID int64, validated bool, confidence float64, adjustedRisk, reasoning string) error {
	aiValidated := 0
	if validated {
		aiValidated = 1
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE asset_vulnerabilities
		SET ai_validated = ?, ai_confidence = ?, ai_adjusted_risk = ?, ai_reasoning = ?
		WHERE id = ?
	`, aiValidated, confidence, adjustedRisk, reasoning, assetVulnID)
	if err != nil {
		return fmt.Errorf("failed to update vuln validation for asset_vuln %d: %w", assetVulnID, err)
	}
	return nil
}

// SaveAttackPaths bulk inserts attack path records for a scan within a transaction.
func (s *SQLiteStorage) SaveAttackPaths(ctx context.Context, scanID string, paths []AttackPathRecord) error {
	if len(paths) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for attack paths: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO attack_paths (scan_id, name, risk_level, probability, steps_json, mitigations_json)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare attack path insert: %w", err)
	}
	defer stmt.Close()

	for _, p := range paths {
		stepsJSON, err := json.Marshal(p.Steps)
		if err != nil {
			return fmt.Errorf("failed to marshal steps for attack path %s: %w", p.Name, err)
		}
		mitigationsJSON, err := json.Marshal(p.Mitigations)
		if err != nil {
			return fmt.Errorf("failed to marshal mitigations for attack path %s: %w", p.Name, err)
		}

		if _, err := stmt.ExecContext(ctx, scanID, p.Name, p.RiskLevel, p.Probability, string(stepsJSON), string(mitigationsJSON)); err != nil {
			return fmt.Errorf("failed to insert attack path %s: %w", p.Name, err)
		}
	}

	return tx.Commit()
}

// SaveAIDecision records an AI decision checkpoint.
// On conflict (same scan_id + checkpoint), the existing record is replaced.
func (s *SQLiteStorage) SaveAIDecision(ctx context.Context, scanID, checkpoint, decisionsJSON, provider string, durationMs int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_decisions (scan_id, checkpoint, decisions_json, provider, duration_ms)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, checkpoint) DO UPDATE SET
			decisions_json = excluded.decisions_json,
			provider = excluded.provider,
			duration_ms = excluded.duration_ms,
			created_at = CURRENT_TIMESTAMP
	`, scanID, checkpoint, decisionsJSON, provider, durationMs)
	if err != nil {
		return fmt.Errorf("failed to save AI decision for checkpoint %s: %w", checkpoint, err)
	}
	return nil
}

// QueryAssetGraph builds a TOON-formatted text representation of the asset graph
// suitable for inclusion in AI prompts. The format is compact and structured for
// LLM consumption.
//
// Output format:
//
//	[assets]
//	hostname=example.com ip=1.2.3.4 alive=true cdn=false waf=none
//	  [ports] 80/tcp(http) 443/tcp(https)
//	  [tech] nginx/1.18 php/7.4
//	  [vulns] sqli(high) xss(medium)
func (s *SQLiteStorage) QueryAssetGraph(ctx context.Context, scanID string) (string, error) {
	// Fetch all assets for the scan
	assetRows, err := s.db.QueryContext(ctx, `
		SELECT id, hostname, ip, is_alive, is_cdn, waf_provider
		FROM assets
		WHERE scan_id = ?
		ORDER BY hostname
	`, scanID)
	if err != nil {
		return "", fmt.Errorf("failed to query assets: %w", err)
	}
	defer assetRows.Close()

	type assetInfo struct {
		id          int64
		hostname    string
		ip          sql.NullString
		isAlive     int
		isCDN       int
		wafProvider sql.NullString
	}

	var assets []assetInfo
	for assetRows.Next() {
		var a assetInfo
		if err := assetRows.Scan(&a.id, &a.hostname, &a.ip, &a.isAlive, &a.isCDN, &a.wafProvider); err != nil {
			continue
		}
		assets = append(assets, a)
	}
	if err := assetRows.Err(); err != nil {
		return "", fmt.Errorf("failed to iterate assets: %w", err)
	}

	if len(assets) == 0 {
		return "[assets]\n(none)\n", nil
	}

	var b strings.Builder
	b.WriteString("[assets]\n")

	for _, a := range assets {
		// Asset header line
		ipStr := "unknown"
		if a.ip.Valid && a.ip.String != "" {
			ipStr = a.ip.String
		}
		aliveStr := "false"
		if a.isAlive == 1 {
			aliveStr = "true"
		}
		cdnStr := "false"
		if a.isCDN == 1 {
			cdnStr = "true"
		}
		wafStr := "none"
		if a.wafProvider.Valid && a.wafProvider.String != "" {
			wafStr = a.wafProvider.String
		}

		fmt.Fprintf(&b, "hostname=%s ip=%s alive=%s cdn=%s waf=%s\n", a.hostname, ipStr, aliveStr, cdnStr, wafStr)

		// Ports
		portRows, err := s.db.QueryContext(ctx, `
			SELECT port, protocol, service FROM asset_ports
			WHERE asset_id = ?
			ORDER BY port
		`, a.id)
		if err == nil {
			var portParts []string
			for portRows.Next() {
				var port int
				var protocol sql.NullString
				var service sql.NullString
				if err := portRows.Scan(&port, &protocol, &service); err != nil {
					continue
				}
				proto := "tcp"
				if protocol.Valid && protocol.String != "" {
					proto = protocol.String
				}
				svc := ""
				if service.Valid && service.String != "" {
					svc = service.String
				}
				if svc != "" {
					portParts = append(portParts, fmt.Sprintf("%d/%s(%s)", port, proto, svc))
				} else {
					portParts = append(portParts, fmt.Sprintf("%d/%s", port, proto))
				}
			}
			portRows.Close()
			if len(portParts) > 0 {
				fmt.Fprintf(&b, "  [ports] %s\n", strings.Join(portParts, " "))
			}
		}

		// Technologies
		techRows, err := s.db.QueryContext(ctx, `
			SELECT technology, version FROM asset_technologies
			WHERE asset_id = ?
			ORDER BY technology
		`, a.id)
		if err == nil {
			var techParts []string
			for techRows.Next() {
				var technology string
				var version sql.NullString
				if err := techRows.Scan(&technology, &version); err != nil {
					continue
				}
				if version.Valid && version.String != "" {
					techParts = append(techParts, fmt.Sprintf("%s/%s", technology, version.String))
				} else {
					techParts = append(techParts, technology)
				}
			}
			techRows.Close()
			if len(techParts) > 0 {
				fmt.Fprintf(&b, "  [tech] %s\n", strings.Join(techParts, " "))
			}
		}

		// Vulnerabilities
		vulnRows, err := s.db.QueryContext(ctx, `
			SELECT v.name, v.severity
			FROM asset_vulnerabilities av
			JOIN vulnerabilities v ON av.vulnerability_id = v.id
			WHERE av.asset_id = ?
			ORDER BY CASE v.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END
		`, a.id)
		if err == nil {
			var vulnParts []string
			for vulnRows.Next() {
				var name string
				var severity sql.NullString
				if err := vulnRows.Scan(&name, &severity); err != nil {
					continue
				}
				sev := "unknown"
				if severity.Valid && severity.String != "" {
					sev = severity.String
				}
				vulnParts = append(vulnParts, fmt.Sprintf("%s(%s)", name, sev))
			}
			vulnRows.Close()
			if len(vulnParts) > 0 {
				fmt.Fprintf(&b, "  [vulns] %s\n", strings.Join(vulnParts, " "))
			}
		}
	}

	return b.String(), nil
}
