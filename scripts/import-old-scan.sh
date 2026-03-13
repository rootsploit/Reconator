#!/bin/bash

# Import Old Reconator Scan into New Database Structure
# Usage: ./import-old-scan.sh <old_scan_directory>

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check arguments
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <old_scan_directory>${NC}"
    echo ""
    echo "Example:"
    echo "  $0 ~/reconator/vulnweb.com"
    echo "  $0 /path/to/old/scan"
    exit 1
fi

OLD_SCAN_DIR="$1"
RECONATOR_ROOT="$HOME/reconator"

# Validate old scan directory
if [ ! -d "$OLD_SCAN_DIR" ]; then
    echo -e "${RED}❌ Error: Directory not found: $OLD_SCAN_DIR${NC}"
    exit 1
fi

if [ ! -f "$OLD_SCAN_DIR/reconator.db" ]; then
    echo -e "${RED}❌ Error: No reconator.db found in $OLD_SCAN_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Reconator Scan Import Tool${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Extract scan metadata from old DB
echo -e "\n${YELLOW}[1/6] Extracting scan metadata...${NC}"
SCAN_ID=$(sqlite3 "$OLD_SCAN_DIR/reconator.db" "SELECT id FROM scans ORDER BY start_time DESC LIMIT 1;" 2>/dev/null || echo "")
TARGET=$(sqlite3 "$OLD_SCAN_DIR/reconator.db" "SELECT target FROM scans ORDER BY start_time DESC LIMIT 1;" 2>/dev/null || echo "")

if [ -z "$SCAN_ID" ]; then
    echo -e "${RED}❌ Error: Could not extract scan ID from database${NC}"
    exit 1
fi

echo -e "   Scan ID: ${GREEN}$SCAN_ID${NC}"
echo -e "   Target:  ${GREEN}$TARGET${NC}"

# Create new directory name
NEW_DIR_NAME="${SCAN_ID}_${TARGET}"
NEW_SCAN_PATH="$RECONATOR_ROOT/$NEW_DIR_NAME"

# Check if already imported
if [ -d "$NEW_SCAN_PATH" ]; then
    echo -e "${YELLOW}⚠️  Warning: Scan already exists at $NEW_SCAN_PATH${NC}"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Import cancelled${NC}"
        exit 1
    fi
    rm -rf "$NEW_SCAN_PATH"
fi

# Copy scan directory
echo -e "\n${YELLOW}[2/6] Copying scan directory...${NC}"
mkdir -p "$RECONATOR_ROOT"
cp -r "$OLD_SCAN_DIR" "$NEW_SCAN_PATH"
echo -e "   ${GREEN}✓${NC} Copied to $NEW_SCAN_PATH"

# Reorganize screenshots
echo -e "\n${YELLOW}[3/6] Reorganizing screenshots...${NC}"
cd "$NEW_SCAN_PATH"

if [ -d "screenshots" ]; then
    mkdir -p "9-screenshots/screenshots"

    # Count files
    FILE_COUNT=$(find screenshots -type f 2>/dev/null | wc -l | tr -d ' ')

    if [ "$FILE_COUNT" -gt 0 ]; then
        mv screenshots/* 9-screenshots/screenshots/ 2>/dev/null || true
        rmdir screenshots 2>/dev/null || true
        echo -e "   ${GREEN}✓${NC} Moved $FILE_COUNT screenshots to 9-screenshots/screenshots/"
    else
        echo -e "   ${YELLOW}⚠${NC}  No screenshots found"
    fi
else
    echo -e "   ${YELLOW}⚠${NC}  No screenshots directory found"
fi

# Initialize global database if needed
echo -e "\n${YELLOW}[4/6] Initializing global database...${NC}"
GLOBAL_DB="$RECONATOR_ROOT/reconator.db"

if [ ! -f "$GLOBAL_DB" ]; then
    echo -e "   ${GREEN}✓${NC} Creating new global database with schema"

    # Initialize schema
    sqlite3 "$GLOBAL_DB" <<'SCHEMA_EOF'
-- Enable WAL mode for better concurrent access
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Scans table: stores scan metadata
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    version TEXT,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    status TEXT DEFAULT 'running',
    config_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time);

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

-- Vulnerabilities table: stores found vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    host TEXT NOT NULL,
    url TEXT,
    template_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    tool TEXT,
    evidence TEXT,
    is_false_positive INTEGER DEFAULT 0,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host);

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

-- Security headers table
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

-- AI summary table
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
SCHEMA_EOF

else
    echo -e "   ${GREEN}✓${NC} Using existing global database"
fi

# Import data into global database
echo -e "\n${YELLOW}[5/6] Importing data into global database...${NC}"

# Function to import table if it exists
import_table() {
    local table_name=$1
    sqlite3 "$GLOBAL_DB" "ATTACH DATABASE '$NEW_SCAN_PATH/reconator.db' AS old_scan; INSERT OR REPLACE INTO $table_name SELECT * FROM old_scan.$table_name; DETACH DATABASE old_scan;" 2>/dev/null
    if [ $? -eq 0 ]; then
        local count=$(sqlite3 "$GLOBAL_DB" "SELECT COUNT(*) FROM $table_name WHERE scan_id='$SCAN_ID';" 2>/dev/null || echo "0")
        if [ "$count" != "0" ]; then
            echo -e "   ${GREEN}✓${NC} Imported $count records from $table_name"
        fi
    fi
}

# Import all tables
import_table "scans"
import_table "subdomains"
import_table "ports"
import_table "vulnerabilities"
import_table "technologies"
import_table "urls"
import_table "screenshots"
import_table "waf_detections"
import_table "takeover_vulns"
import_table "phase_outputs"
import_table "phase_status"

# Update screenshot paths
echo -e "\n${YELLOW}[6/6] Updating screenshot paths...${NC}"
sqlite3 "$GLOBAL_DB" <<EOF
-- Update absolute paths to relative paths
UPDATE screenshots
SET file_path = '${NEW_DIR_NAME}/9-screenshots/screenshots/' ||
    substr(file_path, length(file_path) - instr(reverse(file_path), '/') + 2)
WHERE scan_id = '$SCAN_ID' AND file_path LIKE '/%';

-- Update results/target/screenshots/ format
UPDATE screenshots
SET file_path = '${NEW_DIR_NAME}/9-screenshots/screenshots/' ||
    substr(file_path, instr(file_path, 'screenshots/') + 12)
WHERE scan_id = '$SCAN_ID' AND file_path LIKE '%/screenshots/%' AND file_path NOT LIKE '${NEW_DIR_NAME}%';

-- Update simple screenshots/ format
UPDATE screenshots
SET file_path = '${NEW_DIR_NAME}/9-screenshots/screenshots/' ||
    substr(file_path, 13)
WHERE scan_id = '$SCAN_ID' AND file_path LIKE 'screenshots/%' AND file_path NOT LIKE '${NEW_DIR_NAME}%';

-- Final cleanup: ensure all paths are in correct format
UPDATE screenshots
SET file_path = '${NEW_DIR_NAME}/9-screenshots/screenshots/' ||
    substr(file_path, length(file_path) - instr(reverse(file_path), '/') + 2)
WHERE scan_id = '$SCAN_ID' AND file_path NOT LIKE '${NEW_DIR_NAME}/9-screenshots/screenshots/%';
EOF

UPDATED_COUNT=$(sqlite3 "$GLOBAL_DB" "SELECT COUNT(*) FROM screenshots WHERE scan_id='$SCAN_ID';")
echo -e "   ${GREEN}✓${NC} Updated $UPDATED_COUNT screenshot paths"

# Optional: Remove old local database
read -p "$(echo -e "\nRemove old local database from scan directory? (y/N) ")" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm "$NEW_SCAN_PATH/reconator.db"
    rm "$NEW_SCAN_PATH/reconator.db-shm" 2>/dev/null || true
    rm "$NEW_SCAN_PATH/reconator.db-wal" 2>/dev/null || true
    echo -e "   ${GREEN}✓${NC} Removed old database files"
fi

echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Import complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Scan location: ${YELLOW}$NEW_SCAN_PATH${NC}"
echo -e "Database:      ${YELLOW}$GLOBAL_DB${NC}"
echo ""
echo -e "View in web dashboard:"
echo -e "  ${GREEN}./reconator server${NC}"
echo -e "  Open: ${YELLOW}http://localhost:8888${NC}"
echo ""
