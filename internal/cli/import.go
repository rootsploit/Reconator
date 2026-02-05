package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/storage"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

var importCmd = &cobra.Command{
	Use:   "import <scan-directory>",
	Short: "Import scan results from another reconator instance",
	Long: `Import scan results from a scan directory into the current database.

This is useful for:
  - Importing scans from remote servers (VPS, scanning boxes)
  - Migrating scans between reconator installations
  - Consolidating scans from multiple sources

The import command will:
  1. Detect the scan ID and target from the directory name
  2. Copy all scan data and results to the current database
  3. Update file paths to match the new location

Example:
  reconator import ~/Downloads/20260131-235407-58d8d106_vulnweb.com
  reconator import /mnt/remote-scans/scan_example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	scanDir := args[0]

	// Colors
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)

	// Validate scan directory exists
	if _, err := os.Stat(scanDir); os.IsNotExist(err) {
		return fmt.Errorf("scan directory does not exist: %s", scanDir)
	}

	// Get absolute path
	scanDir, err := filepath.Abs(scanDir)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Extract scan info from directory name
	baseName := filepath.Base(scanDir)
	parts := strings.SplitN(baseName, "_", 2)

	var scanID, target string
	if len(parts) == 2 {
		scanID = parts[0]
		target = parts[1]
	} else {
		return fmt.Errorf("invalid scan directory format. Expected: <scan-id>_<target>, got: %s", baseName)
	}

	fmt.Println()
	cyan.Printf("╔══════════════════════════════════════════════════╗\n")
	cyan.Printf("║         RECONATOR SCAN IMPORT                    ║\n")
	cyan.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Println()

	yellow.Printf("  Scan Directory: %s\n", scanDir)
	yellow.Printf("  Scan ID:        %s\n", scanID)
	yellow.Printf("  Target:         %s\n", target)
	fmt.Println()

	// Check if scan database exists
	oldDB := filepath.Join(scanDir, "reconator.db")
	if _, err := os.Stat(oldDB); os.IsNotExist(err) {
		return fmt.Errorf("scan database not found: %s", oldDB)
	}

	// Get reconator root directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	reconatorRoot := filepath.Join(homeDir, "reconator")

	// Create reconator directory if it doesn't exist
	if err := os.MkdirAll(reconatorRoot, 0755); err != nil {
		return fmt.Errorf("failed to create reconator directory: %w", err)
	}

	// Determine destination directory
	destDir := filepath.Join(reconatorRoot, baseName)

	// Check if scan already exists
	globalDB := filepath.Join(reconatorRoot, "reconator.db")
	if _, err := os.Stat(globalDB); err == nil {
		// Check if scan ID already exists
		db, err := sql.Open("sqlite", globalDB)
		if err == nil {
			defer db.Close()

			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM scans WHERE id = ?", scanID).Scan(&count)
			if err == nil && count > 0 {
				yellow.Printf("  ⚠️  Scan %s already exists in database\n", scanID)
				fmt.Print("  Continue and overwrite? (y/N): ")
				var response string
				fmt.Scanln(&response)
				if strings.ToLower(response) != "y" {
					fmt.Println()
					yellow.Println("  Import cancelled")
					return nil
				}
			}
		}
	}

	// Copy scan directory if it's not already in reconator root
	if !strings.HasPrefix(scanDir, reconatorRoot) {
		fmt.Println()
		cyan.Println("  [1/3] Copying scan directory...")

		if err := copyDir(scanDir, destDir); err != nil {
			return fmt.Errorf("failed to copy scan directory: %w", err)
		}
		green.Printf("  ✓ Copied to %s\n", destDir)
	} else {
		destDir = scanDir
		yellow.Printf("  ✓ Scan already in reconator directory\n")
	}

	// Fix directory structure for web server compatibility
	// Web server expects: OutputDir/Target/phase/files
	// But CLI may create: OutputDir/phase/files
	fmt.Println()
	cyan.Println("  [1.5/3] Fixing directory structure for web server...")
	if err := ensureWebServerStructure(destDir, target); err != nil {
		return fmt.Errorf("failed to fix directory structure: %w", err)
	}
	green.Println("  ✓ Directory structure verified")

	// Fix screenshot paths in JSON files
	fmt.Println()
	cyan.Println("  [1.6/3] Fixing screenshot paths...")
	if err := fixScreenshotPaths(destDir, baseName); err != nil {
		yellow.Printf("  ⚠️  Warning: Failed to fix screenshot paths: %v\n", err)
	} else {
		green.Println("  ✓ Screenshot paths updated")
	}

	// Initialize storage
	fmt.Println()
	cyan.Println("  [2/3] Initializing database...")

	store, err := storage.NewSQLiteStorage(reconatorRoot)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()

	green.Println("  ✓ Database initialized")

	// Import scan data from old database
	fmt.Println()
	cyan.Println("  [3/3] Importing scan data...")

	oldDBPath := filepath.Join(destDir, "reconator.db")
	if err := importScanData(store, oldDBPath, scanID, destDir); err != nil {
		return fmt.Errorf("failed to import scan data: %w", err)
	}

	green.Println("  ✓ Scan data imported successfully")

	fmt.Println()
	green.Printf("╔══════════════════════════════════════════════════╗\n")
	green.Printf("║  ✓ Import completed successfully!               ║\n")
	green.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Println()
	yellow.Printf("  Scan ID: %s\n", scanID)
	yellow.Printf("  Location: %s\n", destDir)
	fmt.Println()

	return nil
}

func importScanData(store *storage.SQLiteStorage, oldDBPath, scanID, scanDir string) error {
	// Open old database
	oldDB, err := sql.Open("sqlite", oldDBPath)
	if err != nil {
		return fmt.Errorf("failed to open old database: %w", err)
	}
	defer oldDB.Close()

	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	// Try to update the scan record with the correct absolute output_dir (if column exists)
	// Note: New storage schema doesn't have output_dir column, so this may fail - that's OK
	green.Println("  ↻ Updating scan record with correct output directory...")
	_, err = oldDB.Exec("UPDATE scans SET output_dir = ? WHERE id = ?", scanDir, scanID)
	if err != nil {
		// Column might not exist in new schema - check if it's just a schema mismatch
		if !strings.Contains(err.Error(), "no such column") {
			return fmt.Errorf("failed to update scan output_dir: %w", err)
		}
		yellow.Println("  ⓘ Skipping output_dir update (using new storage schema)")
	}

	// Get the scan record from old database
	// Try new schema first (target, status, start_time, end_time, duration)
	var target, status string
	var startedAt, endedAt, durationStr sql.NullString
	query := `SELECT target, status, start_time, end_time, duration FROM scans WHERE id = ?`
	err = oldDB.QueryRow(query, scanID).Scan(&target, &status, &startedAt, &endedAt, &durationStr)
	if err != nil {
		// Fall back to old schema without duration field
		query = `SELECT target, status, start_time, end_time FROM scans WHERE id = ?`
		err = oldDB.QueryRow(query, scanID).Scan(&target, &status, &startedAt, &endedAt)
		if err != nil {
			return fmt.Errorf("failed to read scan record: %w", err)
		}
	}

	green.Printf("  ✓ Found scan: %s (%s)\n", target, status)

	// Count records to import
	tables := []string{"subdomains", "ports", "vulnerabilities", "technologies", "urls", "screenshots", "waf_detections", "takeover_vulns", "security_headers", "js_analysis", "secrets"}

	totalRecords := 0
	for _, table := range tables {
		var count int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE scan_id = ?", table)
		err := oldDB.QueryRow(countQuery, scanID).Scan(&count)

		if err != nil {
			if strings.Contains(err.Error(), "no such table") {
				yellow.Printf("  ⚠️  Table %s not found in old database\n", table)
				continue
			}
			return fmt.Errorf("failed to count %s: %w", table, err)
		}

		if count > 0 {
			green.Printf("  ✓ Found %d %s records\n", count, table)
			totalRecords += count
		}
	}

	if totalRecords == 0 {
		yellow.Println("  ⚠️  No data found to import")
		return nil
	}

	// Now actually import the data to the global database
	fmt.Println()
	green.Println("  ↻ Migrating data to global database...")

	// Import scan metadata
	green.Println("  → Importing scan metadata...")
	ctx := context.Background()

	// Parse start time
	var startTime time.Time
	if startedAt.Valid {
		startTime, _ = time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", startedAt.String)
		if startTime.IsZero() {
			startTime = time.Now()
		}
	} else {
		startTime = time.Now()
	}

	// Create scan record
	err = store.CreateScan(ctx, scanID, target, "", nil)
	if err != nil && !strings.Contains(err.Error(), "UNIQUE constraint") {
		return fmt.Errorf("failed to create scan: %w", err)
	}

	// Update scan status and duration
	err = store.UpdateScanStatus(ctx, scanID, status)
	if err != nil {
		yellow.Printf("  ⚠️  Warning: Failed to update scan status: %v\n", err)
	}

	// Update duration if available
	if durationStr.Valid && durationStr.String != "" {
		// Parse end_time to set completed_at
		var endTime time.Time
		if endedAt.Valid {
			endTime, _ = time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", endedAt.String)
		}
		if endTime.IsZero() {
			endTime = time.Now()
		}

		// Update duration and completed_at
		err = store.UpdateScanDuration(ctx, scanID, durationStr.String, endTime)
		if err != nil {
			yellow.Printf("  ⚠️  Warning: Failed to update scan duration: %v\n", err)
		}
	}

	// Import table data using ATTACH DATABASE
	green.Println("  → Copying table data...")
	err = store.ImportFromDatabase(ctx, oldDBPath, scanID)
	if err != nil {
		return fmt.Errorf("failed to import data: %w", err)
	}

	green.Println("\n  ✓ Data migration completed!")

	// Also insert into old database format (for web server compatibility)
	green.Println("  → Registering in web server database...")
	if err := insertIntoWebServerDB(ctx, store, scanID, target, status, scanDir); err != nil {
		yellow.Printf("  ⚠️  Warning: Failed to register in web database: %v\n", err)
	} else {
		green.Println("  ✓ Registered in web server database")
	}

	return nil
}

// insertIntoWebServerDB adds missing columns for web server compatibility
func insertIntoWebServerDB(ctx context.Context, store *storage.SQLiteStorage, scanID, target, status, outputDir string) error {
	// Get the reconator root directory (parent of scan directory)
	reconatorRoot := filepath.Dir(outputDir)
	dbPath := filepath.Join(reconatorRoot, "reconator.db")

	// Open database directly
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Add missing columns for web server compatibility (if they don't exist)
	alterQueries := []string{
		"ALTER TABLE scans ADD COLUMN phases TEXT DEFAULT '[\"all\"]'",
		"ALTER TABLE scans ADD COLUMN current_phase TEXT",
		"ALTER TABLE scans ADD COLUMN progress INTEGER DEFAULT 100",
		"ALTER TABLE scans ADD COLUMN output_dir TEXT",
		"ALTER TABLE scans ADD COLUMN error TEXT",
		"ALTER TABLE scans ADD COLUMN duration TEXT",
		"ALTER TABLE scans ADD COLUMN started_at DATETIME",
		"ALTER TABLE scans ADD COLUMN completed_at DATETIME",
	}

	for _, query := range alterQueries {
		_, err := db.ExecContext(ctx, query)
		// Ignore "duplicate column" errors
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("failed to add column: %w", err)
		}
	}

	// Update the scan record with web-server-needed fields
	_, err = db.ExecContext(ctx, `
		UPDATE scans
		SET output_dir = ?,
		    phases = '["all"]',
		    progress = 100,
		    started_at = start_time,
		    completed_at = end_time,
		    duration = COALESCE(
		        CAST((julianday(end_time) - julianday(start_time)) * 24 * 60 AS TEXT) || 'm',
		        '0m'
		    )
		WHERE id = ?
	`, outputDir, scanID)

	return err
}

// ensureWebServerStructure ensures the directory structure matches what web server expects
// Web server expects: scanDir/target/phase/files
// CLI may create: scanDir/phase/files
func ensureWebServerStructure(scanDir, target string) error {
	targetSubdir := filepath.Join(scanDir, target)

	// Check if target subdirectory already exists
	if _, err := os.Stat(targetSubdir); err == nil {
		// Structure is already correct
		return nil
	}

	// List of phase directories that may exist at root level
	phasePatterns := []string{
		"1-subdomains", "2-waf", "3-ports", "4-takeover", "4-vhost",
		"5-historic", "6-tech", "6b-secheaders", "7b-jsanalysis",
		"8-vulnscan", "9-screenshots", "10-aiguided",
	}

	// Check if any phase directories exist at root level
	phaseDirsExist := false
	for _, pattern := range phasePatterns {
		phaseDir := filepath.Join(scanDir, pattern)
		if _, err := os.Stat(phaseDir); err == nil {
			phaseDirsExist = true
			break
		}
	}

	if !phaseDirsExist {
		// No phase directories found, nothing to fix
		return nil
	}

	// Create target subdirectory
	if err := os.MkdirAll(targetSubdir, 0755); err != nil {
		return fmt.Errorf("failed to create target subdirectory: %w", err)
	}

	// Move all phase directories and other scan files into target subdirectory
	entries, err := os.ReadDir(scanDir)
	if err != nil {
		return fmt.Errorf("failed to read scan directory: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()

		// Skip the target subdirectory itself and the database file
		if name == target || name == "reconator.db" {
			continue
		}

		srcPath := filepath.Join(scanDir, name)
		dstPath := filepath.Join(targetSubdir, name)

		// Move the directory/file
		if err := os.Rename(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to move %s: %w", name, err)
		}
	}

	return nil
}

// fixScreenshotPaths updates screenshot JSON files to use relative paths instead of absolute remote paths
func fixScreenshotPaths(scanDir, baseName string) error {
	// Find screenshot_results.json files
	screenshotFiles := []string{
		filepath.Join(scanDir, "9-screenshots", "screenshot_results.json"),
	}

	// Also check in target subdirectory
	entries, err := os.ReadDir(scanDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
				targetScreenshotFile := filepath.Join(scanDir, entry.Name(), "9-screenshots", "screenshot_results.json")
				screenshotFiles = append(screenshotFiles, targetScreenshotFile)
			}
		}
	}

	for _, jsonFile := range screenshotFiles {
		// Check if file exists
		if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
			continue
		}

		// Read JSON file
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			continue
		}

		// Parse JSON
		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		// Update file_path in screenshots array
		screenshots, ok := result["screenshots"].([]interface{})
		if !ok {
			continue
		}

		modified := false
		for _, screenshot := range screenshots {
			s, ok := screenshot.(map[string]interface{})
			if !ok {
				continue
			}

			filePath, ok := s["file_path"].(string)
			if !ok {
				continue
			}

			// Replace remote paths with relative paths
			// /home/ubuntu/reconator/target/... -> scanID_target/target/...
			if strings.Contains(filePath, "/home/ubuntu/reconator") || strings.HasPrefix(filePath, "/") {
				// Extract just the filename from the path
				filename := filepath.Base(filePath)

				// Construct relative path from reconator root
				relPath := filepath.Join(baseName, strings.TrimPrefix(filepath.Dir(jsonFile), scanDir)[1:], "screenshots", filename)
				s["file_path"] = relPath
				modified = true
			}
		}

		if !modified {
			continue
		}

		// Write updated JSON back
		updatedData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			continue
		}

		if err := os.WriteFile(jsonFile, updatedData, 0644); err != nil {
			return fmt.Errorf("failed to write updated screenshot JSON: %w", err)
		}
	}

	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate destination path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Copy file
		return copyFile(path, dstPath)
	})
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination directory
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := srcFile.WriteTo(dstFile); err != nil {
		return err
	}

	// Copy permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}
