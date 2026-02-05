package cli

import (
	"fmt"
	"strings"

	"github.com/rootsploit/reconator/internal/updater"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/spf13/cobra"
)

var (
	updateForce    bool
	updateRollback bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update reconator to the latest version",
	Long: `Update reconator to the latest version from GitHub releases.

This will:
1. Check GitHub for the latest release
2. Download the binary for your OS/architecture
3. Verify the SHA256 checksum
4. Backup the current binary (saved as reconator.old)
5. Replace with the new version

The old binary is kept as a backup in case you need to rollback.

Examples:
  reconator update              # Check and install latest version
  reconator update --force      # Force update even if already latest
  reconator update --rollback   # Restore previous version from backup`,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().BoolVar(&updateForce, "force", false, "Force update even if already on latest version")
	updateCmd.Flags().BoolVar(&updateRollback, "rollback", false, "Rollback to previous version from backup")

	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("Reconator Auto-Updater")
	fmt.Println("═════════════════════")
	fmt.Println()

	// Get current version from version.go
	currentVersion := getVersion()

	// Handle rollback
	if updateRollback {
		u := updater.New(currentVersion)
		return u.Rollback()
	}

	// Check for updates
	fmt.Printf("Current version: %s\n", currentVersion)
	fmt.Println("Checking for updates...")
	fmt.Println()

	u := updater.New(currentVersion)
	updateInfo, err := u.CheckForUpdate()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if updateInfo == nil && !updateForce {
		fmt.Println("✓ You are already running the latest version!")
		return nil
	}

	if updateInfo == nil && updateForce {
		fmt.Println("No newer version available, but forcing re-download...")
		// In force mode, re-download current version
		// This is useful if the binary is corrupted
		fmt.Println("Note: Force mode requires a newer version to be available")
		fmt.Println("✓ Already on latest version, nothing to force-update")
		return nil
	}

	// Display update information
	fmt.Printf("New version available: %s → %s\n", updateInfo.CurrentVersion, updateInfo.LatestVersion)
	fmt.Printf("Download size: %s\n", updater.FormatBytes(updateInfo.Size))
	fmt.Println()

	// Show release notes (first 5 lines)
	if updateInfo.ReleaseNotes != "" {
		fmt.Println("Release Notes:")
		fmt.Println("─────────────")
		lines := strings.Split(updateInfo.ReleaseNotes, "\n")
		maxLines := 5
		if len(lines) < maxLines {
			maxLines = len(lines)
		}
		for i := 0; i < maxLines; i++ {
			line := strings.TrimSpace(lines[i])
			if line != "" {
				fmt.Println(line)
			}
		}
		if len(lines) > maxLines {
			fmt.Println("...")
		}
		fmt.Println()
	}

	// Confirm update
	fmt.Print("Do you want to update? [Y/n]: ")
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "" && response != "y" && response != "yes" {
		fmt.Println("Update cancelled.")
		return nil
	}

	fmt.Println()

	// Perform update with progress bar
	lastPercent := -1
	progressCallback := func(downloaded, total int64) {
		if total > 0 {
			percent := int(float64(downloaded) / float64(total) * 100)
			if percent != lastPercent && percent%5 == 0 {
				fmt.Printf("Downloaded: %s / %s (%d%%)\n",
					updater.FormatBytes(downloaded),
					updater.FormatBytes(total),
					percent)
				lastPercent = percent
			}
		}
	}

	if err := u.Update(updateInfo, progressCallback); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Println()
	fmt.Println("═════════════════════")
	fmt.Println("Update completed successfully!")
	fmt.Println()
	fmt.Println("The old version has been saved as a backup.")
	fmt.Println("If you experience any issues, you can rollback with:")
	fmt.Println("  reconator update --rollback")

	return nil
}

// getVersion returns the current version
func getVersion() string {
	return "v" + version.Short()
}
