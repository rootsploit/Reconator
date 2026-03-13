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
	Long: `Update reconator to the latest version using go install.

This will:
1. Check the Go module proxy for the latest version
2. Install the latest version via go install
3. Backup the current binary (saved as reconator.old)

The old binary is kept as a backup in case you need to rollback.

Examples:
  reconator update              # Check and install latest version
  reconator update --force      # Force reinstall via go install @latest
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

	u := updater.New(currentVersion)

	// Force mode: skip version check, just go install @latest
	if updateForce {
		fmt.Printf("Current version: %s\n", currentVersion)
		fmt.Println("Force reinstalling latest version...")
		fmt.Println()

		if err := u.ForceUpdate(nil); err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		return nil
	}

	// Normal mode: check for updates first
	fmt.Printf("Current version: %s\n", currentVersion)
	fmt.Println("Checking for updates...")
	fmt.Println()

	updateInfo, err := u.CheckForUpdate()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if updateInfo == nil {
		fmt.Println("✓ You are already running the latest version!")
		return nil
	}

	// Display update information
	fmt.Printf("New version available: %s → %s\n", updateInfo.CurrentVersion, updateInfo.LatestVersion)
	fmt.Println()

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

	if err := u.Update(updateInfo, nil); err != nil {
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
