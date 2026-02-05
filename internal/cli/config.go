package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/apikeys"
	"github.com/spf13/cobra"
)

var (
	// Config command flags
	configTestNotify bool
	configTestOSINT  bool

	configCmd = &cobra.Command{
		Use:   "config",
		Short: "Manage API keys and configuration",
		Long: `Manage API keys and tool configurations.

Reconator uses a unified config file (~/.reconator/config.yaml) as the single
source of truth for ALL API keys (AI, OSINT, notifications). These keys are
synced to tool-specific configs (subfinder, notify) when you run 'reconator config sync'.

Commands:
  show  - Display current configuration
  sync  - Sync keys to subfinder, notify, etc.
  test  - Validate API keys
  init  - Create template config file

Examples:
  reconator config show              # Show current config
  reconator config sync              # Sync keys to tool configs
  reconator config test              # Test all configured API keys
  reconator config test --osint      # Test only OSINT keys
  reconator config init              # Create template config file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default to showing help
			return cmd.Help()
		},
	}

	configShowCmd = &cobra.Command{
		Use:   "show",
		Short: "Display current configuration",
		Long:  "Shows all configured API keys (masked) and their sync targets.",
		RunE:  runConfigShow,
	}

	configSyncCmd = &cobra.Command{
		Use:   "sync",
		Short: "Sync API keys to tool configurations",
		Long: `Syncs API keys from ~/.reconator/api-config.yaml to tool-specific configs:
  - Subfinder: ~/.config/subfinder/provider-config.yaml
  - Notify: ~/.config/notify/provider-config.yaml

Uses merge approach: only updates configured keys, preserves existing settings.`,
		RunE: runConfigSync,
	}

	configTestCmd = &cobra.Command{
		Use:   "test",
		Short: "Validate API keys",
		Long: `Tests configured API keys by making requests to their respective APIs.
Checks key validity and reports any issues.`,
		RunE: runConfigTest,
	}

	configInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Create template config file",
		Long: `Creates a template configuration file at ~/.reconator/api-config.yaml
if it doesn't already exist.`,
		RunE: runConfigInit,
	}
)

func init() {
	// Add subcommands
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSyncCmd)
	configCmd.AddCommand(configTestCmd)
	configCmd.AddCommand(configInitCmd)

	// Test command flags
	configTestCmd.Flags().BoolVar(&configTestNotify, "notify", false, "Test notification webhooks (sends test message)")
	configTestCmd.Flags().BoolVar(&configTestOSINT, "osint", false, "Test only OSINT API keys")
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\n[+] Reconator Configuration")

	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		fmt.Printf("    Warning: Could not load config: %v\n", err)
	}

	fmt.Println()
	fmt.Println(mgr.ShowConfig())

	// Show config file location
	gray := color.New(color.FgHiBlack)
	gray.Printf("\nEdit configuration: %s\n", apikeys.GetDefaultConfigPath())
	gray.Println("Then run: reconator config sync")

	return nil
}

func runConfigSync(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	gray := color.New(color.FgHiBlack)

	cyan.Println("\n[+] Syncing API Keys")

	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		if os.IsNotExist(err) {
			yellow.Println("    Config file not found. Creating template...")
			if err := apikeys.CreateDefaultConfig(); err != nil {
				return fmt.Errorf("failed to create config: %w", err)
			}
			green.Printf("    Created: %s\n", apikeys.GetDefaultConfigPath())
			gray.Println("    Edit this file to add your API keys, then run 'reconator config sync' again.")
			return nil
		}
		return err
	}

	// Check if there are any keys to sync
	if !mgr.HasOSINTKeys() && !mgr.HasNotifyConfig() {
		yellow.Println("    No API keys configured yet.")
		gray.Printf("    Edit %s to add your keys.\n", apikeys.GetDefaultConfigPath())
		return nil
	}

	fmt.Println()

	// Perform sync
	results := mgr.Sync()

	for _, result := range results {
		if result.Success {
			if result.KeysAdded > 0 {
				green.Printf("    ✓ %s: synced %d keys to %s\n", result.Tool, result.KeysAdded, result.ConfigPath)
			} else if result.Error != "" {
				gray.Printf("    ○ %s: %s\n", result.Tool, result.Error)
			} else {
				gray.Printf("    ○ %s: already up to date\n", result.Tool)
			}
		} else {
			yellow.Printf("    ✗ %s: %s\n", result.Tool, result.Error)
		}
	}

	fmt.Println()
	green.Println("[+] Sync complete!")
	gray.Println("    Run 'reconator config test' to validate your keys.")

	return nil
}

func runConfigTest(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	gray := color.New(color.FgHiBlack)

	cyan.Println("\n[+] Testing API Keys")

	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if mgr.GetKeyCount() == 0 {
		yellow.Println("    No API keys configured.")
		gray.Printf("    Edit %s to add your keys.\n", apikeys.GetDefaultConfigPath())
		return nil
	}

	fmt.Println()

	// Test keys
	results := mgr.TestAllKeys()

	validCount := 0
	invalidCount := 0

	for _, result := range results {
		statusIcon := "✓"
		statusColor := green

		if !result.Valid {
			if result.Error == "" || result.Error == "testing not implemented for this provider" {
				statusIcon = "○"
				statusColor = gray
			} else {
				statusIcon = "✗"
				statusColor = red
				invalidCount++
			}
		} else {
			validCount++
		}

		statusColor.Printf("    %s %-20s %s", statusIcon, result.Provider, result.Key)
		if result.Latency > 0 {
			gray.Printf(" (%dms)", result.Latency.Milliseconds())
		}
		if result.Error != "" && result.Error != "configured (full test requires cvemap)" {
			if result.Valid {
				gray.Printf(" - %s", result.Error)
			} else {
				yellow.Printf(" - %s", result.Error)
			}
		}
		fmt.Println()
	}

	fmt.Println()
	if invalidCount == 0 {
		green.Printf("[+] All %d keys validated successfully!\n", validCount)
	} else {
		yellow.Printf("[!] %d valid, %d invalid keys\n", validCount, invalidCount)
	}

	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	gray := color.New(color.FgHiBlack)

	cyan.Println("\n[+] Initializing Configuration")

	configPath := apikeys.GetDefaultConfigPath()

	// Check if already exists
	if _, err := os.Stat(configPath); err == nil {
		yellow.Printf("    Config file already exists: %s\n", configPath)
		gray.Println("    Use 'reconator config show' to view current configuration.")
		return nil
	}

	// Create template
	if err := apikeys.CreateDefaultConfig(); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	green.Printf("    ✓ Created: %s\n", configPath)
	fmt.Println()

	gray.Println("Next steps:")
	gray.Println("  1. Edit the config file to add your API keys")
	gray.Println("  2. Run 'reconator config sync' to sync keys to tool configs")
	gray.Println("  3. Run 'reconator config test' to validate your keys")

	return nil
}

// SyncKeysOnStartup syncs API keys if config file exists and has keys
// This is called during scan startup to ensure tools have latest keys
func SyncKeysOnStartup() {
	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		return // Silently skip if no config
	}

	if mgr.HasOSINTKeys() || mgr.HasNotifyConfig() {
		// Sync in background (don't block startup)
		go func() {
			time.Sleep(100 * time.Millisecond) // Small delay to not interfere with startup
			mgr.Sync()
		}()
	}
}
