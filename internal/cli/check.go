package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check installed tools",
	Long: `Check which reconnaissance tools are installed and available.

Displays the status of all required and optional tools.`,
	RunE: runCheck,
}

func runCheck(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Println("\n[+] Reconator Tool Status\n")

	checker := tools.NewChecker()
	status := checker.CheckAll()

	// Required Go tools
	fmt.Println("Required Go Tools:")
	fmt.Println("─────────────────────────────────────────────────────")
	requiredCount := 0
	requiredInstalled := 0

	for _, tool := range status.Go {
		requiredCount++
		fmt.Printf("  %-15s ", tool.Name)
		if tool.Installed {
			requiredInstalled++
			green.Printf("✓ installed")
			if tool.Version != "" {
				fmt.Printf(" (%s)", tool.Version)
			}
			fmt.Println()
		} else {
			red.Println("✗ not found")
		}
	}

	// Optional Python tools
	fmt.Println("\nOptional Python Tools:")
	fmt.Println("─────────────────────────────────────────────────────")
	optionalCount := 0
	optionalInstalled := 0

	for _, tool := range status.Python {
		optionalCount++
		fmt.Printf("  %-15s ", tool.Name)
		if tool.Installed {
			optionalInstalled++
			green.Printf("✓ installed")
			if tool.Version != "" {
				fmt.Printf(" (%s)", tool.Version)
			}
			fmt.Println()
		} else {
			yellow.Println("○ not found (optional)")
		}
	}

	// Optional Rust tools
	fmt.Println("\nOptional Rust Tools:")
	fmt.Println("─────────────────────────────────────────────────────")

	for _, tool := range status.Rust {
		optionalCount++
		fmt.Printf("  %-15s ", tool.Name)
		if tool.Installed {
			optionalInstalled++
			green.Printf("✓ installed")
			if tool.Version != "" {
				fmt.Printf(" (%s)", tool.Version)
			}
			fmt.Println()
		} else {
			yellow.Println("○ not found (optional)")
		}
	}

	// Wordlists
	fmt.Println("\nWordlists:")
	fmt.Println("─────────────────────────────────────────────────────")
	wordlistStatus := tools.CheckWordlists()
	wordlistCount := 0
	wordlistInstalled := 0
	for name, installed := range wordlistStatus {
		wordlistCount++
		fmt.Printf("  %-30s ", name)
		if installed {
			wordlistInstalled++
			green.Println("✓ installed")
		} else {
			red.Println("✗ not found")
		}
	}

	// Show current wordlist/resolver paths
	if wl := tools.FindWordlist(); wl != "" {
		fmt.Printf("  Active wordlist: %s\n", wl)
	}
	if res := tools.FindResolvers(); res != "" {
		fmt.Printf("  Active resolvers: %s\n", res)
	}

	// Summary
	fmt.Println("\n─────────────────────────────────────────────────────")
	fmt.Printf("Required: %d/%d installed\n", requiredInstalled, requiredCount)
	fmt.Printf("Optional: %d/%d installed\n", optionalInstalled, optionalCount)
	fmt.Printf("Wordlists: %d/%d installed\n", wordlistInstalled, wordlistCount)

	if requiredInstalled < requiredCount || wordlistInstalled < wordlistCount {
		fmt.Println()
		yellow.Println("⚠ Some required tools or wordlists are missing!")
		fmt.Println("  Run 'reconator install' to install them")
	} else {
		fmt.Println()
		green.Println("✓ All required tools and wordlists are installed!")
	}

	if optionalInstalled < optionalCount {
		yellow.Println("  Run 'reconator install --extras' for optional tools")
	}

	return nil
}
