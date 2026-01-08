package cli

import (
	"fmt"
	"sync"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/spf13/cobra"
)

var (
	installExtras bool

	installCmd = &cobra.Command{
		Use:   "install",
		Short: "Install required tools",
		Long: `Install all required reconnaissance tools.

By default, installs only Go-based tools using 'go install'.
Use --extras to also install optional Python/Rust tools.

Examples:
  reconator install           # Install Go tools only
  reconator install --extras  # Install Go tools + optional extras`,
		RunE: runInstall,
	}
)

func init() {
	installCmd.Flags().BoolVar(&installExtras, "extras", false, "Also install optional non-Go tools (waymore, vita, findomain)")
	installCmd.Flags().BoolVar(&installExtras, "extra", false, "Alias for --extras")
}

type installResult struct {
	name string
	err  error
}

func runInstall(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Println("\n[+] Installing Reconator Dependencies\n")

	installer := tools.NewInstaller()

	// Download wordlists in parallel
	fmt.Println("[*] Downloading wordlists...")
	wordlists := installer.GetWordlists()
	wlResults := make(chan installResult, len(wordlists))
	var wlWg sync.WaitGroup

	for _, wl := range wordlists {
		wlWg.Add(1)
		go func(w tools.Wordlist) {
			defer wlWg.Done()
			err := installer.InstallWordlist(w)
			wlResults <- installResult{name: w.Name, err: err}
		}(wl)
	}

	go func() {
		wlWg.Wait()
		close(wlResults)
	}()

	for r := range wlResults {
		fmt.Printf("    %s: ", r.name)
		if r.err != nil {
			yellow.Printf("SKIP (%v)\n", r.err)
		} else {
			green.Println("OK")
		}
	}
	fmt.Printf("    Wordlists installed to: %s\n", tools.WordlistDir())

	// Install Go tools in parallel (max 4 concurrent to avoid overloading)
	fmt.Println("\n[*] Installing Go-based tools (parallel)...")
	goTools := installer.GetGoTools()
	goResults := make(chan installResult, len(goTools))
	sem := make(chan struct{}, 4) // Semaphore for max 4 concurrent installs

	var goWg sync.WaitGroup
	for _, tool := range goTools {
		goWg.Add(1)
		go func(t tools.Tool) {
			defer goWg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release
			err := installer.InstallGoTool(t)
			goResults <- installResult{name: t.Name, err: err}
		}(tool)
	}

	go func() {
		goWg.Wait()
		close(goResults)
	}()

	for r := range goResults {
		fmt.Printf("    %s: ", r.name)
		if r.err != nil {
			yellow.Printf("SKIP (%v)\n", r.err)
		} else {
			green.Println("OK")
		}
	}

	// Install optional tools if requested
	if installExtras {
		fmt.Println("\n[*] Installing optional tools...")

		// Python tools (sequential - pip doesn't handle parallel well)
		pythonTools := installer.GetPythonTools()
		for _, tool := range pythonTools {
			fmt.Printf("    Installing %s (Python)... ", tool.Name)
			if err := installer.InstallPythonTool(tool); err != nil {
				yellow.Printf("SKIP (%v)\n", err)
			} else {
				green.Println("OK")
			}
		}

		// Rust tools (sequential - cargo doesn't handle parallel well)
		rustTools := installer.GetRustTools()
		for _, tool := range rustTools {
			fmt.Printf("    Installing %s (Rust)... ", tool.Name)
			if err := installer.InstallRustTool(tool); err != nil {
				yellow.Printf("SKIP (%v)\n", err)
			} else {
				green.Println("OK")
			}
		}
	}

	green.Println("\n[+] Installation complete!")
	fmt.Println("    Run 'reconator check' to verify all tools are working")

	return nil
}
