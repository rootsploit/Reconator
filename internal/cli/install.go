package cli

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/apikeys"
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
	installCmd.Flags().BoolVar(&installExtras, "extras", false, "Also install optional non-Go tools (waymore, findomain, feroxbuster)")
	installCmd.Flags().BoolVar(&installExtras, "extra", false, "Alias for --extras")
}

type installResult struct {
	name    string
	err     error
	skipped bool
}

func runInstall(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)
	gray := color.New(color.FgHiBlack)

	cyan.Println("\n[+] Installing Reconator Dependencies")
	fmt.Println()

	installer := tools.NewInstaller()
	platform := installer.GetPlatform()

	// Show platform info
	fmt.Printf("    Platform: %s/%s\n", platform.OS, platform.Arch)
	if platform.PkgMgr != "" {
		fmt.Printf("    Package Manager: %s\n", platform.PkgMgr)
	} else {
		yellow.Println("    Package Manager: none detected")
	}
	fmt.Println()

	startTime := time.Now()

	// Step 1: Install system dependencies FIRST (required for other tools)
	fmt.Println("[*] Installing system dependencies...")

	// Critical dependencies list
	criticalDeps := []struct {
		name    string
		check   func() bool
		install func() error
		desc    string
	}{
		{
			name:    "libpcap",
			check:   platform.HasLibpcap,
			install: installer.InstallLibpcap,
			desc:    "required for naabu",
		},
		{
			name:    "git",
			check:   func() bool { return installer.IsInstalled("git") },
			install: func() error { return installer.InstallSystemTool("git") },
			desc:    "required for massdns and templates",
		},
	}

	for _, dep := range criticalDeps {
		spinner := tools.NewSpinner(fmt.Sprintf("Checking %s (%s)...", dep.name, dep.desc))
		spinner.Start()
		if dep.check() {
			spinner.Success(fmt.Sprintf("%s: OK", dep.name))
		} else {
			spinner.Update(fmt.Sprintf("Installing %s...", dep.name))
			if err := dep.install(); err != nil {
				spinner.Fail(fmt.Sprintf("%s: %v", dep.name, err))
			} else {
				spinner.Success(fmt.Sprintf("%s: OK", dep.name))
			}
		}
	}

	// Step 2: Install system tools (nmap, etc.)
	fmt.Println("\n[*] Installing system tools...")
	sysTools := installer.GetSystemTools()
	// Sort for consistent output
	sort.Strings(sysTools)
	for _, name := range sysTools {
		// Skip dependencies already installed above
		if name == "git" {
			continue
		}
		spinner := tools.NewSpinner(fmt.Sprintf("Installing %s...", name))
		spinner.Start()
		if installer.IsInstalled(name) {
			spinner.Skip(fmt.Sprintf("%s: already installed", name))
		} else if err := installer.InstallSystemTool(name); err != nil {
			spinner.Fail(fmt.Sprintf("%s: %v", name, err))
		} else {
			spinner.Success(fmt.Sprintf("%s: OK", name))
		}
	}

	// Step 3: Download wordlists
	fmt.Println("\n[*] Downloading wordlists...")
	wordlists := installer.GetWordlists()
	progress := tools.NewProgressBar(len(wordlists))
	var wlResults []installResult
	var wlMu sync.Mutex

	for _, wl := range wordlists {
		err := installer.InstallWordlist(wl)
		wlMu.Lock()
		wlResults = append(wlResults, installResult{name: wl.Name, err: err})
		progress.Increment()
		wlMu.Unlock()
	}
	progress.Done()

	for _, r := range wlResults {
		if r.err != nil {
			yellow.Printf("    ✗ %s: %v\n", r.name, r.err)
		} else {
			green.Printf("    ✓ %s\n", r.name)
		}
	}
	gray.Printf("    Wordlists installed to: %s\n", tools.WordlistDir())

	// Step 4: Install Go tools in parallel
	fmt.Println("\n[*] Installing Go-based tools...")
	goTools := installer.GetGoTools()
	goProgress := tools.NewProgressBar(len(goTools))
	goResults := make(chan installResult, len(goTools))
	sem := make(chan struct{}, 4) // Max 4 concurrent installs

	var goWg sync.WaitGroup
	for _, tool := range goTools {
		goWg.Add(1)
		go func(t tools.Tool) {
			defer goWg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			var result installResult
			result.name = t.Name

			if installer.IsInstalled(t.Binary) {
				result.skipped = true
			} else {
				result.err = installer.InstallGoTool(t)
			}
			goResults <- result
			goProgress.Increment()
		}(tool)
	}

	go func() {
		goWg.Wait()
		close(goResults)
	}()

	var goResultList []installResult
	for r := range goResults {
		goResultList = append(goResultList, r)
	}
	goProgress.Done()

	// Sort results for consistent output
	sort.Slice(goResultList, func(i, j int) bool {
		return goResultList[i].name < goResultList[j].name
	})

	// Print Go tools results
	var okCount, skipCount, failCount int
	for _, r := range goResultList {
		if r.skipped {
			skipCount++
			gray.Printf("    ○ %s: already installed\n", r.name)
		} else if r.err != nil {
			failCount++
			yellow.Printf("    ✗ %s: %v\n", r.name, r.err)
		} else {
			okCount++
			green.Printf("    ✓ %s\n", r.name)
		}
	}

	// Step 5: Install nuclei templates
	fmt.Println("\n[*] Installing nuclei templates...")
	spinner := tools.NewSpinner("Cloning nuclei-templates...")
	spinner.Start()
	if err := installer.InstallNucleiTemplates(); err != nil {
		spinner.Fail(fmt.Sprintf("nuclei-templates: %v", err))
	} else {
		spinner.Success("nuclei-templates: OK (~/nuclei-templates)")
	}

	// Step 6: Install optional tools if requested
	if installExtras {
		fmt.Println("\n[*] Installing optional tools...")

		// Ensure Python/pipx is available for Python tools
		if !installer.IsInstalled("pipx") && !installer.IsInstalled("pip3") {
			spinner := tools.NewSpinner("Installing Python dependencies...")
			spinner.Start()
			// Try to install python3 and pipx
			if err := installer.InstallSystemTool("python3"); err == nil {
				installer.InstallSystemTool("pipx")
			}
			if installer.IsInstalled("pipx") || installer.IsInstalled("pip3") {
				spinner.Success("Python: OK")
			} else {
				spinner.Fail("Python: install manually (apt install python3 pipx)")
			}
		}

		// Python tools
		pythonTools := installer.GetPythonTools()
		for _, tool := range pythonTools {
			spinner := tools.NewSpinner(fmt.Sprintf("Installing %s (Python)...", tool.Name))
			spinner.Start()
			if installer.IsInstalled(tool.Binary) {
				spinner.Skip(fmt.Sprintf("%s: already installed", tool.Name))
			} else if err := installer.InstallPythonTool(tool); err != nil {
				spinner.Fail(fmt.Sprintf("%s: %v", tool.Name, err))
			} else {
				spinner.Success(fmt.Sprintf("%s: OK", tool.Name))
			}
		}

		// Rust tools (use GitHub releases, no cargo needed)
		rustTools := installer.GetRustTools()
		for _, tool := range rustTools {
			spinner := tools.NewSpinner(fmt.Sprintf("Installing %s...", tool.Name))
			spinner.Start()
			if installer.IsInstalled(tool.Binary) {
				spinner.Skip(fmt.Sprintf("%s: already installed", tool.Name))
			} else if err := installer.InstallRustTool(tool); err != nil {
				spinner.Fail(fmt.Sprintf("%s: %v", tool.Name, err))
			} else {
				spinner.Success(fmt.Sprintf("%s: OK", tool.Name))
			}
		}
	}

	// Step 7: Check Chrome for screenshots
	fmt.Println("\n[*] Checking Chrome (required for screenshots)...")
	chromeInfo := installer.CheckChrome()
	if chromeInfo.Installed {
		green.Printf("    ✓ Chrome: %s\n", chromeInfo.Version)
		gray.Printf("      Path: %s\n", chromeInfo.Path)
	} else {
		yellow.Println("    ○ Chrome: not found (required for gowitness screenshots)")
		yellow.Printf("      %s\n", installer.GetChromeInstallInstructions())
	}

	// Step 8: Create unified config and import existing keys
	fmt.Println("\n[*] Setting up unified configuration...")

	created, imported, err := apikeys.CreateAndImport()
	if err != nil {
		yellow.Printf("    ✗ config: %v\n", err)
	} else {
		configPath := apikeys.GetDefaultConfigPath()
		if created {
			green.Printf("    ✓ Created unified config: %s\n", configPath)
		} else {
			green.Printf("    ✓ Config already exists: %s\n", configPath)
		}
		if imported > 0 {
			green.Printf("    ✓ Imported %d existing keys from tool configs\n", imported)
		}
	}

	// Sync keys to tool configs (subfinder, notify)
	mgr := apikeys.NewManager()
	if err := mgr.Load(); err == nil && (mgr.HasOSINTKeys() || mgr.HasNotifyConfig()) {
		results := mgr.Sync()
		for _, result := range results {
			if result.Success && result.KeysAdded > 0 {
				green.Printf("    ✓ Synced %d keys to %s\n", result.KeysAdded, result.Tool)
			}
		}
	}

	gray.Println("\n    Edit ~/.reconator/config.yaml to add your API keys")
	gray.Println("    Then run: reconator config sync")

	// Summary
	elapsed := time.Since(startTime).Round(time.Second)
	fmt.Println()
	cyan.Println("─────────────────────────────────────────────────")
	green.Printf("[+] Installation complete! (%s)\n", elapsed)
	fmt.Printf("    Go tools: %d installed, %d skipped, %d failed\n", okCount, skipCount, failCount)
	fmt.Println("    Run 'reconator check' to verify all tools are working")

	return nil
}
