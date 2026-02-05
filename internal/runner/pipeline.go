package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/debug"
	"github.com/rootsploit/reconator/internal/dirbrute"
	"github.com/rootsploit/reconator/internal/historic"
	"github.com/rootsploit/reconator/internal/iprange"
	"github.com/rootsploit/reconator/internal/jsanalysis"
	"github.com/rootsploit/reconator/internal/output"
	"github.com/rootsploit/reconator/internal/pipeline"
	"github.com/rootsploit/reconator/internal/portscan"
	"github.com/rootsploit/reconator/internal/report"
	"github.com/rootsploit/reconator/internal/screenshot"
	"github.com/rootsploit/reconator/internal/secheaders"
	"github.com/rootsploit/reconator/internal/storage"
	"github.com/rootsploit/reconator/internal/subdomain"
	"github.com/rootsploit/reconator/internal/sysinfo"
	"github.com/rootsploit/reconator/internal/takeover"
	"github.com/rootsploit/reconator/internal/techdetect"
	"github.com/rootsploit/reconator/internal/tools"
	"github.com/rootsploit/reconator/internal/trufflehog"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/rootsploit/reconator/internal/vhost"
	"github.com/rootsploit/reconator/internal/vulnscan"
	"github.com/rootsploit/reconator/internal/waf"
)

// PipelineRunner executes reconnaissance using the pipeline executor
// Benefits over procedural runner:
// - Automatic dependency management
// - Parallel execution of independent phases
// - Resumable scans (reads from storage)
// - Cleaner phase lifecycle management
type PipelineRunner struct {
	cfg      *config.Config
	checker  *tools.Checker
	out      *output.Manager
	storage  storage.Storage
	progress *PhaseProgress
}

// NewPipelineRunner creates a new pipeline-based runner
func NewPipelineRunner(cfg *config.Config) *PipelineRunner {
	return &PipelineRunner{
		cfg:     cfg,
		checker: tools.NewChecker(),
	}
}

// Run executes the pipeline-based reconnaissance
func (r *PipelineRunner) Run() error {
	start := time.Now()
	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)
	gray := color.New(color.FgHiBlack)

	// Auto-detect system resources and apply profile settings
	r.applyPerformanceProfile()

	// Enable debug logging if requested
	if r.cfg.Debug {
		debug.Enable()
		cyan.Println("[DEBUG MODE ENABLED] Detailed timing logs will be shown")
		// Dump feature flags that affect phase execution
		fmt.Printf("[DEBUG] Config: EnableScreenshots=%v, PassiveMode=%v, SkipDirBrute=%v, SkipVulnScan=%v\n",
			r.cfg.EnableScreenshots, r.cfg.PassiveMode, r.cfg.SkipDirBrute, r.cfg.SkipVulnScan)
		fmt.Println()
	}

	if missing := r.checker.GetMissingRequired(); len(missing) > 0 {
		yellow.Printf("\n⚠ Missing required tools: %v\n", missing)
		fmt.Println("  Run 'reconator install' to install them")
	}

	targets, err := r.getTargets()
	if err != nil {
		return err
	}

	// Show performance settings
	gray.Printf("[*] Profile: %s | Threads: %d | DNS: %d | Rate: %d/s | Parallel: %d\n",
		r.cfg.Profile, r.cfg.Threads, r.cfg.DNSThreads, r.cfg.RateLimit, r.cfg.MaxConcTargets)

	maxConcurrent := r.cfg.MaxConcTargets
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}

	cyan.Printf("\n[+] Starting pipeline reconnaissance for %d target(s)", len(targets))
	if maxConcurrent > 1 && len(targets) > 1 {
		cyan.Printf(" [%d parallel]", maxConcurrent)
	}
	cyan.Println()
	fmt.Println()

	// Process targets with parallelism based on config
	if maxConcurrent == 1 || len(targets) == 1 {
		// Sequential processing (original behavior)
		for _, t := range targets {
			if err := r.processTarget(t); err != nil {
				yellow.Printf("⚠ Error processing %s: %v\n", t, err)
			}
		}
	} else {
		// Parallel processing with semaphore
		var wg sync.WaitGroup
		sem := make(chan struct{}, maxConcurrent)
		errors := make(chan error, len(targets))

		for _, t := range targets {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				sem <- struct{}{}        // Acquire
				defer func() { <-sem }() // Release

				if err := r.processTarget(target); err != nil {
					errors <- fmt.Errorf("%s: %v", target, err)
				}
			}(t)
		}

		// Wait for all targets to complete
		wg.Wait()
		close(errors)

		// Report any errors
		for err := range errors {
			yellow.Printf("⚠ Error: %v\n", err)
		}
	}

	green.Printf("\n[+] Pipeline reconnaissance complete! Total time: %s\n", time.Since(start).Round(time.Second))
	debug.Summary()

	return nil
}

// processTarget runs the pipeline for a single target
func (r *PipelineRunner) processTarget(target string) error {
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize progress tracker (respects debug mode internally)
	r.progress = NewPhaseProgress(r.cfg.Debug)

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	// Check for interrupted scans BEFORE creating directory
	var sqliteDB *storage.SQLiteStorage
	var resumeScanID string
	var scanID string
	var completedPhases map[pipeline.Phase]bool

	if r.cfg.EnableSQLite {
		var err error
		// Open global database to check for incomplete scans
		sqliteDB, err = storage.NewSQLiteStorage(r.cfg.OutputDir)
		if err == nil && r.cfg.AutoResume {
			// Check for interrupted scan
			incompleteScan, _ := sqliteDB.GetIncompleteScan(ctx, target)
			if incompleteScan != nil {
				resumeScanID = incompleteScan.ID
				scanID = incompleteScan.ID
				yellow.Printf("[*] Found interrupted scan: %s (started %s)\n",
					incompleteScan.ID, incompleteScan.StartTime.Format("2006-01-02 15:04:05"))

				// Get completed phases
				completedPhaseNames, _ := sqliteDB.GetCompletedPhases(ctx, resumeScanID)
				completedPhases = make(map[pipeline.Phase]bool)
				for _, name := range completedPhaseNames {
					if phase, ok := r.phaseFromString(name); ok {
						completedPhases[phase] = true
					}
				}

				if len(completedPhases) > 0 {
					green.Printf("[+] Resuming scan - %d phases already completed\n", len(completedPhases))
				}
			}
		}
	}

	// Generate scan ID if not resuming
	if scanID == "" {
		scanID = storage.GenerateScanID()
	}

	// Initialize output directory with format: {scan_id}_{target}
	outDirName := fmt.Sprintf("%s_%s", scanID, target)
	outDir := filepath.Join(r.cfg.OutputDir, outDirName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	cyan.Printf("  Target: %s", target)
	if r.cfg.PassiveMode {
		cyan.Printf(" [PASSIVE]")
	}
	if resumeScanID != "" {
		cyan.Printf(" [RESUME]")
	}
	cyan.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Print phase list in clean mode (progress tracker handles debug check)
	r.progress.PrintPhaseList()

	// Initialize output manager with SQLite
	var err error
	if r.cfg.EnableSQLite {
		// Use resumed scan ID if available, otherwise use the generated scanID
		useScanID := scanID
		if resumeScanID != "" {
			useScanID = resumeScanID
		}
		r.out, err = output.NewManagerWithScanID(outDir, useScanID)
		if err != nil {
			r.out = output.NewManager(outDir)
			r.out.SetScanID(useScanID)
		}
	} else {
		r.out = output.NewManager(outDir)
		r.out.SetScanID(scanID)
	}
	defer r.out.Close()

	r.out.SetScanMeta(target, version.Version)

	// Get SQLite storage for pipeline (or create wrapper)
	var pipelineStorage storage.Storage
	if r.out.HasSQLite() {
		pipelineStorage = r.out.SQLiteDB()
		if sqliteDB != nil {
			sqliteDB.Close() // Use the one from output manager instead
		}
	} else if sqliteDB != nil {
		pipelineStorage = sqliteDB
		defer sqliteDB.Close()
	} else {
		// Create file-based storage wrapper
		pipelineStorage, _ = storage.NewSQLiteStorage(outDir)
		defer pipelineStorage.(*storage.SQLiteStorage).Close()
	}

	// Set up signal handling to mark scan as interrupted on SIGINT/SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	interrupted := false

	go func() {
		<-sigChan
		interrupted = true
		yellow.Println("\n[!] Interrupt received, saving progress...")

		// Mark scan as interrupted
		if sqliteStorage, ok := pipelineStorage.(*storage.SQLiteStorage); ok {
			sqliteStorage.MarkScanInterrupted(ctx, r.out.ScanID())
		}

		cancel()
	}()
	defer signal.Stop(sigChan)

	// Create pipeline executor
	exec := pipeline.NewExecutor(pipelineStorage, r.cfg, r.out.ScanID(), target)

	// Register all phase adapters
	pipeline.RegisterAllAdapters(exec, r.cfg, r.checker)

	// Get phases to execute based on config
	phasesToRun := r.getPhasesToRun()

	// Execute phases in parallel groups
	results := make(map[pipeline.Phase]*pipeline.PhaseResult)
	completed := make(map[pipeline.Phase]bool)

	// Initialize completed phases from resume (if any)
	if completedPhases == nil {
		completedPhases = make(map[pipeline.Phase]bool)
	}
	for phase := range completedPhases {
		completed[phase] = true
	}

	// Get SQLite storage for saving phase status
	var sqliteStorage *storage.SQLiteStorage
	if s, ok := pipelineStorage.(*storage.SQLiteStorage); ok {
		sqliteStorage = s
	}

	// Detect target type to determine execution order
	isASN := iprange.IsASN(target) || iprange.IsIPTarget(target)

	// Get execution order (phases grouped by level)
	// For ASN/IP targets: IPRange must run before Subdomain to discover TLDs
	groups := pipeline.GetParallelGroupsForTarget(isASN)

	if isASN {
		cyan.Printf("[*] ASN/IP target detected - running IP Range discovery first\n\n")
	}

	for _, group := range groups {
		// Check for interruption
		if interrupted {
			yellow.Println("[!] Scan interrupted, progress saved")
			break
		}

		// Filter to only phases we want to run
		var groupPhases []pipeline.Phase
		for _, phase := range group.Phases {
			if phasesToRun[phase] && !r.shouldSkipPhase(phase) && !completedPhases[phase] {
				groupPhases = append(groupPhases, phase)
			} else if r.cfg.Debug && phase == pipeline.PhaseScreenshot {
				// Debug: explain why screenshot was filtered out
				if !phasesToRun[phase] {
					fmt.Println("    [DEBUG] Screenshot not in phasesToRun")
				} else if completedPhases[phase] {
					fmt.Println("    [DEBUG] Screenshot already completed in previous run")
				}
				// shouldSkipPhase already logs its reason
			}
		}

		if len(groupPhases) == 0 {
			continue
		}

		// Check dependencies - phases can run if:
		// 1. All dependencies are completed in this run, OR
		// 2. Dependencies were skipped (not applicable for this target type), OR
		// 3. Dependencies were not requested but data exists from previous runs
		var runnablePhases []pipeline.Phase
		for _, phase := range groupPhases {
			deps := pipeline.GetDependencies(phase)
			allDepsComplete := true
			for _, dep := range deps {
				// If dependency was requested in this run, it must be completed OR skipped
				if phasesToRun[dep] && !completed[dep] {
					// Check if dependency was skipped (e.g., IPRange skipped for domain targets)
					if r.shouldSkipPhase(dep) {
						continue // Skipped phases count as "satisfied" dependency
					}
					allDepsComplete = false
					break
				}
				// If dependency was NOT requested, we'll load data from files (handled by Builder)
			}
			if allDepsComplete || len(deps) == 0 {
				runnablePhases = append(runnablePhases, phase)
			}
		}

		if len(runnablePhases) == 0 {
			continue
		}

		// Print level header (progress tracker handles debug mode)
		r.progress.PrintLevelHeader(group.Level, runnablePhases)

		// Execute phases in this group concurrently
		var wg sync.WaitGroup
		var mu sync.Mutex
		resultsChan := make(chan struct {
			phase  pipeline.Phase
			result *pipeline.PhaseResult
		}, len(runnablePhases))

		for _, phase := range runnablePhases {
			wg.Add(1)
			go func(p pipeline.Phase) {
				defer wg.Done()

				phaseStart := time.Now()

				// Mark phase as running (progress tracker handles debug mode)
				r.progress.MarkRunning(p)

				// In debug mode, also print the detailed message
				if r.cfg.Debug {
					displayName := pipeline.GetPhaseDisplayName(p)
					fmt.Printf("    %s...\n", displayName)
				}

				result, err := exec.Execute(ctx, p)
				if err != nil {
					result = &pipeline.PhaseResult{
						Phase:    p,
						Status:   pipeline.StatusFailed,
						Error:    err,
						Duration: time.Since(phaseStart),
					}
				}

				resultsChan <- struct {
					phase  pipeline.Phase
					result *pipeline.PhaseResult
				}{p, result}
			}(phase)
		}

		// Wait for all phases in group to complete
		wg.Wait()
		close(resultsChan)

		// Collect results
		for res := range resultsChan {
			mu.Lock()
			results[res.phase] = res.result
			if res.result.Status == pipeline.StatusCompleted {
				completed[res.phase] = true
			}
			mu.Unlock()

			// Save results to output manager
			r.savePhaseResult(res.phase, res.result)

			// Save phase status to SQLite for resume support
			if sqliteStorage != nil {
				phaseName := string(res.phase)
				var status string
				var errorMsg string
				switch res.result.Status {
				case pipeline.StatusCompleted:
					status = "completed"
				case pipeline.StatusFailed:
					status = "failed"
					if res.result.Error != nil {
						errorMsg = res.result.Error.Error()
					}
				case pipeline.StatusSkipped:
					status = "skipped"
				default:
					status = "unknown"
				}
				endTime := time.Now()
				startTime := endTime.Add(-res.result.Duration)
				sqliteStorage.SavePhaseStatus(ctx, r.out.ScanID(), phaseName, status,
					startTime, endTime, res.result.Duration.Milliseconds(), errorMsg)
			}

			// Update progress tracker and print result
			switch res.result.Status {
			case pipeline.StatusCompleted:
				// Extract counts from result data for display
				counts := r.extractResultCounts(res.phase, res.result)
				r.progress.SetCounts(res.phase, counts)
				r.progress.MarkCompleted(res.phase, res.result.Duration)
				// Debug mode: print detailed output
				if r.cfg.Debug {
					green.Printf("    ✓ %s completed (%s)\n", pipeline.PhaseName[res.phase], res.result.Duration.Round(time.Millisecond))
				}
			case pipeline.StatusSkipped:
				r.progress.MarkSkipped(res.phase)
				if r.cfg.Debug {
					yellow.Printf("    ○ %s skipped\n", pipeline.PhaseName[res.phase])
				}
			case pipeline.StatusFailed:
				r.progress.MarkFailed(res.phase, res.result.Error)
				if r.cfg.Debug {
					red.Printf("    ✗ %s failed: %v\n", pipeline.PhaseName[res.phase], res.result.Error)
				}
			}
		}
	}

	// Print summary (progress tracker handles debug mode)
	r.progress.PrintSummary(time.Since(start), filepath.Join(r.cfg.OutputDir, target))

	// Save final summary
	r.out.SaveSummary(target)

	// Generate HTML Report if not interrupted
	if !interrupted && r.cfg.GenerateReport {
		r.generateReport(target, results, start)
	}

	// Update scan status based on whether it was interrupted
	if r.out.HasSQLite() {
		if interrupted {
			r.out.SQLiteDB().UpdateScanStatus(ctx, r.out.ScanID(), "interrupted")
			yellow.Printf("[*] Scan interrupted. Resume with: reconator scan %s\n", target)
		} else {
			r.out.SQLiteDB().UpdateScanStatus(ctx, r.out.ScanID(), "completed")
		}
	}

	return nil
}

// getPhasesToRun returns a map of phases that should be executed based on config
func (r *PipelineRunner) getPhasesToRun() map[pipeline.Phase]bool {
	phases := make(map[pipeline.Phase]bool)

	// Check if running all phases or specific ones
	runAll := false
	for _, p := range r.cfg.Phases {
		if p == "all" {
			runAll = true
			break
		}
	}

	if runAll {
		// Run all phases
		for _, p := range pipeline.GetAllPhases() {
			phases[p] = true
		}
	} else {
		// Run only specified phases - DO NOT add dependencies automatically
		// Dependencies will be loaded from existing files by the Builder
		phaseMap := map[string]pipeline.Phase{
			"iprange":    pipeline.PhaseIPRange,
			"subdomain":  pipeline.PhaseSubdomain,
			"waf":        pipeline.PhaseWAF,
			"ports":      pipeline.PhasePorts,
			"vhost":      pipeline.PhaseVHost,
			"takeover":   pipeline.PhaseTakeover,
			"historic":   pipeline.PhaseHistoric,
			"tech":       pipeline.PhaseTech,
			"jsanalysis": pipeline.PhaseJSAnalysis,
			"trufflehog": pipeline.PhaseTruffleHog,
			"secheaders": pipeline.PhaseSecHeaders,
			"dirbrute":   pipeline.PhaseDirBrute,
			"vulnscan":   pipeline.PhaseVulnScan,
			"screenshot": pipeline.PhaseScreenshot,
			"aiguided":   pipeline.PhaseAIGuided,
		}

		for _, p := range r.cfg.Phases {
			if phase, ok := phaseMap[p]; ok {
				phases[phase] = true
				// NOTE: Dependencies are NOT added here - they are loaded from files
				// This allows running specific phases without re-running recon
			}
		}
	}

	return phases
}


// shouldSkipPhase returns true if a phase should be skipped based on config
func (r *PipelineRunner) shouldSkipPhase(phase pipeline.Phase) bool {
	switch phase {
	case pipeline.PhaseIPRange:
		// IPRange only runs for ASN/IP targets, skip for domain targets
		if !iprange.IsASN(r.cfg.Target) && !iprange.IsIPTarget(r.cfg.Target) {
			return true
		}
	case pipeline.PhasePorts:
		// Skip ports in passive mode (no exceptions)
		if r.cfg.PassiveMode {
			return true
		}
	case pipeline.PhaseTech:
		// Allow tech detection if explicitly selected, even in passive mode
		if r.cfg.PassiveMode && !r.cfg.ShouldRunPhase("tech") {
			return true
		}
	case pipeline.PhaseDirBrute:
		if r.cfg.PassiveMode || r.cfg.SkipDirBrute {
			return true
		}
	case pipeline.PhaseVulnScan:
		if r.cfg.PassiveMode || r.cfg.SkipVulnScan {
			return true
		}
	case pipeline.PhaseScreenshot:
		if !r.cfg.EnableScreenshots {
			if r.cfg.Debug {
				fmt.Println("    [DEBUG] Skipping screenshot: EnableScreenshots=false")
			}
			return true
		}
		// Allow screenshots if explicitly selected, even in passive mode
		if r.cfg.PassiveMode && !r.cfg.ShouldRunPhase("screenshot") {
			if r.cfg.Debug {
				fmt.Println("    [DEBUG] Skipping screenshot: PassiveMode=true and not explicitly selected")
			}
			return true
		}
	case pipeline.PhaseAIGuided:
		if r.cfg.SkipAIGuided || r.cfg.PassiveMode {
			return true
		}
		// Also skip if no AI keys (check config struct OR ai-config.yaml file)
		hasConfigKeys := r.cfg.OpenAIKey != "" || r.cfg.ClaudeKey != "" || r.cfg.GeminiKey != ""
		if !hasConfigKeys && !aiguided.HasAnyProviderConfigured() {
			return true
		}
	}
	return false
}

// savePhaseResult saves the phase result using the output manager
func (r *PipelineRunner) savePhaseResult(phase pipeline.Phase, result *pipeline.PhaseResult) {
	if result.Status != pipeline.StatusCompleted || result.Data == nil {
		return
	}

	// Type assert and save based on phase
	switch phase {
	case pipeline.PhaseIPRange:
		if data, ok := result.Data.(*iprange.Result); ok {
			r.out.SaveIPRangeResults(data)
		}
	case pipeline.PhaseSubdomain:
		if data, ok := result.Data.(*subdomain.Result); ok {
			r.out.SaveSubdomains(data)
		}
	case pipeline.PhaseWAF:
		if data, ok := result.Data.(*waf.Result); ok {
			r.out.SaveWAFResults(data)
		}
	case pipeline.PhasePorts:
		if data, ok := result.Data.(*portscan.Result); ok {
			r.out.SavePortResults(data)
		}
	case pipeline.PhaseTakeover:
		if data, ok := result.Data.(*takeover.Result); ok {
			r.out.SaveTakeoverResults(data)
		}
	case pipeline.PhaseHistoric:
		if data, ok := result.Data.(*historic.Result); ok {
			r.out.SaveHistoricResults(data)
		}
	case pipeline.PhaseTech:
		if data, ok := result.Data.(*techdetect.Result); ok {
			r.out.SaveTechResults(data)
		}
	case pipeline.PhaseSecHeaders:
		if data, ok := result.Data.(*secheaders.Result); ok {
			r.out.SaveSecHeadersResults(data)
		}
	case pipeline.PhaseVHost:
		if data, ok := result.Data.(*vhost.Result); ok {
			r.out.SaveVHostResults(data)
		}
	case pipeline.PhaseDirBrute:
		if data, ok := result.Data.(*dirbrute.Result); ok {
			r.out.SaveDirBruteResults(data)
		}
	case pipeline.PhaseVulnScan:
		if data, ok := result.Data.(*vulnscan.Result); ok {
			r.out.SaveVulnResults(data)
		}
	case pipeline.PhaseJSAnalysis:
		if data, ok := result.Data.(*jsanalysis.Result); ok {
			r.out.SaveJSAnalysisResults(data)
		}
	case pipeline.PhaseTruffleHog:
		if data, ok := result.Data.(*trufflehog.Result); ok {
			r.out.SaveTruffleHogResults(data)
		}
	case pipeline.PhaseScreenshot:
		if data, ok := result.Data.(*screenshot.Result); ok {
			r.out.SaveScreenshotResults(data)
		}
	case pipeline.PhaseAIGuided:
		if data, ok := result.Data.(*aiguided.Result); ok {
			r.out.SaveAIGuidedResults(data)
		}
	}
}

// printSummary prints a summary of all phase results
func (r *PipelineRunner) printSummary(results map[pipeline.Phase]*pipeline.PhaseResult, start time.Time) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	green.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	green.Printf("  Pipeline Summary\n")
	green.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	var completed, failed, skipped int
	var totalDuration time.Duration

	for _, phase := range pipeline.GetAllPhases() {
		result, ok := results[phase]
		if !ok {
			continue
		}

		totalDuration += result.Duration

		switch result.Status {
		case pipeline.StatusCompleted:
			completed++
			green.Printf("  ✓ %-25s %s\n", pipeline.PhaseName[phase], result.Duration.Round(time.Millisecond))
		case pipeline.StatusFailed:
			failed++
			red.Printf("  ✗ %-25s FAILED\n", pipeline.PhaseName[phase])
		case pipeline.StatusSkipped:
			skipped++
			yellow.Printf("  ○ %-25s SKIPPED\n", pipeline.PhaseName[phase])
		}
	}

	green.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	green.Printf("  Completed: %d | Failed: %d | Skipped: %d\n", completed, failed, skipped)
	green.Printf("  Total time: %s\n", time.Since(start).Round(time.Second))
	green.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
}

// getTargets reads targets from config
func (r *PipelineRunner) getTargets() ([]string, error) {
	if r.cfg.Target != "" {
		return []string{r.cfg.Target}, nil
	}
	if r.cfg.TargetFile == "" {
		return nil, fmt.Errorf("no target specified")
	}

	f, err := os.Open(r.cfg.TargetFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if t := scanner.Text(); t != "" {
			targets = append(targets, t)
		}
	}
	return targets, scanner.Err()
}

// phaseFromString converts a phase name string to a Phase constant
func (r *PipelineRunner) phaseFromString(name string) (pipeline.Phase, bool) {
	phaseMap := map[string]pipeline.Phase{
		"iprange":    pipeline.PhaseIPRange,
		"subdomain":  pipeline.PhaseSubdomain,
		"waf":        pipeline.PhaseWAF,
		"ports":      pipeline.PhasePorts,
		"vhost":      pipeline.PhaseVHost,
		"takeover":   pipeline.PhaseTakeover,
		"historic":   pipeline.PhaseHistoric,
		"tech":       pipeline.PhaseTech,
		"jsanalysis": pipeline.PhaseJSAnalysis,
		"trufflehog": pipeline.PhaseTruffleHog,
		"secheaders": pipeline.PhaseSecHeaders,
		"dirbrute":   pipeline.PhaseDirBrute,
		"vulnscan":   pipeline.PhaseVulnScan,
		"screenshot": pipeline.PhaseScreenshot,
		"aiguided":   pipeline.PhaseAIGuided,
	}
	phase, ok := phaseMap[name]
	return phase, ok
}

// applyPerformanceProfile detects system resources and applies appropriate settings
// Settings are auto-detected unless user overrides with flags like --threads or --parallel-targets
func (r *PipelineRunner) applyPerformanceProfile() {
	// Auto-detect based on system resources
	settings, info := sysinfo.GetSettingsForSystem()
	r.cfg.Profile = string(info.Profile) // Store detected profile for display

	// Apply settings only for values that are 0 (auto)
	// User can override any setting via CLI flags
	if r.cfg.Threads == 0 {
		r.cfg.Threads = settings.Threads
	}
	if r.cfg.DNSThreads == 0 {
		r.cfg.DNSThreads = settings.DNSThreads
	}
	if r.cfg.MaxConcTargets == 0 {
		r.cfg.MaxConcTargets = settings.MaxConcTargets
	}
	if r.cfg.RateLimit == 0 {
		r.cfg.RateLimit = settings.RateLimit
	}
}

// generateReport creates an HTML report from the phase results
func (r *PipelineRunner) generateReport(target string, results map[pipeline.Phase]*pipeline.PhaseResult, start time.Time) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	outDir := filepath.Join(r.cfg.OutputDir, target)

	// Build report data from results
	reportData := &report.Data{
		Target:   target,
		Version:  version.Version,
		Date:     time.Now().Format(time.RFC1123),
		Duration: time.Since(start).Round(time.Second).String(),
	}

	// Extract data from phase results
	if res, ok := results[pipeline.PhaseSubdomain]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*subdomain.Result); ok {
			reportData.Subdomain = data
		}
	}
	if res, ok := results[pipeline.PhaseWAF]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*waf.Result); ok {
			reportData.WAF = data
		}
	}
	if res, ok := results[pipeline.PhasePorts]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*portscan.Result); ok {
			reportData.Ports = data
		}
	}
	if res, ok := results[pipeline.PhaseTakeover]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*takeover.Result); ok {
			reportData.Takeover = data
		}
	}
	if res, ok := results[pipeline.PhaseHistoric]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*historic.Result); ok {
			reportData.Historic = data
		}
	}
	if res, ok := results[pipeline.PhaseTech]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*techdetect.Result); ok {
			reportData.Tech = data
		}
	}
	if res, ok := results[pipeline.PhaseSecHeaders]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*secheaders.Result); ok {
			reportData.SecHeaders = data
		}
	}
	if res, ok := results[pipeline.PhaseVHost]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*vhost.Result); ok {
			reportData.VHost = data
		}
	}
	if res, ok := results[pipeline.PhaseDirBrute]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*dirbrute.Result); ok {
			reportData.DirBrute = data
		}
	}
	if res, ok := results[pipeline.PhaseVulnScan]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*vulnscan.Result); ok {
			reportData.VulnScan = data
		}
	}
	if res, ok := results[pipeline.PhaseAIGuided]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*aiguided.Result); ok {
			reportData.AIGuided = data
		}
	}
	if res, ok := results[pipeline.PhaseIPRange]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*iprange.Result); ok {
			reportData.IPRange = data
		}
	}
	if res, ok := results[pipeline.PhaseScreenshot]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*screenshot.Result); ok {
			reportData.Screenshot = data
		}
	}
	if res, ok := results[pipeline.PhaseJSAnalysis]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*jsanalysis.Result); ok {
			reportData.JSAnalysis = data
		}
	}
	if res, ok := results[pipeline.PhaseTruffleHog]; ok && res.Status == pipeline.StatusCompleted {
		if data, ok := res.Data.(*trufflehog.Result); ok {
			reportData.TruffleHog = data
		}
	}

	// If we don't have results from this run, try to load from existing files
	if reportData.Subdomain == nil || reportData.Ports == nil {
		r.loadExistingResultsForReport(outDir, reportData)
	}

	if err := report.Generate(reportData, outDir); err != nil {
		yellow.Printf("    ⚠ Failed to generate report: %v\n", err)
	} else {
		green.Printf("    Report generated: report_%s.html\n", target)
	}
}

// loadExistingResultsForReport loads results from existing JSON files when running partial scans
func (r *PipelineRunner) loadExistingResultsForReport(outDir string, reportData *report.Data) {
	// Load subdomain results if missing
	if reportData.Subdomain == nil {
		if data := loadJSON[subdomain.Result](filepath.Join(outDir, "1-subdomains", "subdomains.json")); data != nil {
			reportData.Subdomain = data
		}
	}

	// Load WAF results if missing
	if reportData.WAF == nil {
		if data := loadJSON[waf.Result](filepath.Join(outDir, "2-waf", "waf_detection.json")); data != nil {
			reportData.WAF = data
		}
	}

	// Load port results if missing
	if reportData.Ports == nil {
		if data := loadJSON[portscan.Result](filepath.Join(outDir, "3-ports", "port_scan.json")); data != nil {
			reportData.Ports = data
		}
	}

	// Load takeover results if missing
	if reportData.Takeover == nil {
		if data := loadJSON[takeover.Result](filepath.Join(outDir, "4-takeover", "takeover.json")); data != nil {
			reportData.Takeover = data
		}
	}

	// Load historic results if missing
	if reportData.Historic == nil {
		if data := loadJSON[historic.Result](filepath.Join(outDir, "5-historic", "historic_urls.json")); data != nil {
			reportData.Historic = data
		}
	}

	// Load tech results if missing
	if reportData.Tech == nil {
		if data := loadJSON[techdetect.Result](filepath.Join(outDir, "6-tech", "tech_detection.json")); data != nil {
			reportData.Tech = data
		}
	}

	// Load dirbrute results if missing
	if reportData.DirBrute == nil {
		if data := loadJSON[dirbrute.Result](filepath.Join(outDir, "7-dirbrute", "dirbrute.json")); data != nil {
			reportData.DirBrute = data
		}
	}

	// Load vulnscan results if missing
	if reportData.VulnScan == nil {
		if data := loadJSON[vulnscan.Result](filepath.Join(outDir, "8-vulnscan", "vulnerabilities.json")); data != nil {
			reportData.VulnScan = data
		}
	}

	// Load security headers results if missing
	if reportData.SecHeaders == nil {
		if data := loadJSON[secheaders.Result](filepath.Join(outDir, "6b-secheaders", "security_headers.json")); data != nil {
			reportData.SecHeaders = data
		}
	}

	// Load AI-guided results if missing
	if reportData.AIGuided == nil {
		if data := loadJSON[aiguided.Result](filepath.Join(outDir, "10-aiguided", "ai_guided.json")); data != nil {
			reportData.AIGuided = data
		}
	}

	// Load screenshot results if missing
	if reportData.Screenshot == nil {
		if data := loadJSON[screenshot.Result](filepath.Join(outDir, "9-screenshots", "screenshot_results.json")); data != nil {
			reportData.Screenshot = data
		}
	}

	// Load JS analysis results if missing
	if reportData.JSAnalysis == nil {
		if data := loadJSON[jsanalysis.Result](filepath.Join(outDir, "6c-jsanalysis", "js_analysis.json")); data != nil {
			reportData.JSAnalysis = data
		}
	}

	// Load TruffleHog results if missing
	if reportData.TruffleHog == nil {
		if data := loadJSON[trufflehog.Result](filepath.Join(outDir, "7c-trufflehog", "trufflehog_secrets.json")); data != nil {
			reportData.TruffleHog = data
		}
	}
}

// loadJSON is a generic helper to load JSON files into structs
func loadJSON[T any](path string) *T {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return &result
}

// extractResultCounts extracts key metrics from phase results for progress display
func (r *PipelineRunner) extractResultCounts(phase pipeline.Phase, result *pipeline.PhaseResult) map[string]int {
	counts := make(map[string]int)
	if result.Data == nil {
		return counts
	}

	switch phase {
	case pipeline.PhaseSubdomain:
		if data, ok := result.Data.(*subdomain.Result); ok {
			counts["subdomains"] = data.TotalAll  // All discovered
			counts["validated"] = data.Total      // Validated (alive)
		}
	case pipeline.PhaseWAF:
		if data, ok := result.Data.(*waf.Result); ok {
			counts["cdn"] = len(data.CDNHosts)
			counts["direct"] = len(data.DirectHosts)
		}
	case pipeline.PhasePorts:
		if data, ok := result.Data.(*portscan.Result); ok {
			counts["alive"] = data.AliveCount
			counts["ports"] = data.TotalPorts
		}
	case pipeline.PhaseTakeover:
		if data, ok := result.Data.(*takeover.Result); ok {
			counts["vulnerable"] = len(data.Vulnerable)
		}
	case pipeline.PhaseHistoric:
		if data, ok := result.Data.(*historic.Result); ok {
			counts["urls"] = len(data.URLs)
			counts["js"] = len(data.Categorized.JSFiles)
		}
	case pipeline.PhaseTech:
		if data, ok := result.Data.(*techdetect.Result); ok {
			counts["techs"] = data.Total
		}
	case pipeline.PhaseDirBrute:
		if data, ok := result.Data.(*dirbrute.Result); ok {
			counts["discoveries"] = len(data.Discoveries)
		}
	case pipeline.PhaseVulnScan:
		if data, ok := result.Data.(*vulnscan.Result); ok {
			for _, v := range data.Vulnerabilities {
				switch v.Severity {
				case "critical":
					counts["critical"]++
				case "high":
					counts["high"]++
				case "medium":
					counts["medium"]++
				}
			}
		}
	case pipeline.PhaseTruffleHog:
		if data, ok := result.Data.(*trufflehog.Result); ok {
			counts["secrets"] = data.TotalFound
			counts["verified"] = data.Verified
		}
	case pipeline.PhaseScreenshot:
		if data, ok := result.Data.(*screenshot.Result); ok {
			counts["screenshots"] = len(data.Screenshots)
		}
	case pipeline.PhaseIPRange:
		if data, ok := result.Data.(*iprange.Result); ok {
			counts["ips"] = len(data.IPs)
			counts["domains"] = len(data.Domains)
		}
	}

	return counts
}
