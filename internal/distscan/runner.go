// Package distscan provides one-command distributed scanning.
// When users pass --distributed to the scan command, this orchestrator:
//  1. Provisions cloud workers (AWS EC2 or DigitalOcean droplets)
//  2. Installs reconator and tools on each worker
//  3. Splits targets across workers and runs scans
//  4. Downloads and consolidates results from all workers
//  5. Generates a unified report
//  6. Tears down all cloud resources
package distscan

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/fleet"
	"github.com/rootsploit/reconator/internal/fleet/provision"
)

// defaultSetupCmd installs reconator and common recon tools on a fresh Ubuntu worker
const defaultSetupCmd = `export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && apt-get install -y -qq git curl unzip jq > /dev/null 2>&1 && command -v go >/dev/null 2>&1 || { curl -sL https://go.dev/dl/go1.24.1.linux-amd64.tar.gz | tar -C /usr/local -xz && export PATH=$PATH:/usr/local/go/bin; echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc; } && export PATH=$PATH:/usr/local/go/bin:~/go/bin && go install github.com/rootsploit/reconator@latest 2>/dev/null && reconator install --extras 2>/dev/null; echo "setup done"`

// Runner orchestrates a distributed scan across cloud workers
type Runner struct {
	cfg         *config.Config
	provisioner provision.Provisioner
	fleetMgr    *fleet.Manager
	workerIPs   []string
}

// New creates a new distributed scan runner
func New(cfg *config.Config) *Runner {
	return &Runner{cfg: cfg}
}

// Run executes the full distributed scan lifecycle
func (r *Runner) Run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	workers := r.cfg.DistWorkers
	if workers < 1 {
		workers = 3
	}
	provider := r.cfg.DistProvider
	if provider == "" {
		provider = "digitalocean"
	}

	// --- Phase 1: Provision cloud workers ---
	cyan.Println("\n[distributed] Phase 1: Provisioning cloud workers")
	fmt.Printf("    Provider: %s, Workers: %d, Region: %s\n", provider, workers, regionOrDefault(r.cfg.DistRegion, provider))

	yellow.Println("    WARNING: This will create billable cloud resources.")
	fmt.Println("    Press Ctrl+C within 5 seconds to cancel...")
	select {
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		fmt.Println("\n[distributed] Cancelled.")
		return nil
	}

	provisioner, err := r.createProvisioner(provider)
	if err != nil {
		return fmt.Errorf("create provisioner: %w", err)
	}
	r.provisioner = provisioner

	// Ensure cleanup on interrupt
	defer r.cleanup(context.Background())

	ips, err := provisioner.Create(ctx, workers, "reconator-dist")
	if err != nil {
		return fmt.Errorf("provision workers: %w", err)
	}
	r.workerIPs = ips
	green.Printf("[distributed] Provisioned %d worker(s): %s\n", len(ips), strings.Join(ips, ", "))

	// --- Phase 2: Setup workers ---
	cyan.Println("\n[distributed] Phase 2: Setting up workers (installing reconator + tools)")

	fleetCfg := fleet.DefaultFleetConfig()
	fleetCfg.Backend = fleet.BackendSSH
	fleetCfg.Workers = len(ips)
	fleetCfg.SSH = &fleet.SSHConfig{
		Hosts:   ips,
		User:    "root",
		KeyFile: r.cfg.DistSSHKey,
		Port:    22,
	}
	r.fleetMgr = fleet.NewManager(fleetCfg)

	// Wait for SSH to be ready (cloud instances need time to boot)
	cyan.Println("    Waiting for SSH to become available...")
	time.Sleep(30 * time.Second)

	if err := r.fleetMgr.Init(ctx); err != nil {
		return fmt.Errorf("init fleet: %w", err)
	}

	// Run setup on each worker
	setupCmd := r.cfg.DistSetupCmd
	if setupCmd == "" {
		setupCmd = defaultSetupCmd
	}
	cyan.Printf("    Running setup on %d worker(s)...\n", len(r.fleetMgr.ActiveWorkers()))
	for _, w := range r.fleetMgr.ActiveWorkers() {
		result, err := w.Execute(ctx, "bash", "-c", setupCmd)
		if err != nil {
			yellow.Printf("    [%s] Setup error: %v\n", w.ID(), err)
		} else if result.ExitCode != 0 {
			yellow.Printf("    [%s] Setup warning: exit %d\n", w.ID(), result.ExitCode)
		} else {
			green.Printf("    [%s] Setup complete\n", w.ID())
		}
	}

	// --- Phase 3: Distribute and run scans ---
	cyan.Println("\n[distributed] Phase 3: Running distributed scan")

	targets := r.resolveTargets()
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	activeWorkers := r.fleetMgr.ActiveWorkers()
	if len(activeWorkers) == 0 {
		return fmt.Errorf("no active workers available after setup")
	}

	// Distribute targets across workers using round-robin
	workerTargets := distributeTargets(targets, len(activeWorkers))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var scanErrors []string

	for i, w := range activeWorkers {
		if len(workerTargets[i]) == 0 {
			continue
		}
		wg.Add(1)
		go func(worker fleet.Worker, tgts []string, idx int) {
			defer wg.Done()

			targetStr := strings.Join(tgts, ",")
			scanCmd := r.buildScanCommand(tgts)
			cyan.Printf("    [%s] Scanning %d target(s): %s\n", worker.ID(), len(tgts), targetStr)

			result, err := worker.Execute(ctx, "bash", "-c", scanCmd)
			if err != nil {
				mu.Lock()
				scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", worker.ID(), err))
				mu.Unlock()
				yellow.Printf("    [%s] Scan error: %v\n", worker.ID(), err)
				return
			}
			if result.ExitCode != 0 {
				yellow.Printf("    [%s] Scan exited %d\n", worker.ID(), result.ExitCode)
			} else {
				green.Printf("    [%s] Scan complete\n", worker.ID())
			}
		}(w, workerTargets[i], i)
	}
	wg.Wait()

	if len(scanErrors) == len(activeWorkers) {
		return fmt.Errorf("all workers failed: %s", strings.Join(scanErrors, "; "))
	}

	// --- Phase 4: Download and consolidate results ---
	cyan.Println("\n[distributed] Phase 4: Downloading and consolidating results")

	outDir := r.cfg.OutputDir
	if outDir == "" {
		homeDir, _ := os.UserHomeDir()
		outDir = filepath.Join(homeDir, "reconator")
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	for i, w := range activeWorkers {
		if len(workerTargets[i]) == 0 {
			continue
		}
		cyan.Printf("    [%s] Downloading results...\n", w.ID())
		for _, target := range workerTargets[i] {
			remotePath := fmt.Sprintf("/root/reconator/%s/", target)
			localPath := filepath.Join(outDir, target)
			if err := os.MkdirAll(localPath, 0755); err != nil {
				yellow.Printf("    [%s] mkdir error: %v\n", w.ID(), err)
				continue
			}
			// Use rsync-style download via tar + scp
			if err := r.downloadResults(ctx, w, remotePath, localPath); err != nil {
				yellow.Printf("    [%s] Download error for %s: %v\n", w.ID(), target, err)
			} else {
				green.Printf("    [%s] Downloaded results for %s\n", w.ID(), target)
			}
		}
	}

	// Consolidate: merge subdomain lists and finding files across workers
	if len(targets) > 0 {
		r.consolidateResults(outDir, targets)
	}

	// --- Phase 5: Teardown ---
	cyan.Println("\n[distributed] Phase 5: Tearing down cloud resources")
	r.cleanup(context.Background())

	green.Println("\n[distributed] Distributed scan complete!")
	fmt.Printf("    Results: %s\n", outDir)
	fmt.Printf("    Targets: %d, Workers: %d\n", len(targets), len(activeWorkers))

	return nil
}

// createProvisioner creates the appropriate cloud provisioner
func (r *Runner) createProvisioner(provider string) (provision.Provisioner, error) {
	region := r.cfg.DistRegion
	size := r.cfg.DistSize
	apiKey := r.cfg.DistAPIKey

	switch provider {
	case "digitalocean", "do":
		if apiKey == "" {
			apiKey = os.Getenv("DO_TOKEN")
		}
		if apiKey == "" {
			apiKey = os.Getenv("DIGITALOCEAN_TOKEN")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("DigitalOcean API key required: use --api-key or set DO_TOKEN env var")
		}
		return provision.NewDOProvisioner(apiKey, region, size, "", r.cfg.DistSSHKeyID, []string{"reconator"}), nil

	case "aws":
		return provision.NewAWSProvisioner(region, "", size, "", "", r.cfg.DistSpot), nil

	default:
		return nil, fmt.Errorf("unsupported provider: %s (use: aws, digitalocean)", provider)
	}
}

// resolveTargets builds the list of target domains from config
func (r *Runner) resolveTargets() []string {
	var targets []string

	if r.cfg.Target != "" {
		targets = append(targets, r.cfg.Target)
	}

	if r.cfg.TargetFile != "" {
		f, err := os.Open(r.cfg.TargetFile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		}
	}

	return targets
}

// buildScanCommand constructs the reconator scan command for a worker
func (r *Runner) buildScanCommand(targets []string) string {
	parts := []string{"export PATH=$PATH:/usr/local/go/bin:~/go/bin &&"}

	if len(targets) == 1 {
		parts = append(parts, "reconator", "scan", targets[0])
	} else {
		// Write targets to a temp file on the worker
		targetList := strings.Join(targets, "\n")
		parts = append(parts, fmt.Sprintf("echo '%s' > /tmp/targets.txt && reconator scan -l /tmp/targets.txt", targetList))
	}

	// Forward relevant flags
	if r.cfg.QuickMode {
		parts = append(parts, "--quick")
	}
	if r.cfg.PassiveMode {
		parts = append(parts, "--passive")
	}
	if r.cfg.DeepScan {
		parts = append(parts, "--deep")
	}
	if r.cfg.SkipAIGuided {
		parts = append(parts, "--no-ai")
	}

	// Always disable report generation on workers (we generate consolidated report locally)
	parts = append(parts, "--no-report")
	// Disable screenshots on workers (requires browser)
	parts = append(parts, "--no-screenshots")

	return strings.Join(parts, " ")
}

// downloadResults downloads scan results from a worker using scp
func (r *Runner) downloadResults(ctx context.Context, w fleet.Worker, remotePath, localPath string) error {
	// Create a tar on the remote, download it, and extract locally
	tarCmd := fmt.Sprintf("cd %s && tar czf /tmp/results.tar.gz . 2>/dev/null || true", remotePath)
	if _, err := w.Execute(ctx, "bash", "-c", tarCmd); err != nil {
		return fmt.Errorf("tar results: %w", err)
	}

	// Download the tar via scp
	localTar := filepath.Join(localPath, "results.tar.gz")
	if err := w.Download(ctx, "/tmp/results.tar.gz", localTar); err != nil {
		return fmt.Errorf("download tar: %w", err)
	}

	// Extract locally
	extractCmd := fmt.Sprintf("cd '%s' && tar xzf results.tar.gz && rm -f results.tar.gz", localPath)
	cmd := execCommand(ctx, "bash", "-c", extractCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("extract tar: %s: %w", string(out), err)
	}

	return nil
}

// consolidateResults merges results from multiple targets into summary files
func (r *Runner) consolidateResults(outDir string, targets []string) {
	green := color.New(color.FgGreen)

	// Merge all subdomain files into a consolidated list
	allSubdomains := make(map[string]bool)
	for _, target := range targets {
		subFile := filepath.Join(outDir, target, "subdomains.txt")
		if data, err := os.ReadFile(subFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					allSubdomains[line] = true
				}
			}
		}
	}

	if len(allSubdomains) > 0 {
		consolidatedFile := filepath.Join(outDir, "all_subdomains.txt")
		var lines []string
		for sub := range allSubdomains {
			lines = append(lines, sub)
		}
		os.WriteFile(consolidatedFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		green.Printf("    Consolidated %d unique subdomains -> %s\n", len(lines), consolidatedFile)
	}

	// Merge alive hosts
	allAlive := make(map[string]bool)
	for _, target := range targets {
		aliveFile := filepath.Join(outDir, target, "alive.txt")
		if data, err := os.ReadFile(aliveFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					allAlive[line] = true
				}
			}
		}
	}

	if len(allAlive) > 0 {
		consolidatedFile := filepath.Join(outDir, "all_alive.txt")
		var lines []string
		for host := range allAlive {
			lines = append(lines, host)
		}
		os.WriteFile(consolidatedFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		green.Printf("    Consolidated %d alive hosts -> %s\n", len(lines), consolidatedFile)
	}

	green.Printf("    Results consolidated in: %s\n", outDir)
}

// cleanup tears down all cloud resources
func (r *Runner) cleanup(ctx context.Context) {
	if r.fleetMgr != nil {
		r.fleetMgr.Shutdown(ctx)
		r.fleetMgr = nil
	}
	if r.provisioner != nil {
		if err := r.provisioner.Destroy(ctx); err != nil {
			color.New(color.FgYellow).Printf("[distributed] Cleanup warning: %v\n", err)
		}
		r.provisioner = nil
	}
}

// distributeTargets splits targets across N workers using round-robin
func distributeTargets(targets []string, numWorkers int) [][]string {
	result := make([][]string, numWorkers)
	for i, t := range targets {
		idx := i % numWorkers
		result[idx] = append(result[idx], t)
	}
	return result
}

// regionOrDefault returns the configured region or a sensible default
func regionOrDefault(region, provider string) string {
	if region != "" {
		return region
	}
	switch provider {
	case "aws":
		return "us-east-1"
	case "digitalocean", "do":
		return "nyc1"
	default:
		return "us-east-1"
	}
}
