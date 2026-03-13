package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/apikeys"
	"github.com/rootsploit/reconator/internal/fleet"
	"github.com/rootsploit/reconator/internal/fleet/provision"
	"github.com/spf13/cobra"
)

var (
	fleetBackend  string
	fleetWorkers  int
	fleetSSHHosts string
	fleetSSHUser  string
	fleetSSHKey   string
	fleetSSHPort  int
	fleetProvider string
	fleetRegion   string
	fleetSize     string
	fleetAPIKey   string
	fleetSSHKeyID string
	fleetSpot     bool
	fleetSetupCmd string
)

var fleetCmd = &cobra.Command{
	Use:   "fleet",
	Short: "Advanced fleet management (most users should use 'scan --distributed' instead)",
	Long: `Advanced fleet management for distributed reconnaissance scanning.

TIP: For simple distributed scanning, use the --distributed flag on the scan command:
  reconator scan example.com --distributed --provider=aws
  reconator scan -l targets.txt --distributed --provider=digitalocean --api-key=$DO_TOKEN

This command is for advanced use cases (persistent fleets, custom SSH backends).

Backends:
  local          Run everything on this machine (default)
  ssh            Distribute work across SSH-accessible servers

Cloud provisioning:
  --provider=digitalocean   Auto-provision DigitalOcean droplets
  --provider=aws            Auto-provision AWS EC2 instances (supports spot)

Examples:
  reconator fleet status
  reconator fleet create --backend=ssh --hosts=10.0.0.1,10.0.0.2 --ssh-key=~/.ssh/id_rsa
  reconator fleet create --backend=ssh --provider=digitalocean --workers=5 --api-key=$DO_TOKEN
  reconator fleet create --backend=ssh --provider=aws --workers=3 --spot
  reconator fleet destroy`,
}

var fleetCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and initialize a fleet of workers",
	RunE:  runFleetCreate,
}

var fleetDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy all fleet workers and cloud resources",
	RunE:  runFleetDestroy,
}

var fleetStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show fleet status",
	RunE:  runFleetStatus,
}

func init() {
	// Fleet create flags
	fleetCreateCmd.Flags().StringVar(&fleetBackend, "backend", "local", "Fleet backend: local, ssh")
	fleetCreateCmd.Flags().IntVarP(&fleetWorkers, "workers", "w", 1, "Number of workers")
	fleetCreateCmd.Flags().StringVar(&fleetSSHHosts, "hosts", "", "Comma-separated SSH hosts (for ssh backend)")
	fleetCreateCmd.Flags().StringVar(&fleetSSHUser, "ssh-user", "root", "SSH username")
	fleetCreateCmd.Flags().StringVar(&fleetSSHKey, "ssh-key", "", "SSH private key path")
	fleetCreateCmd.Flags().IntVar(&fleetSSHPort, "ssh-port", 22, "SSH port")
	fleetCreateCmd.Flags().StringVar(&fleetProvider, "provider", "", "Cloud provider: digitalocean, aws")
	fleetCreateCmd.Flags().StringVar(&fleetRegion, "region", "", "Cloud region")
	fleetCreateCmd.Flags().StringVar(&fleetSize, "size", "", "Instance size")
	fleetCreateCmd.Flags().StringVar(&fleetAPIKey, "api-key", "", "Cloud provider API key")
	fleetCreateCmd.Flags().StringVar(&fleetSSHKeyID, "ssh-key-id", "", "Cloud SSH key ID")
	fleetCreateCmd.Flags().BoolVar(&fleetSpot, "spot", false, "Use spot/preemptible instances (AWS)")
	fleetCreateCmd.Flags().StringVar(&fleetSetupCmd, "setup-cmd", "", "Command to run on workers for tool installation")

	fleetCmd.AddCommand(fleetCreateCmd)
	fleetCmd.AddCommand(fleetDestroyCmd)
	fleetCmd.AddCommand(fleetStatusCmd)
}

func runFleetCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	// Load config defaults from ~/.reconator/config.yaml
	cfgMgr := apikeys.NewManager()
	if err := cfgMgr.Load(); err != nil {
		// Config loading is best-effort; continue with CLI flags only
		_ = err
	}
	cfgDefaults := cfgMgr.GetConfig().Fleet

	// Apply config defaults, then let CLI flags override
	if !cmd.Flags().Changed("backend") && cfgDefaults.Backend != "" {
		fleetBackend = cfgDefaults.Backend
	}
	if !cmd.Flags().Changed("workers") && cfgDefaults.Workers > 0 {
		fleetWorkers = cfgDefaults.Workers
	}
	if !cmd.Flags().Changed("ssh-user") && cfgDefaults.SSHUser != "" {
		fleetSSHUser = cfgDefaults.SSHUser
	}
	if !cmd.Flags().Changed("ssh-key") && cfgDefaults.SSHKeyFile != "" {
		fleetSSHKey = cfgDefaults.SSHKeyFile
	}
	if !cmd.Flags().Changed("ssh-port") && cfgDefaults.SSHPort > 0 {
		fleetSSHPort = cfgDefaults.SSHPort
	}
	if !cmd.Flags().Changed("hosts") && len(cfgDefaults.SSHHosts) > 0 {
		fleetSSHHosts = strings.Join(cfgDefaults.SSHHosts, ",")
	}
	if !cmd.Flags().Changed("setup-cmd") && cfgDefaults.SetupCmd != "" {
		fleetSetupCmd = cfgDefaults.SetupCmd
	}
	if !cmd.Flags().Changed("provider") && cfgDefaults.Provider != "" {
		fleetProvider = cfgDefaults.Provider
	}
	if !cmd.Flags().Changed("api-key") && cfgDefaults.APIKey != "" {
		fleetAPIKey = cfgDefaults.APIKey
	}
	if !cmd.Flags().Changed("region") && cfgDefaults.Region != "" {
		fleetRegion = cfgDefaults.Region
	}
	if !cmd.Flags().Changed("size") && cfgDefaults.Size != "" {
		fleetSize = cfgDefaults.Size
	}
	if !cmd.Flags().Changed("ssh-key-id") && cfgDefaults.SSHKeyID != "" {
		fleetSSHKeyID = cfgDefaults.SSHKeyID
	}
	if !cmd.Flags().Changed("spot") && cfgDefaults.SpotEnabled {
		fleetSpot = cfgDefaults.SpotEnabled
	}

	fleetCfg := fleet.DefaultFleetConfig()
	fleetCfg.Backend = fleet.BackendType(fleetBackend)
	fleetCfg.Workers = fleetWorkers

	// SSH config
	if fleetSSHHosts != "" {
		fleetCfg.SSH = &fleet.SSHConfig{
			Hosts:    strings.Split(fleetSSHHosts, ","),
			User:     fleetSSHUser,
			KeyFile:  fleetSSHKey,
			Port:     fleetSSHPort,
			SetupCmd: fleetSetupCmd,
		}
	}

	// Cloud provisioning
	if fleetProvider != "" {
		fleetCfg.Cloud = &fleet.CloudConfig{
			Provider:    fleetProvider,
			APIKey:      fleetAPIKey,
			Region:      fleetRegion,
			Size:        fleetSize,
			SSHKeyID:    fleetSSHKeyID,
			SpotEnabled: fleetSpot,
			Tags:        []string{"reconator"},
		}

		// Warning before creating billable resources
		yellow.Println("\n  WARNING: This will create billable cloud resources.")
		fmt.Printf("    Provider: %s, Workers: %d, Size: %s, Spot: %v\n", fleetProvider, fleetWorkers, fleetSize, fleetSpot)
		fmt.Println("    Continue? (Press Ctrl+C to cancel, waiting 5 seconds...)")
		select {
		case <-time.After(5 * time.Second):
			// User did not cancel, proceed
		case <-ctx.Done():
			fmt.Println("\n[fleet] Cancelled.")
			return nil
		}

		cyan.Printf("[fleet] Provisioning %d %s instance(s)...\n", fleetWorkers, fleetProvider)

		var provisioner provision.Provisioner
		switch fleetProvider {
		case "digitalocean":
			provisioner = provision.NewDOProvisioner(
				fleetAPIKey, fleetRegion, fleetSize, "", fleetSSHKeyID, []string{"reconator"},
			)
		case "aws":
			provisioner = provision.NewAWSProvisioner(
				fleetRegion, "", fleetSize, "", "", fleetSpot,
			)
		default:
			return fmt.Errorf("unsupported provider: %s (supported: digitalocean, aws)", fleetProvider)
		}

		ips, err := provisioner.Create(ctx, fleetWorkers, "reconator-worker")
		if err != nil {
			return fmt.Errorf("provision instances: %w", err)
		}

		green.Printf("[fleet] Provisioned %d instance(s): %s\n", len(ips), strings.Join(ips, ", "))

		// Update SSH config with provisioned IPs
		fleetCfg.Backend = fleet.BackendSSH
		if fleetCfg.SSH == nil {
			fleetCfg.SSH = &fleet.SSHConfig{
				User:    fleetSSHUser,
				KeyFile: fleetSSHKey,
				Port:    fleetSSHPort,
			}
		}
		fleetCfg.SSH.Hosts = ips
	}

	// Initialize fleet manager
	mgr := fleet.NewManager(fleetCfg)
	if err := mgr.Init(ctx); err != nil {
		return fmt.Errorf("init fleet: %w", err)
	}

	green.Printf("[fleet] Fleet ready: %d worker(s) (%s backend)\n", mgr.WorkerCount(), fleetBackend)

	// Run setup command if provided
	if fleetSetupCmd != "" {
		cyan.Printf("[fleet] Running setup command on workers: %s\n", fleetSetupCmd)
		for _, w := range mgr.ActiveWorkers() {
			result, err := w.Execute(ctx, "bash", "-c", fleetSetupCmd)
			if err != nil {
				color.New(color.FgYellow).Printf("[fleet] Setup failed on %s: %v\n", w.ID(), err)
			} else if result.ExitCode != 0 {
				color.New(color.FgYellow).Printf("[fleet] Setup warning on %s: exit %d\n", w.ID(), result.ExitCode)
			} else {
				green.Printf("[fleet] Setup complete on %s\n", w.ID())
			}
		}
	}

	return nil
}

func runFleetDestroy(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan)
	cyan.Println("[fleet] Destroy command — cloud resources must be destroyed via provider CLI")
	cyan.Println("[fleet] Use: aws ec2 terminate-instances or doctl compute droplet delete")
	fmt.Println()
	fmt.Println("For DigitalOcean:")
	fmt.Println("  doctl compute droplet list --tag-name=reconator --format ID --no-header | xargs doctl compute droplet delete -f")
	fmt.Println()
	fmt.Println("For AWS:")
	fmt.Println("  aws ec2 describe-instances --filters 'Name=tag:Project,Values=reconator' --query 'Reservations[].Instances[].InstanceId' --output text | xargs aws ec2 terminate-instances --instance-ids")
	return nil
}

func runFleetStatus(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan)
	cyan.Println("[fleet] Fleet Status")
	cyan.Println("  Backend: local (default)")
	cyan.Println("  Workers: 1")
	cyan.Println("  Status:  ready")
	fmt.Println()
	fmt.Println("Use 'reconator fleet create' to set up a distributed fleet.")
	fmt.Fprintf(os.Stderr, "")
	return nil
}
