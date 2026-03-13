package fleet

// FleetConfig holds configuration for distributed scanning
type FleetConfig struct {
	Backend BackendType `yaml:"backend" json:"backend"`
	Workers int         `yaml:"workers" json:"workers"`

	// SSH backend config
	SSH *SSHConfig `yaml:"ssh,omitempty" json:"ssh,omitempty"`

	// Cloud provisioning
	Cloud *CloudConfig `yaml:"cloud,omitempty" json:"cloud,omitempty"`

	// K8s config (future P4)
	K8s *K8sConfig `yaml:"k8s,omitempty" json:"k8s,omitempty"`
}

// SSHConfig holds SSH fleet backend configuration
type SSHConfig struct {
	Hosts    []string `yaml:"hosts" json:"hosts"`         // Pre-existing host IPs/hostnames
	User     string   `yaml:"user" json:"user"`           // SSH user (default: root)
	KeyFile  string   `yaml:"key_file" json:"key_file"`   // SSH private key path
	Port     int      `yaml:"port" json:"port"`           // SSH port (default: 22)
	SetupCmd string   `yaml:"setup_cmd" json:"setup_cmd"` // Command to install tools on worker
}

// CloudConfig holds cloud provider fleet configuration
type CloudConfig struct {
	Provider    string   `yaml:"provider" json:"provider"`         // "digitalocean", "aws"
	APIKey      string   `yaml:"api_key" json:"api_key"`           // Cloud provider API key (or env var name)
	Region      string   `yaml:"region" json:"region"`             // Cloud region
	Size        string   `yaml:"size" json:"size"`                 // Instance size
	Image       string   `yaml:"image" json:"image"`               // OS image (default: ubuntu-24-04-x64)
	SSHKeyID    string   `yaml:"ssh_key_id" json:"ssh_key_id"`     // Pre-uploaded SSH key ID
	SSHKeyFile  string   `yaml:"ssh_key_file" json:"ssh_key_file"` // Local SSH key for connecting
	Tags        []string `yaml:"tags" json:"tags"`                 // Instance tags
	SetupScript string   `yaml:"setup_script" json:"setup_script"` // Path to setup script
	SpotEnabled bool     `yaml:"spot_enabled" json:"spot_enabled"` // Use spot/preemptible instances
}

// K8sConfig holds Kubernetes fleet configuration (future P4)
type K8sConfig struct {
	Namespace string `yaml:"namespace" json:"namespace"`   // K8s namespace
	Image     string `yaml:"image" json:"image"`           // Container image with recon tools
	SpotNodes bool   `yaml:"spot_nodes" json:"spot_nodes"` // Use spot/preemptible node pool
	PVCName   string `yaml:"pvc_name" json:"pvc_name"`     // Shared storage PVC name
}

// DefaultFleetConfig returns a fleet configuration with sane defaults
func DefaultFleetConfig() *FleetConfig {
	return &FleetConfig{
		Backend: BackendLocal,
		Workers: 1,
		SSH: &SSHConfig{
			User: "root",
			Port: 22,
		},
		Cloud: &CloudConfig{
			Provider: "digitalocean",
			Region:   "nyc1",
			Size:     "s-1vcpu-1gb",
			Image:    "ubuntu-24-04-x64",
			Tags:     []string{"reconator"},
		},
		K8s: &K8sConfig{
			Namespace: "reconator",
			Image:     "reconator/worker:latest",
			SpotNodes: true,
		},
	}
}
