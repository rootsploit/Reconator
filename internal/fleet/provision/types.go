package provision

import "context"

// Provisioner interface for cloud provider fleet management
type Provisioner interface {
	Create(ctx context.Context, count int, namePrefix string) ([]string, error) // Returns IPs
	Destroy(ctx context.Context) error
	Provider() string
}

// DropletInfo holds DigitalOcean droplet information
type DropletInfo struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Status string `json:"status"`
}

// InstanceInfo holds AWS EC2 instance information
type InstanceInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicIP  string `json:"public_ip"`
	PrivateIP string `json:"private_ip"`
	Status    string `json:"status"`
	SpotPrice string `json:"spot_price,omitempty"`
}
