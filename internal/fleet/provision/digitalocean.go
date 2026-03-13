package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
)

const doAPIBase = "https://api.digitalocean.com/v2"

// DOProvisioner manages DigitalOcean droplet provisioning
type DOProvisioner struct {
	apiKey   string
	region   string
	size     string
	image    string
	sshKeyID string
	tags     []string
	droplets []DropletInfo
}

// NewDOProvisioner creates a new DigitalOcean provisioner
func NewDOProvisioner(apiKey, region, size, image, sshKeyID string, tags []string) *DOProvisioner {
	if region == "" {
		region = "nyc1"
	}
	if size == "" {
		size = "s-1vcpu-1gb"
	}
	if image == "" {
		image = "ubuntu-24-04-x64"
	}
	return &DOProvisioner{
		apiKey:   apiKey,
		region:   region,
		size:     size,
		image:    image,
		sshKeyID: sshKeyID,
		tags:     tags,
	}
}

func (p *DOProvisioner) Provider() string { return "digitalocean" }

// Create provisions count droplets and returns their IPs
func (p *DOProvisioner) Create(ctx context.Context, count int, namePrefix string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	var ips []string
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%s-%d", namePrefix, i+1)
		cyan.Printf("[do] Creating droplet %s (%s, %s)...\n", name, p.size, p.region)

		droplet, err := p.createDroplet(ctx, name)
		if err != nil {
			color.New(color.FgYellow).Printf("[do] Failed to create %s: %v\n", name, err)
			continue
		}

		// Wait for droplet to be ready and get IP
		ip, err := p.waitForReady(ctx, droplet.ID)
		if err != nil {
			color.New(color.FgYellow).Printf("[do] Droplet %s not ready: %v\n", name, err)
			continue
		}

		droplet.IP = ip
		droplet.Status = "active"
		p.droplets = append(p.droplets, *droplet)
		ips = append(ips, ip)
		green.Printf("[do] Droplet %s ready: %s\n", name, ip)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("failed to create any droplets")
	}
	return ips, nil
}

// Destroy terminates all provisioned droplets
func (p *DOProvisioner) Destroy(ctx context.Context) error {
	var errs []error
	for _, d := range p.droplets {
		if err := p.destroyDroplet(ctx, d.ID); err != nil {
			errs = append(errs, fmt.Errorf("destroy droplet %d: %w", d.ID, err))
		} else {
			color.New(color.FgCyan).Printf("[do] Destroyed droplet %s (%d)\n", d.Name, d.ID)
		}
	}
	p.droplets = nil
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

func (p *DOProvisioner) createDroplet(ctx context.Context, name string) (*DropletInfo, error) {
	reqBody := map[string]interface{}{
		"name":   name,
		"region": p.region,
		"size":   p.size,
		"image":  p.image,
		"tags":   p.tags,
	}
	if p.sshKeyID != "" {
		reqBody["ssh_keys"] = []string{p.sshKeyID}
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", doAPIBase+"/droplets", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DO API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Droplet struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"droplet"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	return &DropletInfo{
		ID:   result.Droplet.ID,
		Name: result.Droplet.Name,
	}, nil
}

func (p *DOProvisioner) waitForReady(ctx context.Context, dropletID int) (string, error) {
	deadline := time.After(3 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline:
			return "", fmt.Errorf("timeout waiting for droplet %d", dropletID)
		case <-ticker.C:
			ip, ready, err := p.getDropletStatus(ctx, dropletID)
			if err != nil {
				continue
			}
			if ready && ip != "" {
				return ip, nil
			}
		}
	}
}

func (p *DOProvisioner) getDropletStatus(ctx context.Context, dropletID int) (string, bool, error) {
	url := fmt.Sprintf("%s/droplets/%d", doAPIBase, dropletID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	var result struct {
		Droplet struct {
			Status   string `json:"status"`
			Networks struct {
				V4 []struct {
					IPAddress string `json:"ip_address"`
					Type      string `json:"type"`
				} `json:"v4"`
			} `json:"networks"`
		} `json:"droplet"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Droplet.Status != "active" {
		return "", false, nil
	}

	for _, net := range result.Droplet.Networks.V4 {
		if net.Type == "public" {
			return net.IPAddress, true, nil
		}
	}
	return "", false, nil
}

func (p *DOProvisioner) destroyDroplet(ctx context.Context, dropletID int) error {
	url := fmt.Sprintf("%s/droplets/%d", doAPIBase, dropletID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DO delete error %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
