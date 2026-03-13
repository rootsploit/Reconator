package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
)

// AWSProvisioner manages AWS EC2 instance provisioning via CLI
type AWSProvisioner struct {
	region      string
	ami         string
	instType    string
	keyName     string
	secGroup    string
	tags        map[string]string
	spotEnabled bool
	instances   []InstanceInfo
}

// NewAWSProvisioner creates a new AWS provisioner
func NewAWSProvisioner(region, ami, instType, keyName, secGroup string, spotEnabled bool) *AWSProvisioner {
	if region == "" {
		region = "us-east-1"
	}
	if instType == "" {
		instType = "t3.micro"
	}
	return &AWSProvisioner{
		region:      region,
		ami:         ami,
		instType:    instType,
		keyName:     keyName,
		secGroup:    secGroup,
		spotEnabled: spotEnabled,
		tags:        map[string]string{"Project": "reconator"},
	}
}

func (p *AWSProvisioner) Provider() string { return "aws" }

// Create launches count EC2 instances and returns their public IPs
func (p *AWSProvisioner) Create(ctx context.Context, count int, namePrefix string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	// Resolve AMI if not specified
	if p.ami == "" {
		ami, err := p.resolveLatestUbuntuAMI(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolve AMI: %w", err)
		}
		p.ami = ami
	}

	mode := "on-demand"
	if p.spotEnabled {
		mode = "spot"
	}
	cyan.Printf("[aws] Launching %d %s instance(s) (%s, %s, %s)...\n", count, mode, p.instType, p.region, p.ami)

	args := []string{
		"ec2", "run-instances",
		"--region", p.region,
		"--image-id", p.ami,
		"--instance-type", p.instType,
		"--count", fmt.Sprintf("%d", count),
		"--output", "json",
	}

	if p.keyName != "" {
		args = append(args, "--key-name", p.keyName)
	}
	if p.secGroup != "" {
		args = append(args, "--security-group-ids", p.secGroup)
	}
	if p.spotEnabled {
		args = append(args, "--instance-market-options", `{"MarketType":"spot"}`)
	}

	// Add tags
	tagSpecs := fmt.Sprintf("ResourceType=instance,Tags=[{Key=Name,Value=%s},{Key=Project,Value=reconator}]", namePrefix)
	args = append(args, "--tag-specifications", tagSpecs)

	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("aws ec2 run-instances: %s: %w", string(out), err)
	}

	var result struct {
		Instances []struct {
			InstanceID string `json:"InstanceId"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse AWS response: %w", err)
	}

	// Wait for each instance to be running and get IPs
	var ips []string
	for _, inst := range result.Instances {
		ip, err := p.waitForRunning(ctx, inst.InstanceID)
		if err != nil {
			color.New(color.FgYellow).Printf("[aws] Instance %s not ready: %v\n", inst.InstanceID, err)
			continue
		}
		p.instances = append(p.instances, InstanceInfo{
			ID:       inst.InstanceID,
			Name:     namePrefix,
			PublicIP: ip,
			Status:   "running",
		})
		ips = append(ips, ip)
		green.Printf("[aws] Instance %s ready: %s\n", inst.InstanceID, ip)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no instances became ready")
	}
	return ips, nil
}

// Destroy terminates all provisioned instances
func (p *AWSProvisioner) Destroy(ctx context.Context) error {
	if len(p.instances) == 0 {
		return nil
	}

	var ids []string
	for _, inst := range p.instances {
		ids = append(ids, inst.ID)
	}

	args := []string{
		"ec2", "terminate-instances",
		"--region", p.region,
		"--instance-ids",
	}
	args = append(args, ids...)

	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("aws ec2 terminate-instances: %s: %w", string(out), err)
	}

	color.New(color.FgCyan).Printf("[aws] Terminated %d instance(s): %s\n", len(ids), strings.Join(ids, ", "))
	p.instances = nil
	return nil
}

func (p *AWSProvisioner) waitForRunning(ctx context.Context, instanceID string) (string, error) {
	deadline := time.After(3 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline:
			return "", fmt.Errorf("timeout waiting for instance %s", instanceID)
		case <-ticker.C:
			ip, err := p.getInstancePublicIP(ctx, instanceID)
			if err != nil {
				continue
			}
			if ip != "" {
				return ip, nil
			}
		}
	}
}

func (p *AWSProvisioner) getInstancePublicIP(ctx context.Context, instanceID string) (string, error) {
	args := []string{
		"ec2", "describe-instances",
		"--region", p.region,
		"--instance-ids", instanceID,
		"--output", "json",
	}

	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	var result struct {
		Reservations []struct {
			Instances []struct {
				State struct {
					Name string `json:"Name"`
				} `json:"State"`
				PublicIPAddress string `json:"PublicIpAddress"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return "", err
	}

	if len(result.Reservations) > 0 && len(result.Reservations[0].Instances) > 0 {
		inst := result.Reservations[0].Instances[0]
		if inst.State.Name == "running" && inst.PublicIPAddress != "" {
			return inst.PublicIPAddress, nil
		}
	}
	return "", nil
}

func (p *AWSProvisioner) resolveLatestUbuntuAMI(ctx context.Context) (string, error) {
	args := []string{
		"ec2", "describe-images",
		"--region", p.region,
		"--owners", "099720109477", // Canonical
		"--filters",
		"Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
		"Name=state,Values=available",
		"--query", "sort_by(Images, &CreationDate)[-1].ImageId",
		"--output", "text",
	}

	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("resolve AMI: %s: %w", string(out), err)
	}

	ami := strings.TrimSpace(string(out))
	if ami == "" || ami == "None" {
		return "", fmt.Errorf("no Ubuntu 24.04 AMI found in %s", p.region)
	}
	return ami, nil
}
