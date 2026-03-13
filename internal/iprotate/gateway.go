package iprotate

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

// GatewayManager handles AWS API Gateway lifecycle for IP rotation
type GatewayManager struct {
	gateways []GatewayInfo
}

// NewGatewayManager creates a new gateway manager
func NewGatewayManager() *GatewayManager {
	return &GatewayManager{}
}

// Deploy creates API Gateway REST APIs in the specified regions that proxy to targetURL.
// Each gateway acts as an HTTP passthrough — every request through it gets a different
// source IP from AWS's massive IP pool, providing IP rotation without extra infrastructure.
func (gm *GatewayManager) Deploy(ctx context.Context, regions []string, targetURL string) ([]GatewayInfo, error) {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	cyan.Printf("[iprotate] Deploying API Gateways across %d regions for %s\n", len(regions), targetURL)

	var gateways []GatewayInfo
	for _, region := range regions {
		gw, err := gm.deployGateway(ctx, region, targetURL)
		if err != nil {
			color.New(color.FgYellow).Printf("[iprotate] Failed in %s: %v\n", region, err)
			continue
		}
		gateways = append(gateways, *gw)
		green.Printf("[iprotate] Gateway ready: %s (%s)\n", gw.Endpoint, region)
	}

	if len(gateways) == 0 {
		return nil, fmt.Errorf("failed to deploy any API Gateways")
	}

	gm.gateways = gateways
	cyan.Printf("[iprotate] %d/%d gateways deployed successfully\n", len(gateways), len(regions))
	return gateways, nil
}

// Teardown destroys all deployed API Gateways
func (gm *GatewayManager) Teardown(ctx context.Context) error {
	cyan := color.New(color.FgCyan)
	var errs []error

	for _, gw := range gm.gateways {
		if err := gm.deleteGateway(ctx, gw.Region, gw.APIID); err != nil {
			errs = append(errs, fmt.Errorf("delete %s (%s): %w", gw.APIID, gw.Region, err))
		} else {
			cyan.Printf("[iprotate] Deleted gateway %s (%s)\n", gw.APIID, gw.Region)
		}
	}
	gm.gateways = nil

	if len(errs) > 0 {
		return fmt.Errorf("teardown errors: %v", errs)
	}
	return nil
}

// Gateways returns deployed gateways
func (gm *GatewayManager) Gateways() []GatewayInfo {
	return gm.gateways
}

// deployGateway creates a single API Gateway in the given region that proxies to targetURL.
// Uses AWS CLI to create a REST API with an {proxy+} resource and HTTP_PROXY integration.
func (gm *GatewayManager) deployGateway(ctx context.Context, region, targetURL string) (*GatewayInfo, error) {
	apiName := fmt.Sprintf("reconator-iprotate-%s", region)

	// Step 1: Create REST API
	createArgs := []string{
		"apigateway", "create-rest-api",
		"--region", region,
		"--name", apiName,
		"--endpoint-configuration", `{"types":["REGIONAL"]}`,
		"--output", "json",
	}
	out, err := runAWS(ctx, createArgs...)
	if err != nil {
		return nil, fmt.Errorf("create-rest-api: %w", err)
	}

	var apiResult struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &apiResult); err != nil {
		return nil, fmt.Errorf("parse create-rest-api: %w", err)
	}
	apiID := apiResult.ID

	// Step 2: Get root resource ID
	resArgs := []string{
		"apigateway", "get-resources",
		"--region", region,
		"--rest-api-id", apiID,
		"--output", "json",
	}
	out, err = runAWS(ctx, resArgs...)
	if err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("get-resources: %w", err)
	}

	var resResult struct {
		Items []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &resResult); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("parse get-resources: %w", err)
	}

	var rootID string
	for _, item := range resResult.Items {
		if item.Path == "/" {
			rootID = item.ID
			break
		}
	}
	if rootID == "" {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("root resource not found")
	}

	// Step 3: Create {proxy+} resource
	proxyArgs := []string{
		"apigateway", "create-resource",
		"--region", region,
		"--rest-api-id", apiID,
		"--parent-id", rootID,
		"--path-part", "{proxy+}",
		"--output", "json",
	}
	out, err = runAWS(ctx, proxyArgs...)
	if err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("create-resource: %w", err)
	}

	var proxyResult struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &proxyResult); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("parse create-resource: %w", err)
	}
	proxyResourceID := proxyResult.ID

	// Step 4: Create ANY method on {proxy+}
	methodArgs := []string{
		"apigateway", "put-method",
		"--region", region,
		"--rest-api-id", apiID,
		"--resource-id", proxyResourceID,
		"--http-method", "ANY",
		"--authorization-type", "NONE",
		"--request-parameters", `method.request.path.proxy=true`,
		"--output", "json",
	}
	if _, err := runAWS(ctx, methodArgs...); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("put-method: %w", err)
	}

	// Step 5: Create HTTP_PROXY integration
	// Target URL should end with /{proxy} to forward the full path
	integrationURI := strings.TrimRight(targetURL, "/") + "/{proxy}"
	integrationArgs := []string{
		"apigateway", "put-integration",
		"--region", region,
		"--rest-api-id", apiID,
		"--resource-id", proxyResourceID,
		"--http-method", "ANY",
		"--type", "HTTP_PROXY",
		"--integration-http-method", "ANY",
		"--uri", integrationURI,
		"--request-parameters", `integration.request.path.proxy=method.request.path.proxy`,
		"--output", "json",
	}
	if _, err := runAWS(ctx, integrationArgs...); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("put-integration: %w", err)
	}

	// Step 6: Also set up root resource (/) with ANY + HTTP_PROXY for base path requests
	rootMethodArgs := []string{
		"apigateway", "put-method",
		"--region", region,
		"--rest-api-id", apiID,
		"--resource-id", rootID,
		"--http-method", "ANY",
		"--authorization-type", "NONE",
		"--output", "json",
	}
	if _, err := runAWS(ctx, rootMethodArgs...); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("put-method root: %w", err)
	}

	rootIntArgs := []string{
		"apigateway", "put-integration",
		"--region", region,
		"--rest-api-id", apiID,
		"--resource-id", rootID,
		"--http-method", "ANY",
		"--type", "HTTP_PROXY",
		"--integration-http-method", "ANY",
		"--uri", strings.TrimRight(targetURL, "/") + "/",
		"--output", "json",
	}
	if _, err := runAWS(ctx, rootIntArgs...); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("put-integration root: %w", err)
	}

	// Step 7: Deploy to "proxy" stage
	deployArgs := []string{
		"apigateway", "create-deployment",
		"--region", region,
		"--rest-api-id", apiID,
		"--stage-name", "proxy",
		"--output", "json",
	}
	if _, err := runAWS(ctx, deployArgs...); err != nil {
		_ = gm.deleteGateway(ctx, region, apiID)
		return nil, fmt.Errorf("create-deployment: %w", err)
	}

	endpoint := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/proxy", apiID, region)
	return &GatewayInfo{
		APIID:    apiID,
		Region:   region,
		Endpoint: endpoint,
	}, nil
}

func (gm *GatewayManager) deleteGateway(ctx context.Context, region, apiID string) error {
	args := []string{
		"apigateway", "delete-rest-api",
		"--region", region,
		"--rest-api-id", apiID,
	}
	_, err := runAWS(ctx, args...)
	return err
}

// runAWS executes an aws CLI command and returns the output
func runAWS(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return out, nil
}
