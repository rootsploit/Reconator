package iprotate

import (
	"context"
	"fmt"
	"sync"

	"github.com/fatih/color"
)

// IPRotator is the main coordinator for IP rotation.
// It manages the lifecycle of AWS API Gateways and the local rotating proxy.
//
// Usage:
//
//	rotator := iprotate.New(cfg)
//	if err := rotator.Start(ctx); err != nil { ... }
//	defer rotator.Stop(ctx)
//	proxyURL := rotator.ProxyURL() // http://127.0.0.1:8888
//	// Configure recon tools to use proxyURL as HTTP proxy
type IPRotator struct {
	cfg     *IPRotateConfig
	gateway *GatewayManager
	proxy   *RotatingProxy
	mu      sync.Mutex
	running bool
}

// New creates a new IPRotator with the given configuration
func New(cfg *IPRotateConfig) *IPRotator {
	if cfg == nil {
		cfg = DefaultIPRotateConfig()
	}
	return &IPRotator{
		cfg:     cfg,
		gateway: NewGatewayManager(),
	}
}

// Start deploys API Gateways across regions and starts the local proxy.
// The targetURL is the base URL of the target to proxy through gateways.
func (r *IPRotator) Start(ctx context.Context, targetURL string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("IP rotator already running")
	}

	cyan := color.New(color.FgCyan)
	cyan.Printf("[iprotate] Starting IP rotation for %s\n", targetURL)

	target := targetURL
	if r.cfg.TargetURL != "" {
		target = r.cfg.TargetURL
	}
	if target == "" {
		return fmt.Errorf("target URL is required")
	}

	// Deploy gateways
	gateways, err := r.gateway.Deploy(ctx, r.cfg.Regions, target)
	if err != nil {
		return fmt.Errorf("deploy gateways: %w", err)
	}

	// Start local proxy
	port := r.cfg.ProxyPort
	if port == 0 {
		port = 8888
	}
	r.proxy = NewRotatingProxy(gateways, port)
	r.running = true

	// Start proxy in background
	go func() {
		if err := r.proxy.Start(ctx); err != nil {
			color.New(color.FgRed).Printf("[iprotate] Proxy error: %v\n", err)
		}
	}()

	green := color.New(color.FgGreen)
	green.Printf("[iprotate] IP rotation active: %s → %d gateways → target\n", r.ProxyURL(), len(gateways))
	green.Printf("[iprotate] Configure tools: HTTP_PROXY=%s\n", r.ProxyURL())

	return nil
}

// Stop tears down all gateways and stops the proxy
func (r *IPRotator) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	cyan := color.New(color.FgCyan)
	cyan.Println("[iprotate] Shutting down IP rotation...")

	var errs []error

	// Stop proxy
	if r.proxy != nil {
		if err := r.proxy.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("stop proxy: %w", err))
		}
	}

	// Teardown gateways
	if err := r.gateway.Teardown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("teardown gateways: %w", err))
	}

	r.running = false
	cyan.Println("[iprotate] IP rotation stopped")

	if len(errs) > 0 {
		return fmt.Errorf("stop errors: %v", errs)
	}
	return nil
}

// ProxyURL returns the local proxy URL (e.g., "http://127.0.0.1:8888")
func (r *IPRotator) ProxyURL() string {
	if r.proxy != nil {
		return r.proxy.ProxyURL()
	}
	return fmt.Sprintf("http://127.0.0.1:%d", r.cfg.ProxyPort)
}

// IsRunning returns whether the rotator is active
func (r *IPRotator) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// GatewayCount returns the number of active gateways
func (r *IPRotator) GatewayCount() int {
	return len(r.gateway.Gateways())
}
