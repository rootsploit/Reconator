package iprotate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// RotatingProxy is a local HTTP proxy that distributes requests across
// multiple AWS API Gateway endpoints for IP rotation. Each request through
// a different gateway gets a new source IP from AWS's pool.
type RotatingProxy struct {
	gateways []GatewayInfo
	port     int
	counter  atomic.Uint64
	server   *http.Server
	client   *http.Client
}

// NewRotatingProxy creates a proxy that round-robins across the given gateways
func NewRotatingProxy(gateways []GatewayInfo, port int) *RotatingProxy {
	return &RotatingProxy{
		gateways: gateways,
		port:     port,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
	}
}

// Start begins listening on the configured port
func (rp *RotatingProxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rp.handleRequest)

	rp.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", rp.port),
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}

	cyan := color.New(color.FgCyan)
	cyan.Printf("[iprotate] Proxy listening on http://127.0.0.1:%d (%d gateways)\n", rp.port, len(rp.gateways))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rp.server.Shutdown(shutdownCtx)
	}()

	if err := rp.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("proxy server: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the proxy
func (rp *RotatingProxy) Stop() error {
	if rp.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return rp.server.Shutdown(ctx)
}

// ProxyURL returns the local proxy URL for configuring tools
func (rp *RotatingProxy) ProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", rp.port)
}

// handleRequest proxies the incoming request through a round-robin selected gateway
func (rp *RotatingProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if len(rp.gateways) == 0 {
		http.Error(w, "no gateways available", http.StatusBadGateway)
		return
	}

	// Round-robin gateway selection
	idx := rp.counter.Add(1) - 1
	gw := rp.gateways[idx%uint64(len(rp.gateways))]

	// Build the gateway URL: gateway endpoint + original path
	// The gateway's {proxy+} resource will forward it to the target
	gwURL := strings.TrimRight(gw.Endpoint, "/") + r.URL.Path
	if r.URL.RawQuery != "" {
		gwURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, gwURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("create request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers (except Host)
	for key, values := range r.Header {
		if strings.EqualFold(key, "Host") {
			continue
		}
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}

	// Set Host to the gateway's host
	if parsed, err := url.Parse(gw.Endpoint); err == nil {
		proxyReq.Host = parsed.Host
	}

	resp, err := rp.client.Do(proxyReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("gateway error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
