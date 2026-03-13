package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// MCPRequest represents an incoming MCP request
type MCPRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
	ID     interface{}           `json:"id,omitempty"`
}

// MCPResponse represents an MCP response
type MCPResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *MCPError       `json:"error,omitempty"`
	ID     interface{}     `json:"id,omitempty"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ScanState represents the current scan state
type ScanState struct {
	Status   string                 `json:"status"` // idle, running, paused, stopped, complete
	Target   string                 `json:"target,omitempty"`
	Phase    string                 `json:"phase,omitempty"`
	Progress float64                `json:"progress"` // 0.0 - 1.0
	Results  map[string]interface{} `json:"results,omitempty"`
}

// MCPServer represents an MCP server instance
type MCPServer struct {
	mu          sync.Mutex
	scanState   ScanState
	stopped     bool
}

// NewMCPServer creates a new MCP server
func NewMCPServer() *MCPServer {
	return &MCPServer{
		scanState: ScanState{Status: "idle", Progress: 0.0},
		stopped:   false,
	}
}

// HandleRequest handles an incoming MCP request
func (s *MCPServer) HandleRequest(req MCPRequest) (MCPResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result json.RawMessage

	switch req.Method {
	case "initialize":
		result = s.handleInitialize(req.Params)
	case "tools/list":
		result = s.handleListTools(req.Params)
	case "tools/call":
		result = s.handleToolCall(req.Params)
	case "scan/start":
		result = s.handleScanStart(req.Params)
	case "scan/stop":
		result = s.handleScanStop(req.Params)
	case "scan/pause":
		result = s.handleScanPause(req.Params)
	case "scan/resume":
		result = s.handleScanResume(req.Params)
	case "scan/status":
		result = s.handleScanStatus(req.Params)
	case "scan/progress":
		result = s.handleScanProgress(req.Params)
	case "scan/results":
		result = s.handleScanResults(req.Params)
	default:
		return MCPResponse{
			Error: &MCPError{
				Code:    -32601,
				Message: fmt.Sprintf("Method not found: %s", req.Method),
			},
			ID: req.ID,
		}, nil
	}

	return MCPResponse{
		Result: result,
		ID:     req.ID,
	}, nil
}

func (s *MCPServer) handleInitialize(params map[string]interface{}) json.RawMessage {
	resp := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]string{
			"name":    "reconator",
			"version": "2.0.0",
		},
		"capabilities": map[string]bool{
			"tools":         true,
			"streaming":     true,
			"pause_resume":  true,
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) handleListTools(params map[string]interface{}) json.RawMessage {
	tools := []map[string]interface{}{
		{
			"name":        "reconator_scan",
			"description": "Start a reconnaissance scan on target domain",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target":   map[string]string{"type": "string"},
					"phases":   map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					"mode":     map[string]interface{}{"type": "string", "enum": []string{"minimal", "passive", "quick", "normal", "full", "stealth", "webapp", "api"}},
					"deep":     map[string]string{"type": "boolean"},
					"json":     map[string]string{"type": "boolean"},
					"quiet":    map[string]string{"type": "boolean"},
				},
				"required": []string{"target"},
			},
		},
		{
			"name":        "reconator_status",
			"description": "Get current scan status",
		},
		{
			"name":        "reconator_progress",
			"description": "Get detailed progress including current phase and percentage",
		},
		{
			"name":        "reconator_results",
			"description": "Get scan results incrementally",
		},
		{
			"name":        "reconator_pause",
			"description": "Pause current scan (graceful)",
		},
		{
			"name":        "reconator_resume",
			"description": "Resume paused scan",
		},
		{
			"name":        "reconator_stop",
			"description": "Stop current scan",
		},
	}
	resp := map[string]interface{}{"tools": tools}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) handleToolCall(params map[string]interface{}) json.RawMessage {
	toolName, _ := params["name"].(string)
	toolArgs, _ := params["arguments"].(map[string]interface{})

	switch toolName {
	case "reconator_scan":
		target, _ := toolArgs["target"].(string)
		return s.startScan(target, toolArgs)
	case "reconator_status":
		return s.getStatus()
	case "reconator_progress":
		return s.getProgress()
	case "reconator_results":
		return s.getResults()
	case "reconator_pause":
		return s.pauseScan()
	case "reconator_resume":
		return s.resumeScan()
	case "reconator_stop":
		return s.stopScan()
	}

	errResp := map[string]string{"error": fmt.Sprintf("Unknown tool: %s", toolName)}
	data, _ := json.Marshal(errResp)
	return data
}

func (s *MCPServer) handleScanStart(params map[string]interface{}) json.RawMessage {
	target, _ := params["target"].(string)
	return s.startScan(target, params)
}

func (s *MCPServer) handleScanStop(params map[string]interface{}) json.RawMessage {
	return s.stopScan()
}

func (s *MCPServer) handleScanPause(params map[string]interface{}) json.RawMessage {
	return s.pauseScan()
}

func (s *MCPServer) handleScanResume(params map[string]interface{}) json.RawMessage {
	return s.resumeScan()
}

func (s *MCPServer) handleScanStatus(params map[string]interface{}) json.RawMessage {
	return s.getStatus()
}

func (s *MCPServer) handleScanProgress(params map[string]interface{}) json.RawMessage {
	return s.getProgress()
}

func (s *MCPServer) handleScanResults(params map[string]interface{}) json.RawMessage {
	return s.getResults()
}

// Internal helpers

func (s *MCPServer) startScan(target string, params map[string]interface{}) json.RawMessage {
	if target == "" {
		errResp := map[string]string{"error": "target is required"}
		data, _ := json.Marshal(errResp)
		return data
	}

	// Update state
	s.scanState = ScanState{
		Status:   "running",
		Target:   target,
		Phase:    "starting",
		Progress: 0.0,
	}

	// Note: Actual scan execution would require integrating with runner package
	// For MCP mode, the client would typically start reconator as a subprocess
	// or use the CLI flags directly

	resp := map[string]interface{}{
		"status":    "started",
		"target":    target,
		"message":   "To run scan: reconator scan " + target + " --json-progress",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) stopScan() json.RawMessage {
	s.scanState.Status = "stopped"

	resp := map[string]string{
		"status":  "stopped",
		"message": "Scan stopped",
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) pauseScan() json.RawMessage {
	s.scanState.Status = "paused"

	resp := map[string]string{
		"status":  "paused",
		"message": "Scan paused",
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) resumeScan() json.RawMessage {
	s.scanState.Status = "running"

	resp := map[string]string{
		"status":  "resumed",
		"message": "Scan resumed",
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) getStatus() json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := map[string]interface{}{
		"status":    s.scanState.Status,
		"target":    s.scanState.Target,
		"phase":     s.scanState.Phase,
		"progress":  s.scanState.Progress,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) getProgress() json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := map[string]interface{}{
		"progress":  s.scanState.Progress,
		"phase":     s.scanState.Phase,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *MCPServer) getResults() json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := map[string]interface{}{
		"results":   s.scanState.Results,
		"status":    s.scanState.Status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(resp)
	return data
}

// RunMCPServer runs the MCP server
func RunMCPServer() error {
	server := NewMCPServer()

	// Setup signal handlers for pause/resume
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGSTOP, syscall.SIGCONT, syscall.SIGTERM)

	go func() {
		for {
			sig := <-sigChan
			switch sig {
			case syscall.SIGSTOP:
				server.mu.Lock()
				if server.scanState.Status == "running" {
					server.scanState.Status = "paused"
				}
				server.mu.Unlock()
				fmt.Println(`{"type":"event","event":"paused","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`)
			case syscall.SIGCONT:
				server.mu.Lock()
				if server.scanState.Status == "paused" {
					server.scanState.Status = "running"
				}
				server.mu.Unlock()
				fmt.Println(`{"type":"event","event":"resumed","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`)
			case syscall.SIGTERM:
				server.mu.Lock()
				server.stopped = true
				server.scanState.Status = "stopped"
				server.mu.Unlock()
				os.Exit(0)
			}
		}
	}()

	// Read JSON-RPC requests from stdin
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println(`{"jsonrpc":"2.0","method":"initialized","id":null}`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req MCPRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errResp := MCPResponse{
				Error: &MCPError{
					Code:    -32700,
					Message: "Parse error",
				},
			}
			data, _ := json.Marshal(errResp)
			fmt.Println(string(data))
			continue
		}

		resp, _ := server.HandleRequest(req)
		data, _ := json.Marshal(resp)
		fmt.Println(string(data))
	}

	return scanner.Err()
}

func main() {
	if err := RunMCPServer(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP Server error: %v\n", err)
		os.Exit(1)
	}
}
