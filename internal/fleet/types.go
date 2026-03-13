package fleet

import (
	"context"
	"time"
)

// BackendType represents a fleet backend type
type BackendType string

const (
	BackendLocal BackendType = "local"
	BackendSSH   BackendType = "ssh"
	BackendK8s   BackendType = "k8s" // Future P4
)

// WorkerStatus represents the current state of a worker
type WorkerStatus string

const (
	StatusPending   WorkerStatus = "pending"
	StatusReady     WorkerStatus = "ready"
	StatusBusy      WorkerStatus = "busy"
	StatusError     WorkerStatus = "error"
	StatusDestroyed WorkerStatus = "destroyed"
)

// Worker interface - every backend (local, SSH, K8s) implements this
type Worker interface {
	ID() string
	Backend() BackendType
	Deploy(ctx context.Context) error
	Execute(ctx context.Context, cmd string, args ...string) (*ExecResult, error)
	Upload(ctx context.Context, localPath, remotePath string) error
	Download(ctx context.Context, remotePath, localPath string) error
	Destroy(ctx context.Context) error
	Status() WorkerStatus
}

// ExecResult holds the result of a command execution
type ExecResult struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

// PhaseTask represents a distributable unit of work
type PhaseTask struct {
	Phase       string            `json:"phase"`        // e.g., "subdomain", "portscan", "vulnscan"
	Target      string            `json:"target"`       // Target domain/IP
	Command     string            `json:"command"`      // Command to execute
	Args        map[string]string `json:"args"`         // Phase-specific arguments
	InputFiles  []string          `json:"input_files"`  // Files to upload before execution
	OutputFiles []string          `json:"output_files"` // Files to download after execution
}

// TaskResult represents the result of a distributed task
type TaskResult struct {
	WorkerID  string      `json:"worker_id"`
	Task      *PhaseTask  `json:"task"`
	Result    *ExecResult `json:"result"`
	OutputDir string      `json:"output_dir"` // Local directory where downloaded results are stored
	Error     error       `json:"error,omitempty"`
}
