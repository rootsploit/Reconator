package fleet

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"
)

// LocalWorker runs commands on the local machine
type LocalWorker struct {
	id     string
	status WorkerStatus
}

// NewLocalWorker creates a new local worker
func NewLocalWorker() *LocalWorker {
	return &LocalWorker{
		id:     "local-" + uuid.New().String()[:8],
		status: StatusReady,
	}
}

func (w *LocalWorker) ID() string                      { return w.id }
func (w *LocalWorker) Backend() BackendType            { return BackendLocal }
func (w *LocalWorker) Status() WorkerStatus            { return w.status }
func (w *LocalWorker) Deploy(_ context.Context) error  { return nil }
func (w *LocalWorker) Destroy(_ context.Context) error { w.status = StatusDestroyed; return nil }

// Upload is a no-op for local workers (files are already local)
func (w *LocalWorker) Upload(_ context.Context, _, _ string) error { return nil }

// Download is a no-op for local workers (files are already local)
func (w *LocalWorker) Download(_ context.Context, _, _ string) error { return nil }

// Execute runs a command locally via os/exec
func (w *LocalWorker) Execute(ctx context.Context, cmd string, args ...string) (*ExecResult, error) {
	w.status = StatusBusy
	defer func() { w.status = StatusReady }()

	start := time.Now()
	c := exec.CommandContext(ctx, cmd, args...)

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()

	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			return result, fmt.Errorf("execute %s: %w", cmd, err)
		}
	}

	return result, nil
}
