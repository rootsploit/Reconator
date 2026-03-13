package fleet

import (
	"context"
	"fmt"
	"sync"

	"github.com/fatih/color"
)

// Manager orchestrates workers across fleet backends
type Manager struct {
	config  *FleetConfig
	workers []Worker
	mu      sync.RWMutex
}

// NewManager creates a new fleet manager
func NewManager(cfg *FleetConfig) *Manager {
	return &Manager{
		config: cfg,
	}
}

// Init creates and connects all workers based on config
func (m *Manager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cyan := color.New(color.FgCyan)
	count := m.config.Workers
	if count < 1 {
		count = 1
	}

	switch m.config.Backend {
	case BackendLocal:
		for i := 0; i < count; i++ {
			w := NewLocalWorker()
			m.workers = append(m.workers, w)
		}
		cyan.Printf("[fleet] Initialized %d local worker(s)\n", count)

	case BackendSSH:
		if m.config.SSH == nil || len(m.config.SSH.Hosts) == 0 {
			return fmt.Errorf("SSH backend requires at least one host in config")
		}
		for _, host := range m.config.SSH.Hosts {
			w := NewSSHWorker(host, m.config.SSH.User, m.config.SSH.KeyFile, m.config.SSH.Port)
			if err := w.Deploy(ctx); err != nil {
				color.New(color.FgYellow).Printf("[fleet] Warning: failed to connect to %s: %v\n", host, err)
				continue
			}
			m.workers = append(m.workers, w)
		}
		if len(m.workers) == 0 {
			return fmt.Errorf("no SSH workers could be connected")
		}
		cyan.Printf("[fleet] Connected to %d/%d SSH worker(s)\n", len(m.workers), len(m.config.SSH.Hosts))

	case BackendK8s:
		return fmt.Errorf("Kubernetes backend not yet implemented (P4)")

	default:
		return fmt.Errorf("unknown fleet backend: %s", m.config.Backend)
	}

	return nil
}

// Distribute distributes tasks across available workers using round-robin
func (m *Manager) Distribute(ctx context.Context, tasks []*PhaseTask) ([]*TaskResult, error) {
	m.mu.RLock()
	workers := m.activeWorkersLocked()
	m.mu.RUnlock()

	if len(workers) == 0 {
		return nil, fmt.Errorf("no active workers available")
	}

	results := make([]*TaskResult, len(tasks))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to bound concurrency to worker count
	sem := make(chan struct{}, len(workers))

	for i, task := range tasks {
		wg.Add(1)
		go func(idx int, t *PhaseTask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Round-robin worker assignment
			worker := workers[idx%len(workers)]

			result := &TaskResult{
				WorkerID: worker.ID(),
				Task:     t,
			}

			// Upload input files
			for _, f := range t.InputFiles {
				if err := worker.Upload(ctx, f, f); err != nil {
					result.Error = fmt.Errorf("upload %s: %w", f, err)
					mu.Lock()
					results[idx] = result
					mu.Unlock()
					return
				}
			}

			// Execute the command
			execResult, err := worker.Execute(ctx, t.Command, t.Target)
			result.Result = execResult
			if err != nil {
				result.Error = err
			}

			// Download output files
			for _, f := range t.OutputFiles {
				if err := worker.Download(ctx, f, f); err != nil {
					result.Error = fmt.Errorf("download %s: %w", f, err)
				}
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, task)
	}

	wg.Wait()
	return results, nil
}

// Shutdown destroys all workers
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for _, w := range m.workers {
		if err := w.Destroy(ctx); err != nil {
			errs = append(errs, fmt.Errorf("destroy %s: %w", w.ID(), err))
		}
	}
	m.workers = nil

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// WorkerCount returns the total number of workers
func (m *Manager) WorkerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.workers)
}

// ActiveWorkers returns workers in ready state
func (m *Manager) ActiveWorkers() []Worker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeWorkersLocked()
}

func (m *Manager) activeWorkersLocked() []Worker {
	var active []Worker
	for _, w := range m.workers {
		if w.Status() == StatusReady || w.Status() == StatusBusy {
			active = append(active, w)
		}
	}
	return active
}
