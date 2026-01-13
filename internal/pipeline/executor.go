package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/storage"
)

// PhaseResult represents the output of a phase execution
type PhaseResult struct {
	Phase     Phase
	Status    Status
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Data      interface{}
	Error     error
}

// Status represents the execution status of a phase
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusSkipped   Status = "skipped"
)

// PhaseExecutor defines the interface for executing a single phase
type PhaseExecutor interface {
	// Execute runs the phase with the given input
	Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error)

	// Name returns the phase identifier
	Name() Phase
}

// Executor orchestrates phase execution with dependency management
type Executor struct {
	storage  storage.Storage
	cfg      *config.Config
	scanID   string
	target   string
	executors map[Phase]PhaseExecutor
}

// NewExecutor creates a new phase executor
func NewExecutor(s storage.Storage, cfg *config.Config, scanID, target string) *Executor {
	return &Executor{
		storage:   s,
		cfg:       cfg,
		scanID:    scanID,
		target:    target,
		executors: make(map[Phase]PhaseExecutor),
	}
}

// Register adds a phase executor
func (e *Executor) Register(executor PhaseExecutor) {
	e.executors[executor.Name()] = executor
}

// Execute runs a single phase after loading its dependencies
func (e *Executor) Execute(ctx context.Context, phase Phase) (*PhaseResult, error) {
	executor, ok := e.executors[phase]
	if !ok {
		return nil, fmt.Errorf("no executor registered for phase: %s", phase)
	}

	// Build input from dependencies
	builder := NewBuilder(e.storage, e.scanID, e.target, e.cfg)
	input, err := builder.Build(ctx, phase)
	if err != nil {
		return &PhaseResult{
			Phase:  phase,
			Status: StatusFailed,
			Error:  fmt.Errorf("failed to build input: %w", err),
		}, err
	}

	// Execute the phase
	result, err := executor.Execute(ctx, input)
	if err != nil {
		result.Status = StatusFailed
		result.Error = err
	}

	return result, err
}

// ExecuteAll runs all phases in dependency order
func (e *Executor) ExecuteAll(ctx context.Context) (map[Phase]*PhaseResult, error) {
	results := make(map[Phase]*PhaseResult)
	completed := make(map[Phase]bool)

	phases := GetAllPhases()
	for _, phase := range phases {
		// Skip if no executor registered
		if _, ok := e.executors[phase]; !ok {
			results[phase] = &PhaseResult{
				Phase:  phase,
				Status: StatusSkipped,
			}
			completed[phase] = true
			continue
		}

		// Check dependencies
		deps := GetDependencies(phase)
		allDepsComplete := true
		for _, dep := range deps {
			if !completed[dep] {
				allDepsComplete = false
				break
			}
		}

		if !allDepsComplete {
			results[phase] = &PhaseResult{
				Phase:  phase,
				Status: StatusSkipped,
				Error:  fmt.Errorf("dependencies not met"),
			}
			completed[phase] = true
			continue
		}

		// Execute phase
		result, _ := e.Execute(ctx, phase)
		results[phase] = result
		completed[phase] = result.Status == StatusCompleted
	}

	return results, nil
}

// CheckDependencies verifies all dependencies for a phase are satisfied
func (e *Executor) CheckDependencies(ctx context.Context, phase Phase) (bool, []Phase) {
	deps := GetDependencies(phase)
	missing := []Phase{}

	for _, dep := range deps {
		path := (&Builder{storage: e.storage}).getPhaseOutputPath(dep)
		exists, _ := e.storage.Exists(ctx, path)
		if !exists {
			missing = append(missing, dep)
		}
	}

	return len(missing) == 0, missing
}

// GetExecutionOrder returns phases in optimal execution order
// considering parallelism opportunities
func GetExecutionOrder() [][]Phase {
	return [][]Phase{
		// Level 0: Entry points (no dependencies)
		{PhaseIPRange, PhaseSubdomain},
		// Level 1: Depend on subdomain only (can run in parallel)
		{PhaseWAF, PhaseTakeover, PhaseHistoric},
		// Level 2: Depend on ports
		{PhasePorts},
		// Level 3: Depend on ports (can run in parallel)
		{PhaseTech, PhaseDirBrute},
		// Level 4: Depend on multiple phases
		{PhaseVulnScan},
		// Level 5: Final analysis
		{PhaseAIGuided},
	}
}

// PhaseGroup represents a set of phases that can run concurrently
type PhaseGroup struct {
	Phases []Phase
	Level  int
}

// GetParallelGroups returns phases grouped by execution level
func GetParallelGroups() []PhaseGroup {
	order := GetExecutionOrder()
	groups := make([]PhaseGroup, len(order))
	for i, phases := range order {
		groups[i] = PhaseGroup{
			Phases: phases,
			Level:  i,
		}
	}
	return groups
}
