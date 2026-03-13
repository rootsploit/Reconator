package pipeline

import (
	"context"
	"time"

	"github.com/rootsploit/reconator/internal/aiguided"
	"github.com/rootsploit/reconator/internal/config"
)

// AICheckpoint1Adapter implements PhaseExecutor for AI Checkpoint 1
// Runs after subdomain + historic + JS analysis to analyze recon surface
// Auto-skips when no AI keys are configured
type AICheckpoint1Adapter struct {
	runner *aiguided.CheckpointRunner
	cfg    *config.Config
}

func NewAICheckpoint1Adapter(cfg *config.Config) *AICheckpoint1Adapter {
	return &AICheckpoint1Adapter{
		runner: aiguided.NewCheckpointRunner(),
		cfg:    cfg,
	}
}

func (a *AICheckpoint1Adapter) Name() Phase { return PhaseAICheckpoint1 }

func (a *AICheckpoint1Adapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseAICheckpoint1,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Auto-skip if no AI support
	if !a.runner.HasAISupport() {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Collect JS findings from categorized URLs
	var jsFindings []string
	if input.CategorizedURLs != nil {
		jsFindings = input.CategorizedURLs.JSFiles
	}

	// Run checkpoint 1
	decisions := a.runner.RunCheckpoint1(ctx, input.Subdomains, input.URLs, jsFindings)

	result.Status = StatusCompleted
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)
	result.Data = decisions
	return result, nil
}

// AICheckpoint2Adapter implements PhaseExecutor for AI Checkpoint 2
// Runs after ports + WAF + tech detection to optimize scanning strategy
// Auto-skips when no AI keys are configured
type AICheckpoint2Adapter struct {
	runner *aiguided.CheckpointRunner
	cfg    *config.Config
}

func NewAICheckpoint2Adapter(cfg *config.Config) *AICheckpoint2Adapter {
	return &AICheckpoint2Adapter{
		runner: aiguided.NewCheckpointRunner(),
		cfg:    cfg,
	}
}

func (a *AICheckpoint2Adapter) Name() Phase { return PhaseAICheckpoint2 }

func (a *AICheckpoint2Adapter) Execute(ctx context.Context, input *PhaseInput) (*PhaseResult, error) {
	start := time.Now()
	result := &PhaseResult{
		Phase:     PhaseAICheckpoint2,
		Status:    StatusRunning,
		StartTime: start,
	}

	// Auto-skip if no AI support
	if !a.runner.HasAISupport() {
		result.Status = StatusSkipped
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(start)
		return result, nil
	}

	// Collect WAF hosts
	var wafHosts []string
	if len(input.CDNHosts) > 0 {
		wafHosts = input.CDNHosts
	}

	// Run checkpoint 2
	decisions := a.runner.RunCheckpoint2(ctx, input.AliveHosts, input.OpenPorts, wafHosts, input.TechByHost)

	// Merge with existing decisions from checkpoint 1 if available
	if input.AIDecisions != nil {
		input.AIDecisions.Merge(decisions)
		result.Data = input.AIDecisions
	} else {
		result.Data = decisions
	}

	result.Status = StatusCompleted
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start)
	return result, nil
}
