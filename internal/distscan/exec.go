package distscan

import (
	"context"
	"os/exec"
)

// execCommand wraps exec.CommandContext for local commands
func execCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
