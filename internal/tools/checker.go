package tools

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Checker struct{}

func NewChecker() *Checker { return &Checker{} }

func (c *Checker) CheckAll() *AllToolsStatus {
	s := &AllToolsStatus{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check all tools in parallel
	goTools := GoTools()
	pythonTools := PythonTools()
	rustTools := RustTools()

	// Pre-allocate slices
	s.Go = make([]ToolStatus, len(goTools))
	s.Python = make([]ToolStatus, len(pythonTools))
	s.Rust = make([]ToolStatus, len(rustTools))

	// Check Go tools in parallel
	for i, t := range goTools {
		wg.Add(1)
		go func(idx int, tool Tool) {
			defer wg.Done()
			status := c.check(tool)
			mu.Lock()
			s.Go[idx] = status
			mu.Unlock()
		}(i, t)
	}

	// Check Python tools in parallel
	for i, t := range pythonTools {
		wg.Add(1)
		go func(idx int, tool Tool) {
			defer wg.Done()
			status := c.check(tool)
			mu.Lock()
			s.Python[idx] = status
			mu.Unlock()
		}(i, t)
	}

	// Check Rust tools in parallel
	for i, t := range rustTools {
		wg.Add(1)
		go func(idx int, tool Tool) {
			defer wg.Done()
			status := c.check(tool)
			mu.Lock()
			s.Rust[idx] = status
			mu.Unlock()
		}(i, t)
	}

	wg.Wait()
	return s
}

func (c *Checker) IsInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (c *Checker) GetMissingRequired() []string {
	var missing []string
	for _, t := range GoTools() {
		if t.Required && !c.IsInstalled(t.Binary) {
			missing = append(missing, t.Name)
		}
	}
	return missing
}

func (c *Checker) check(t Tool) ToolStatus {
	installed := c.IsInstalled(t.Binary)
	s := ToolStatus{Name: t.Name, Installed: installed}
	if installed {
		s.Version = c.versionFast(t.Binary)
	}
	return s
}

// versionFast tries to get version quickly with shorter timeout
func (c *Checker) versionFast(bin string) string {
	// Try --version first (most common), with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "--version")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		v := strings.TrimSpace(strings.Split(string(out), "\n")[0])
		if len(v) > 40 {
			return v[:40] + "..."
		}
		return v
	}
	return ""
}
