package exec

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rootsploit/reconator/internal/debug"
)

// processManager tracks all running child processes for cleanup
var (
	runningProcesses = make(map[int]*exec.Cmd)
	processMu        sync.Mutex
)

// trackProcess adds a process to the tracking map
func trackProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		processMu.Lock()
		runningProcesses[cmd.Process.Pid] = cmd
		processMu.Unlock()
	}
}

// untrackProcess removes a process from the tracking map
func untrackProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		processMu.Lock()
		delete(runningProcesses, cmd.Process.Pid)
		processMu.Unlock()
	}
}

// KillAllProcesses terminates all tracked child processes and their process groups
func KillAllProcesses() {
	processMu.Lock()
	defer processMu.Unlock()

	for pid, cmd := range runningProcesses {
		if cmd.Process != nil {
			// Kill the entire process group (negative PID)
			syscall.Kill(-pid, syscall.SIGKILL)
			// Also try to kill the process directly
			cmd.Process.Kill()
		}
	}
	// Clear the map
	runningProcesses = make(map[int]*exec.Cmd)
}

type Result struct {
	Stdout, Stderr string
	ExitCode       int
	Duration       time.Duration
	Error          error
}

type Options struct {
	Timeout time.Duration
	Stdin   io.Reader
	Dir     string
	Env     []string
	Ctx     context.Context // Optional context for cancellation
}

func Run(name string, args []string, opts *Options) *Result {
	if opts == nil {
		opts = &Options{Timeout: 5 * time.Minute}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}

	// Debug: log start
	start := debug.LogStart(name, args)

	// Use provided context or create a new one with timeout
	var ctx context.Context
	var cancel context.CancelFunc
	if opts.Ctx != nil {
		// Use parent context with timeout
		ctx, cancel = context.WithTimeout(opts.Ctx, opts.Timeout)
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), opts.Timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	// Create new process group so we can kill all child processes
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}

	// Capture both stdout and stderr to prevent leaking to terminal
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Start()
	if err == nil {
		trackProcess(cmd)
		err = cmd.Wait()
		untrackProcess(cmd)
	}

	r := &Result{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		Duration: time.Since(start),
	}
	if err != nil {
		r.Error = err
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	// Debug: log end
	outputLines := len(Lines(r.Stdout))
	debug.LogEnd(name, args, start, r.Error, outputLines)

	return r
}

func RunWithInput(name string, args []string, input string, opts *Options) *Result {
	if opts == nil {
		opts = &Options{}
	}
	opts.Stdin = strings.NewReader(input)
	return Run(name, args, opts)
}

// RunWithContext runs a command with a parent context for cancellation
func RunWithContext(ctx context.Context, name string, args []string, opts *Options) *Result {
	if opts == nil {
		opts = &Options{}
	}
	opts.Ctx = ctx
	return Run(name, args, opts)
}

// RunWithInputAndContext runs a command with input and a parent context
func RunWithInputAndContext(ctx context.Context, name string, args []string, input string, opts *Options) *Result {
	if opts == nil {
		opts = &Options{}
	}
	opts.Ctx = ctx
	opts.Stdin = strings.NewReader(input)
	return Run(name, args, opts)
}

func WriteTempFile(content, suffix string) (string, error) {
	f, err := os.CreateTemp("", "reconator-*"+suffix)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if l := strings.TrimSpace(s.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, s.Err()
}

func Lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TempFile(content, suffix string) (string, func(), error) {
	path, err := WriteTempFile(content, suffix)
	if err != nil {
		return "", nil, err
	}
	return path, func() { os.Remove(path) }, nil
}
