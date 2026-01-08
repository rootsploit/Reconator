package exec

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

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
}

func Run(name string, args []string, opts *Options) *Result {
	if opts == nil {
		opts = &Options{Timeout: 5 * time.Minute}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
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

	start := time.Now()
	err := cmd.Run()

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
	return r
}

func RunWithInput(name string, args []string, input string, opts *Options) *Result {
	if opts == nil {
		opts = &Options{}
	}
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
