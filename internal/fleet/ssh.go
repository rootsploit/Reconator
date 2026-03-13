package fleet

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// SSHWorker runs commands on a remote machine over SSH
type SSHWorker struct {
	id      string
	host    string
	port    int
	user    string
	keyFile string
	client  *ssh.Client
	status  WorkerStatus
}

// NewSSHWorker creates a new SSH worker
func NewSSHWorker(host, user, keyFile string, port int) *SSHWorker {
	if port == 0 {
		port = 22
	}
	if user == "" {
		user = "root"
	}
	return &SSHWorker{
		id:      "ssh-" + uuid.New().String()[:8],
		host:    host,
		port:    port,
		user:    user,
		keyFile: keyFile,
		status:  StatusPending,
	}
}

func (w *SSHWorker) ID() string           { return w.id }
func (w *SSHWorker) Backend() BackendType { return BackendSSH }
func (w *SSHWorker) Status() WorkerStatus { return w.status }

// Deploy establishes the SSH connection
func (w *SSHWorker) Deploy(_ context.Context) error {
	keyData, err := os.ReadFile(w.keyFile)
	if err != nil {
		w.status = StatusError
		return fmt.Errorf("read SSH key %s: %w", w.keyFile, err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		w.status = StatusError
		return fmt.Errorf("parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: w.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", w.host, w.port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		w.status = StatusError
		return fmt.Errorf("SSH dial %s: %w", addr, err)
	}

	w.client = client
	w.status = StatusReady
	return nil
}

// Execute runs a command over the SSH session
func (w *SSHWorker) Execute(_ context.Context, cmd string, args ...string) (*ExecResult, error) {
	if w.client == nil {
		return nil, fmt.Errorf("SSH client not connected")
	}

	w.status = StatusBusy
	defer func() { w.status = StatusReady }()

	session, err := w.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()

	// Build full command string
	fullCmd := cmd
	for _, a := range args {
		fullCmd += " " + a
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	err = session.Run(fullCmd)

	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			result.ExitCode = exitErr.ExitStatus()
		} else {
			result.ExitCode = -1
			return result, fmt.Errorf("SSH execute: %w", err)
		}
	}

	return result, nil
}

// Upload copies a local file to the remote machine via scp
func (w *SSHWorker) Upload(_ context.Context, localPath, remotePath string) error {
	addr := fmt.Sprintf("%s@%s:%s", w.user, w.host, remotePath)
	args := []string{
		"-i", w.keyFile,
		"-P", fmt.Sprintf("%d", w.port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		localPath, addr,
	}
	cmd := exec.Command("scp", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp upload to %s: %s: %w", w.host, string(out), err)
	}
	return nil
}

// Download copies a remote file to the local machine via scp
func (w *SSHWorker) Download(_ context.Context, remotePath, localPath string) error {
	addr := fmt.Sprintf("%s@%s:%s", w.user, w.host, remotePath)
	args := []string{
		"-i", w.keyFile,
		"-P", fmt.Sprintf("%d", w.port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		addr, localPath,
	}
	cmd := exec.Command("scp", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp download from %s: %s: %w", w.host, string(out), err)
	}
	return nil
}

// Destroy closes the SSH connection
func (w *SSHWorker) Destroy(_ context.Context) error {
	w.status = StatusDestroyed
	if w.client != nil {
		return w.client.Close()
	}
	return nil
}
