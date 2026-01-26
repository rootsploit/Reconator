package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootsploit/reconator/internal/cli"
	"github.com/rootsploit/reconator/internal/exec"
)

func main() {
	// Set up signal handler to clean up child processes on exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n[!] Received interrupt signal, cleaning up...\n")
		exec.KillAllProcesses()
		os.Exit(130) // Standard exit code for SIGINT
	}()

	if err := cli.Execute(); err != nil {
		exec.KillAllProcesses()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
