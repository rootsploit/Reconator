package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rootsploit/reconator/internal/server"
	"github.com/spf13/cobra"
)

var (
	serverPort     int
	serverHost     string
	serverAPIKey   string
	serverGenKey   bool
	serverAllowAll bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the web dashboard server",
	Long: `Start a web dashboard server for managing scans and viewing results.

The server provides:
  - REST API for scan management
  - WebSocket for live scan progress
  - HTML dashboard for visualization

Security features:
  - Rate limiting (100 requests/minute per IP)
  - CORS protection
  - Security headers (X-Frame-Options, CSP, etc.)
  - Optional API key authentication

Examples:
  # Start with default settings (localhost:8888)
  reconator server

  # Start on custom port
  reconator server --port 9000

  # Allow external connections (use with caution!)
  reconator server --host 0.0.0.0

  # Generate and use API key for authentication
  reconator server --gen-key

  # Use specific API key
  reconator server --api-key YOUR_SECRET_KEY`,
	RunE: runServer,
}

func init() {
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8888, "Server port")
	serverCmd.Flags().StringVarP(&serverHost, "host", "H", "127.0.0.1", "Server host (use 0.0.0.0 for all interfaces)")
	serverCmd.Flags().StringVar(&serverAPIKey, "api-key", "", "API key for authentication (protects scan endpoints)")
	serverCmd.Flags().BoolVar(&serverGenKey, "gen-key", false, "Generate a random API key")
	serverCmd.Flags().BoolVar(&serverAllowAll, "allow-all-origins", false, "Allow all CORS origins (insecure, for development)")

	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	// Print banner
	cyan.Println("\n┌─────────────────────────────────────────┐")
	cyan.Println("│       RECONATOR WEB DASHBOARD           │")
	cyan.Println("└─────────────────────────────────────────┘")
	fmt.Println()

	// Always generate or use API key for authentication (REQUIRED)
	apiKey := serverAPIKey
	if apiKey == "" {
		// Generate random API key for this session
		apiKey = server.GenerateAPIKey()
		green.Println("  🔐 Authentication Enabled (Required)")
		green.Println("  ────────────────────────────────────────")
		green.Printf("  Username: reconator\n")
		green.Printf("  API Key:  %s\n", apiKey)
		green.Println("  ────────────────────────────────────────")
		yellow.Println("  ⚠️  Save this key - it won't be shown again!")
		yellow.Println("  ⚠️  Use this key in Authorization header or ?api_key= param")
		fmt.Println()
	} else {
		// User provided their own API key
		cyan.Println("  🔐 Authentication Enabled with provided API key")
		cyan.Printf("  Username: reconator\n")
		fmt.Println()
	}

	// Security warning for external access
	if serverHost == "0.0.0.0" {
		yellow.Println("  ⚠️  WARNING: Server is accessible from all network interfaces!")
		yellow.Println("  ⚠️  Ensure you have proper firewall rules in place.")
		yellow.Println("  ⚠️  API authentication is REQUIRED for all endpoints.")
		fmt.Println()
	}

	// Configure allowed origins
	allowedOrigins := []string{
		fmt.Sprintf("http://localhost:%d", serverPort),
		fmt.Sprintf("http://127.0.0.1:%d", serverPort),
	}
	if serverAllowAll {
		yellow.Println("  ⚠️  CORS: All origins allowed (insecure)")
		allowedOrigins = []string{"*"}
	}

	// Create server config
	serverConfig := &server.Config{
		Port:           serverPort,
		Host:           serverHost,
		APIKey:         apiKey,
		AllowedOrigins: allowedOrigins,
		Debug:          cfg.Debug,
		ScanConfig:     &cfg,
	}

	// Create and start server
	srv := server.New(serverConfig)

	fmt.Println("  Starting server...")
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	return srv.StartWithGracefulShutdown()
}
