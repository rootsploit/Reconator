package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rootsploit/reconator/internal/auth"
	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/version"
	"github.com/rootsploit/reconator/web"
)

// Server represents the web dashboard server
type Server struct {
	router          *gin.Engine
	httpServer      *http.Server
	config          *Config
	scanMgr         *ScanManager
	wsHub           *WebSocketHub
	jwtManager      *auth.JWTManager
	sessionStore    *auth.SessionStore
	authRateLimiter *AuthRateLimiter
}

// Config holds server configuration
type Config struct {
	Port           int
	Host           string
	APIKey         string // Optional API key for authentication
	AllowedOrigins []string
	Debug          bool
	ScanConfig     *config.Config
	RotateJWT      bool // Rotate JWT keys on server start (invalidates existing sessions)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Port:           8888,
		Host:           "127.0.0.1", // Localhost only by default (secure)
		AllowedOrigins: []string{"http://localhost:8888", "http://127.0.0.1:8888"},
		Debug:          false,
		ScanConfig:     config.DefaultConfig(),
	}
}

// New creates a new server instance
func New(cfg *Config) *Server {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Set Gin mode based on debug flag
	if cfg.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Initialize JWT manager (with optional key rotation)
	home, _ := os.UserHomeDir()
	keyPath := filepath.Join(home, ".reconator")
	jwtManager, err := auth.NewJWTManagerWithRotation(keyPath, cfg.RotateJWT)
	if err != nil {
		fmt.Printf("Warning: Failed to initialize JWT manager: %v\n", err)
		fmt.Println("JWT authentication will be disabled. Using API key only.")
	}

	// Create server instance
	wsHub := NewWebSocketHub()
	scanMgr := NewScanManager(cfg.ScanConfig)
	scanMgr.SetWebSocketHub(wsHub)

	// Initialize auth rate limiter for brute force protection
	authRateLimiter := NewAuthRateLimiter()

	// Initialize session store (invalidates all sessions on server restart)
	sessionStore := auth.NewSessionStore()

	s := &Server{
		router:          router,
		config:          cfg,
		scanMgr:         scanMgr,
		wsHub:           wsHub,
		jwtManager:      jwtManager,
		sessionStore:    sessionStore,
		authRateLimiter: authRateLimiter,
	}

	// Setup middleware and routes
	s.setupMiddleware()
	s.setupRoutes()

	// Serve scan data (screenshots, reports, etc.)
	router.Static("/scan-data", cfg.ScanConfig.OutputDir)

	return s
}

// setupMiddleware configures security and logging middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware (handles panics)
	s.router.Use(gin.Recovery())

	// Custom structured logger
	s.router.Use(s.requestLogger())

	// Security headers middleware
	s.router.Use(s.securityHeaders())

	// CORS configuration
	corsConfig := cors.Config{
		AllowOrigins:     s.config.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-API-Key", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	s.router.Use(cors.New(corsConfig))

	// Rate limiting middleware
	s.router.Use(s.rateLimiter())
}

// securityHeaders adds security headers to all responses
func (s *Server) securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		// XSS protection
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://localhost:* wss://localhost:*")
		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Permissions policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		c.Next()
	}
}

// requestLogger logs requests in a structured format
func (s *Server) requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		// Skip logging for static assets, health checks, and WebSocket connections
		if path == "/health" || path == "/favicon.ico" || path == "/ws" ||
			strings.HasPrefix(path, "/assets/") || strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".map") {
			return
		}

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		// Format latency in readable units
		var latencyStr string
		if latency < time.Millisecond {
			latencyStr = fmt.Sprintf("%.2fµs", float64(latency.Microseconds()))
		} else if latency < time.Second {
			latencyStr = fmt.Sprintf("%.2fms", float64(latency.Microseconds())/1000.0)
		} else {
			latencyStr = fmt.Sprintf("%.2fs", latency.Seconds())
		}

		// Color-coded status
		statusColor := "\033[32m" // Green
		if statusCode >= 400 {
			statusColor = "\033[31m" // Red
		} else if statusCode >= 300 {
			statusColor = "\033[33m" // Yellow
		}

		// Only log API requests and important operations
		if strings.HasPrefix(path, "/api/") {
			fmt.Printf("%s[%d]\033[0m %-6s %-50s %15s %10s\n",
				statusColor, statusCode, method, path, clientIP, latencyStr)
		}
	}
}

// rateLimiter implements simple in-memory rate limiting
func (s *Server) rateLimiter() gin.HandlerFunc {
	// Simple token bucket implementation
	type client struct {
		tokens    int
		lastReset time.Time
	}
	clients := make(map[string]*client)
	maxTokens := 100       // Max requests per window
	window := time.Minute  // Window duration
	refillRate := 10       // Tokens per second

	return func(c *gin.Context) {
		ip := c.ClientIP()

		cl, exists := clients[ip]
		if !exists {
			cl = &client{tokens: maxTokens, lastReset: time.Now()}
			clients[ip] = cl
		}

		// Refill tokens based on time passed
		elapsed := time.Since(cl.lastReset)
		if elapsed >= window {
			cl.tokens = maxTokens
			cl.lastReset = time.Now()
		} else {
			refill := int(elapsed.Seconds()) * refillRate
			cl.tokens = min(cl.tokens+refill, maxTokens)
		}

		if cl.tokens <= 0 {
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
			})
			return
		}

		cl.tokens--
		c.Next()
	}
}

// apiKeyAuth middleware for protected endpoints
// SECURITY: Always enforces authentication - API key is now required
func (s *Server) apiKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authentication is ALWAYS required (API key is generated on server startup)
		if s.config.APIKey == "" {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Server misconfiguration: API key not set",
			})
			return
		}

		// Check for API key in X-API-Key header or query parameter
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.GetHeader("Authorization") // Also support Authorization header
			if apiKey != "" && len(apiKey) > 7 && apiKey[:7] == "Bearer " {
				apiKey = apiKey[7:] // Strip "Bearer " prefix
			}
		}
		if apiKey == "" {
			apiKey = c.Query("api_key") // Fallback to query parameter
		}

		if apiKey != s.config.APIKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or missing API key. Provide API key in X-API-Key header, Authorization header, or ?api_key= query parameter.",
			})
			return
		}

		c.Next()
	}
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Health check (no auth required)
	s.router.GET("/health", s.healthCheck)

	// API routes
	api := s.router.Group("/api/v1")
	{
		// Public endpoints
		api.GET("/version", s.getVersion)

		// Authentication endpoints with aggressive rate limiting
		authGroup := api.Group("/auth")
		authGroup.Use(s.authRateLimiter.AuthRateLimitMiddleware())
		{
			authGroup.POST("/login", s.login)
			authGroup.POST("/refresh", s.refreshToken)
			authGroup.POST("/logout", s.logout)
		}

		// User info endpoint (requires JWT)
		if s.jwtManager != nil {
			api.GET("/user", auth.JWTMiddleware(s.jwtManager, s.sessionStore), s.getCurrentUser)
		}

		// Protected scan endpoints (JWT or API key)
		scans := api.Group("/scans")
		scans.Use(s.flexibleAuth())
		{
			scans.GET("", s.listScans)
			scans.POST("", s.startScan)
			scans.GET("/:id", s.getScan)
			scans.GET("/:id/status", s.getScanStatus)
			scans.DELETE("/:id", s.stopScan)
			scans.POST("/:id/pause", s.pauseScan)
			scans.POST("/:id/resume", s.resumeScan)
			scans.GET("/:id/findings", s.getScanFindings)
			scans.GET("/:id/report", s.getScanReport)
		}

		// Export endpoints
		exports := api.Group("/export")
		exports.Use(s.flexibleAuth())
		{
			exports.POST("/:id/csv", s.exportCSV)
			exports.POST("/:id/json", s.exportJSON)
			exports.POST("/:id/sarif", s.exportSARIF)
			exports.POST("/:id/html", s.exportHTML)
		}

		// Vulnerability management endpoints
		vulns := api.Group("/vulnerabilities")
		vulns.Use(s.flexibleAuth())
		{
			vulns.POST("/:id/mark-fp", s.markVulnAsFalsePositive)
			vulns.DELETE("/:id/mark-fp", s.unmarkVulnAsFalsePositive)
			vulns.POST("/:id/note", s.addVulnNote)
		}

		// Stats endpoint
		api.GET("/stats", s.flexibleAuth(), s.getStats)

		// Configuration endpoints
		config := api.Group("/config")
		config.Use(s.flexibleAuth())
		{
			config.GET("", s.getConfig)
			config.POST("/test", s.testAPIKey)
			config.POST("/update", s.updateAPIKey)
			config.POST("/sync", s.syncConfig)
		}

		// Schedules endpoints (placeholder for Phase 2.2)
		schedules := api.Group("/schedules")
		schedules.Use(s.flexibleAuth())
		{
			schedules.GET("", s.listSchedules)
			schedules.POST("", s.createSchedule)
			schedules.GET("/:id", s.getSchedule)
			schedules.PUT("/:id", s.updateSchedule)
			schedules.DELETE("/:id", s.deleteSchedule)
		}

		// Templates endpoints (placeholder for Phase 2.2)
		templates := api.Group("/templates")
		templates.Use(s.flexibleAuth())
		{
			templates.GET("", s.listTemplates)
			templates.POST("", s.createTemplate)
			templates.GET("/:id", s.getTemplate)
			templates.PUT("/:id", s.updateTemplate)
			templates.DELETE("/:id", s.deleteTemplate)
		}
	}

	// WebSocket for live updates
	s.router.GET("/ws", s.handleWebSocket)

	// Serve scan results (screenshots, reports, etc.) - MUST be before NoRoute
	// This allows the frontend to load screenshots and other scan artifacts
	resultsDir := s.config.ScanConfig.OutputDir
	if resultsDir == "" {
		resultsDir = "./results"
	}
	s.router.Static("/results", resultsDir)

	// Serve static files for UI at root (embedded or development)
	// Use NoRoute to serve static files as fallback for unmatched routes
	// Try embedded assets first, fall back to physical directory if not embedded
	webFS, err := web.GetFS()
	if err != nil {
		// Fallback to physical directory if embedded assets not available
		webFS = http.Dir("web/dist")
	}
	s.router.NoRoute(gin.WrapH(http.FileServer(webFS)))
}

// flexibleAuth accepts either JWT token or API key for backward compatibility
func (s *Server) flexibleAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try JWT first if available
		if s.jwtManager != nil {
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token := authHeader[7:]
				claims, err := s.jwtManager.ValidateToken(token)
				if err == nil {
					// JWT is valid, set user context and continue
					c.Set("username", claims.Username)
					c.Set("session_id", claims.SessionID)
					c.Next()
					return
				}
			}
		}

		// Fallback to API key authentication
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey != s.config.APIKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or missing authentication. Provide JWT token in Authorization header or API key in X-API-Key header.",
			})
			return
		}

		c.Next()
	}
}

// Start starts the server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start WebSocket hub
	go s.wsHub.Run()

	// Print startup message
	fmt.Printf("\n\033[36m[*] Reconator Dashboard\033[0m\n")
	fmt.Printf("    Version: %s\n", version.Version)
	fmt.Printf("    Address: http://%s\n", addr)
	fmt.Printf("    API Docs: http://%s/api/v1\n", addr)
	if s.config.APIKey != "" {
		fmt.Printf("    API Key: %s (required for scan operations)\n", maskAPIKey(s.config.APIKey))
	}

	// Show asset source
	if web.HasAssets() {
		fmt.Printf("    Assets: Embedded (single binary deployment)\n")
	} else {
		fmt.Printf("    Assets: Development mode (web/dist)\n")
	}

	fmt.Printf("\n")

	return s.httpServer.ListenAndServe()
}

// StartWithGracefulShutdown starts the server with graceful shutdown handling
func (s *Server) StartWithGracefulShutdown() error {
	// Channel to listen for errors
	errChan := make(chan error, 1)

	// Start server in goroutine
	go func() {
		if err := s.Start(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return err
	case <-quit:
		fmt.Println("\n[*] Shutting down server...")
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	fmt.Println("[*] Server stopped")
	return nil
}

// GenerateAPIKey generates a secure random API key
func GenerateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Helper to mask API key for display
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
