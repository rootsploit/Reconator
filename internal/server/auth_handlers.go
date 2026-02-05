package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rootsploit/reconator/internal/auth"
)

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest represents refresh token request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// login handles user authentication and returns JWT tokens
func (s *Server) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate credentials
	// Username must be "reconator" and password must be the API key
	if req.Username != "reconator" || req.Password != s.config.APIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate session ID
	sessionID, err := auth.GenerateSessionID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session"})
		return
	}

	// Create session in store (invalidated on server restart)
	s.sessionStore.CreateSession(sessionID, req.Username)

	// Generate JWT token pair
	tokenPair, err := s.jwtManager.GenerateTokenPair(req.Username, sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Reset rate limiting on successful authentication
	s.authRateLimiter.RecordSuccess(c.ClientIP())

	c.JSON(http.StatusOK, tokenPair)
}

// refreshToken handles token refresh
func (s *Server) refreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Refresh the access token
	tokenPair, err := s.jwtManager.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

// logout handles user logout (client should discard tokens)
func (s *Server) logout(c *gin.Context) {
	// Invalidate session on server side
	sessionID, exists := c.Get("session_id")
	if exists {
		s.sessionStore.InvalidateSession(sessionID.(string))
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// getCurrentUser returns information about the authenticated user
func (s *Server) getCurrentUser(c *gin.Context) {
	username, _ := c.Get("username")
	sessionID, _ := c.Get("session_id")

	c.JSON(http.StatusOK, gin.H{
		"username":   username,
		"session_id": sessionID,
	})
}
