package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// JWTMiddleware creates a middleware for JWT authentication with session validation
func JWTMiddleware(jwtManager *JWTManager, sessionStore *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := parts[1]

		// Validate token
		claims, err := jwtManager.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Validate session (ensures tokens from before server restart are invalid)
		if !sessionStore.ValidateSession(claims.SessionID, claims.IssuedAt.Time) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session invalidated or server restarted"})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("username", claims.Username)
		c.Set("session_id", claims.SessionID)

		c.Next()
	}
}

// OptionalJWTMiddleware creates a middleware that checks for JWT but doesn't require it
func OptionalJWTMiddleware(jwtManager *JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			claims, err := jwtManager.ValidateToken(parts[1])
			if err == nil {
				c.Set("username", claims.Username)
				c.Set("session_id", claims.SessionID)
			}
		}

		c.Next()
	}
}
