package server

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthRateLimiter implements aggressive rate limiting for authentication endpoints
// to prevent brute force attacks on login credentials
type AuthRateLimiter struct {
	attempts map[string]*AuthAttempt
	mu       sync.RWMutex
}

// AuthAttempt tracks authentication attempts per IP address
type AuthAttempt struct {
	Count        int
	FirstAttempt time.Time
	BlockedUntil *time.Time
}

// NewAuthRateLimiter creates a new authentication rate limiter
func NewAuthRateLimiter() *AuthRateLimiter {
	limiter := &AuthRateLimiter{
		attempts: make(map[string]*AuthAttempt),
	}

	// Start cleanup goroutine to remove old entries
	go limiter.cleanup()

	return limiter
}

// cleanup removes old entries every hour to prevent memory leaks
func (arl *AuthRateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		arl.mu.Lock()
		now := time.Now()
		for ip, attempt := range arl.attempts {
			// Remove if not blocked and last attempt > 1 hour ago
			if attempt.BlockedUntil == nil &&
				now.Sub(attempt.FirstAttempt) > time.Hour {
				delete(arl.attempts, ip)
			}
			// Remove if block expired
			if attempt.BlockedUntil != nil &&
				now.After(*attempt.BlockedUntil) {
				delete(arl.attempts, ip)
			}
		}
		arl.mu.Unlock()
	}
}

// Allow checks if the IP is allowed to attempt authentication
// Returns (allowed, remainingBlockTime)
func (arl *AuthRateLimiter) Allow(ip string) (bool, time.Duration) {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	now := time.Now()
	attempt, exists := arl.attempts[ip]

	if !exists {
		// First attempt from this IP
		arl.attempts[ip] = &AuthAttempt{
			Count:        1,
			FirstAttempt: now,
		}
		return true, 0
	}

	// Check if currently blocked
	if attempt.BlockedUntil != nil {
		if now.Before(*attempt.BlockedUntil) {
			remaining := attempt.BlockedUntil.Sub(now)
			return false, remaining
		}
		// Block expired, reset counters
		attempt.Count = 1
		attempt.FirstAttempt = now
		attempt.BlockedUntil = nil
		return true, 0
	}

	// Reset counter if time window passed (15 minutes)
	if now.Sub(attempt.FirstAttempt) > 15*time.Minute {
		attempt.Count = 1
		attempt.FirstAttempt = now
		return true, 0
	}

	// Increment attempt counter
	attempt.Count++

	// Progressive blocking based on attempt count
	// 5 attempts in 15 min = 5 min block
	// 10 attempts in 15 min = 30 min block
	// 15+ attempts in 15 min = 24 hour block
	if attempt.Count >= 15 {
		blockUntil := now.Add(24 * time.Hour)
		attempt.BlockedUntil = &blockUntil
		return false, 24 * time.Hour
	} else if attempt.Count >= 10 {
		blockUntil := now.Add(30 * time.Minute)
		attempt.BlockedUntil = &blockUntil
		return false, 30 * time.Minute
	} else if attempt.Count >= 5 {
		blockUntil := now.Add(5 * time.Minute)
		attempt.BlockedUntil = &blockUntil
		return false, 5 * time.Minute
	}

	// Still allowed
	return true, 0
}

// RecordSuccess resets the attempt counter for successful authentication
func (arl *AuthRateLimiter) RecordSuccess(ip string) {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	delete(arl.attempts, ip)
}

// AuthRateLimitMiddleware is a Gin middleware that enforces rate limiting on auth endpoints
func (arl *AuthRateLimiter) AuthRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		allowed, blockDuration := arl.Allow(ip)
		if !allowed {
			c.JSON(429, gin.H{
				"error":           "Too many authentication attempts",
				"retry_after_sec": int(blockDuration.Seconds()),
				"message":         "Account temporarily locked due to failed authentication attempts",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
