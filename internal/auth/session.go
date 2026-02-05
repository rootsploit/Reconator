package auth

import (
	"sync"
	"time"
)

// SessionStore tracks active sessions in memory
// Sessions are invalidated when the server restarts
type SessionStore struct {
	sessions   map[string]*Session
	mu         sync.RWMutex
	serverEpoch time.Time // When server started - used to invalidate old tokens
}

// Session represents an active user session
type Session struct {
	SessionID string
	Username  string
	CreatedAt time.Time
	LastSeen  time.Time
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:   make(map[string]*Session),
		serverEpoch: time.Now(),
	}
}

// CreateSession creates a new session
func (s *SessionStore) CreateSession(sessionID, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sessionID] = &Session{
		SessionID: sessionID,
		Username:  username,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
}

// ValidateSession checks if a session is valid and updates last seen time
func (s *SessionStore) ValidateSession(sessionID string, issuedAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if token was issued before server restart
	if issuedAt.Before(s.serverEpoch) {
		return false
	}

	session, exists := s.sessions[sessionID]
	if !exists {
		return false
	}

	// Update last seen time
	session.LastSeen = time.Now()
	return true
}

// InvalidateSession removes a session
func (s *SessionStore) InvalidateSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
}

// GetActiveSessions returns count of active sessions
func (s *SessionStore) GetActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.sessions)
}

// CleanupExpiredSessions removes sessions older than the specified duration
func (s *SessionStore) CleanupExpiredSessions(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.LastSeen) > maxAge {
			delete(s.sessions, id)
		}
	}
}

// GetServerEpoch returns when the server started
func (s *SessionStore) GetServerEpoch() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.serverEpoch
}
