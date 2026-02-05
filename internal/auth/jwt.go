package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// Claims represents JWT claims
type Claims struct {
	Username  string `json:"username"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token operations
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewJWTManager creates a new JWT manager with RSA keys
func NewJWTManager(keyPath string) (*JWTManager, error) {
	privateKey, publicKey, err := loadOrGenerateKeys(keyPath, false)
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		accessTTL:  2 * time.Hour,      // 2 hours for access token (more secure)
		refreshTTL: 24 * time.Hour,     // 24 hours for refresh token
	}, nil
}

// NewJWTManagerWithRotation creates a new JWT manager and optionally rotates keys
// If rotateKeys is true, existing keys are deleted and new ones are generated
// This invalidates all existing JWT tokens (useful for security on server restart)
func NewJWTManagerWithRotation(keyPath string, rotateKeys bool) (*JWTManager, error) {
	privateKey, publicKey, err := loadOrGenerateKeys(keyPath, rotateKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		accessTTL:  2 * time.Hour,
		refreshTTL: 24 * time.Hour,
	}, nil
}

// GenerateTokenPair generates both access and refresh tokens
func (m *JWTManager) GenerateTokenPair(username, sessionID string) (*TokenPair, error) {
	now := time.Now()
	expiresAt := now.Add(m.accessTTL)

	// Access token claims
	accessClaims := Claims{
		Username:  username,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "reconator",
			Subject:   username,
			ID:        sessionID,
		},
	}

	// Create access token with RS256
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh token claims (longer TTL)
	refreshClaims := Claims{
		Username:  username,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.refreshTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "reconator",
			Subject:   username,
			ID:        sessionID + "-refresh",
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken validates and parses a JWT token
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token from a valid refresh token
func (m *JWTManager) RefreshAccessToken(refreshToken string) (*TokenPair, error) {
	claims, err := m.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Generate new token pair
	return m.GenerateTokenPair(claims.Username, claims.SessionID)
}

// loadOrGenerateKeys loads existing RSA keys or generates new ones
// If rotateKeys is true, existing keys are deleted and regenerated (invalidates all tokens)
func loadOrGenerateKeys(keyPath string, rotateKeys bool) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKeyPath := filepath.Join(keyPath, "jwt_private.pem")
	publicKeyPath := filepath.Join(keyPath, "jwt_public.pem")

	// If rotation requested, delete existing keys
	if rotateKeys {
		os.Remove(privateKeyPath)
		os.Remove(publicKeyPath)
		fmt.Println("[Security] JWT keys rotated - all existing sessions invalidated")
	}

	// Try to load existing keys
	if !rotateKeys && fileExists(privateKeyPath) && fileExists(publicKeyPath) {
		privateKey, err := loadPrivateKey(privateKeyPath)
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := loadPublicKey(publicKeyPath)
		if err != nil {
			return nil, nil, err
		}
		return privateKey, publicKey, nil
	}

	// Generate new keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) // 4096-bit RSA key for security
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// Save keys to disk
	if err := savePrivateKey(privateKeyPath, privateKey); err != nil {
		return nil, nil, err
	}
	if err := savePublicKey(publicKeyPath, publicKey); err != nil {
		return nil, nil, err
	}

	if rotateKeys {
		fmt.Println("[Security] New JWT keys generated successfully")
	}

	return privateKey, publicKey, nil
}

// loadPrivateKey loads RSA private key from PEM file
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// loadPublicKey loads RSA public key from PEM file
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// savePrivateKey saves RSA private key to PEM file
func savePrivateKey(path string, key *rsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// savePublicKey saves RSA public key to PEM file
func savePublicKey(path string, key *rsa.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PublicKey(key)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GenerateSessionID generates a secure random session ID
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
