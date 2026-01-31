package aiguided

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ProviderType represents an AI provider
type ProviderType string

const (
	ProviderOpenAI  ProviderType = "openai"
	ProviderClaude  ProviderType = "claude"
	ProviderGemini  ProviderType = "gemini"
	ProviderGroq    ProviderType = "groq"
	ProviderOllama  ProviderType = "ollama"
	ProviderDeepSeek ProviderType = "deepseek"
)

// ProviderConfig holds configuration for a single AI provider
type ProviderConfig struct {
	Name     ProviderType `yaml:"name" json:"name"`
	Keys     []string     `yaml:"keys" json:"keys"`
	Endpoint string       `yaml:"endpoint,omitempty" json:"endpoint,omitempty"` // For self-hosted
	Model    string       `yaml:"model,omitempty" json:"model,omitempty"`
	RPMLimit int          `yaml:"rpm_limit,omitempty" json:"rpm_limit,omitempty"` // Requests per minute
	Fallback ProviderType `yaml:"fallback,omitempty" json:"fallback,omitempty"`
}

// AIConfig holds the complete AI configuration
type AIConfig struct {
	Providers []ProviderConfig `yaml:"providers" json:"providers"`
	DefaultProvider ProviderType `yaml:"default_provider,omitempty" json:"default_provider,omitempty"`
}

// KeyUsage tracks usage for a single API key
type KeyUsage struct {
	Requests     int64     `json:"requests"`
	Tokens       int64     `json:"tokens"`
	LastUsed     time.Time `json:"last_used"`
	RateLimited  bool      `json:"rate_limited"`
	RateLimitEnd time.Time `json:"rate_limit_end"`
	Errors       int       `json:"errors"`
}

// ProviderManager manages AI providers with key rotation and failover
type ProviderManager struct {
	config    *AIConfig
	keyUsage  map[string]*KeyUsage // key -> usage stats
	keyIndex  map[ProviderType]int // provider -> current key index
	mu        sync.RWMutex
}

// NewProviderManager creates a new provider manager
func NewProviderManager() *ProviderManager {
	return &ProviderManager{
		config:   &AIConfig{},
		keyUsage: make(map[string]*KeyUsage),
		keyIndex: make(map[ProviderType]int),
	}
}

// LoadFromFile loads AI configuration from a YAML file
func (pm *ProviderManager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, pm.config)
}

// LoadFromEnv loads API keys from environment variables
func (pm *ProviderManager) LoadFromEnv() {
	// OpenAI
	if keys := getEnvKeys("OPENAI_API_KEY", "OPENAI_API_KEYS"); len(keys) > 0 {
		pm.addProvider(ProviderOpenAI, keys, "", "gpt-4o-mini", 60)
	}

	// Claude
	if keys := getEnvKeys("ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "ANTHROPIC_API_KEYS"); len(keys) > 0 {
		pm.addProvider(ProviderClaude, keys, "", "claude-sonnet-4-20250514", 50)
	}

	// Gemini
	if keys := getEnvKeys("GEMINI_API_KEY", "GOOGLE_AI_KEY", "GEMINI_API_KEYS"); len(keys) > 0 {
		pm.addProvider(ProviderGemini, keys, "", "gemini-1.5-flash", 60)
	}

	// Groq
	if keys := getEnvKeys("GROQ_API_KEY", "GROQ_API_KEYS"); len(keys) > 0 {
		pm.addProvider(ProviderGroq, keys, "", "llama-3.3-70b-versatile", 30)
	}

	// DeepSeek
	if keys := getEnvKeys("DEEPSEEK_API_KEY", "DEEPSEEK_API_KEYS"); len(keys) > 0 {
		pm.addProvider(ProviderDeepSeek, keys, "", "deepseek-chat", 60)
	}

	// Ollama (local)
	ollamaURL := os.Getenv("OLLAMA_HOST")
	if ollamaURL == "" {
		ollamaURL = os.Getenv("OLLAMA_URL")
	}
	ollamaModel := os.Getenv("OLLAMA_MODEL")
	if ollamaModel == "" {
		ollamaModel = "llama3.2"
	}
	if ollamaURL != "" || os.Getenv("OLLAMA_ENABLED") == "true" {
		if ollamaURL == "" {
			ollamaURL = "http://localhost:11434"
		}
		pm.addProvider(ProviderOllama, []string{""}, ollamaURL, ollamaModel, 0) // No rate limit for local
	}

	// Set up fallback chain
	pm.setupFallbackChain()
}

// addProvider adds a provider to the configuration
func (pm *ProviderManager) addProvider(name ProviderType, keys []string, endpoint, model string, rpmLimit int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.config.Providers = append(pm.config.Providers, ProviderConfig{
		Name:     name,
		Keys:     keys,
		Endpoint: endpoint,
		Model:    model,
		RPMLimit: rpmLimit,
	})
	pm.keyIndex[name] = 0
}

// setupFallbackChain sets up automatic fallback between providers
// Uses the order from config file - each provider falls back to the next one in the list
func (pm *ProviderManager) setupFallbackChain() {
	for i := range pm.config.Providers {
		provider := &pm.config.Providers[i]
		if provider.Fallback != "" {
			continue // Already configured manually
		}

		// Find next available provider in config order
		for j := i + 1; j < len(pm.config.Providers); j++ {
			nextProvider := &pm.config.Providers[j]
			// hasValidKeys already checks Ollama reachability
			if hasValidKeys(*nextProvider) {
				provider.Fallback = nextProvider.Name
				break
			}
		}
	}
}

// HasProvider checks if a provider is configured
func (pm *ProviderManager) HasProvider(provider ProviderType) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, p := range pm.config.Providers {
		if p.Name == provider && hasValidKeys(p) {
			return true
		}
	}
	return false
}

// GetAvailableProviders returns list of configured providers
func (pm *ProviderManager) GetAvailableProviders() []ProviderType {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var providers []ProviderType
	for _, p := range pm.config.Providers {
		if hasValidKeys(p) {
			providers = append(providers, p.Name)
		}
	}
	return providers
}

// hasValidKeys checks if provider has non-placeholder keys
func hasValidKeys(p ProviderConfig) bool {
	// Ollama doesn't need keys, just an endpoint that's reachable
	if p.Name == ProviderOllama {
		if p.Endpoint == "" {
			return false
		}
		// Quick reachability check with short timeout
		return isOllamaReachable(p.Endpoint)
	}

	for _, key := range p.Keys {
		// Skip empty keys
		if key == "" {
			continue
		}
		// Skip placeholder keys
		if strings.Contains(key, "YOUR_") && strings.Contains(key, "_KEY") {
			continue
		}
		// Found a valid key
		return true
	}
	return false
}

// Ollama reachability cache to avoid repeated network checks
var (
	ollamaReachableCache     = make(map[string]bool)
	ollamaReachableCacheMu   sync.RWMutex
	ollamaReachableCacheTime = make(map[string]time.Time)
)

// isOllamaReachable checks if Ollama is running at the given endpoint
// Uses a very short timeout to avoid blocking when Ollama isn't running
// Results are cached for 30 seconds to avoid repeated checks
func isOllamaReachable(endpoint string) bool {
	ollamaReachableCacheMu.RLock()
	if cachedTime, ok := ollamaReachableCacheTime[endpoint]; ok {
		if time.Since(cachedTime) < 30*time.Second {
			result := ollamaReachableCache[endpoint]
			ollamaReachableCacheMu.RUnlock()
			return result
		}
	}
	ollamaReachableCacheMu.RUnlock()

	// Do the actual check
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(endpoint + "/api/version")
	reachable := err == nil && resp != nil && resp.StatusCode == 200
	if resp != nil {
		resp.Body.Close()
	}

	// Cache the result
	ollamaReachableCacheMu.Lock()
	ollamaReachableCache[endpoint] = reachable
	ollamaReachableCacheTime[endpoint] = time.Now()
	ollamaReachableCacheMu.Unlock()

	return reachable
}

// HasAnyProviderConfigured checks if any AI provider is available
// This loads from both environment variables and config file
func HasAnyProviderConfigured() bool {
	pm := NewProviderManager()
	pm.LoadFromEnv()

	// Load from config file if it exists
	configPath := GetDefaultConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		pm.LoadFromFile(configPath)
	}

	return len(pm.GetAvailableProviders()) > 0
}

// QueryRaw sends a prompt and returns the raw string response (for custom parsing)
func (pm *ProviderManager) QueryRaw(prompt string) (string, ProviderType, error) {
	providers := pm.GetAvailableProviders()
	if len(providers) == 0 {
		return "", "", fmt.Errorf("no AI providers configured")
	}

	var errors []string

	// Try all available providers in order
	for _, provider := range providers {
		response, err := pm.queryProviderRaw(provider, prompt)
		if err == nil {
			return response, provider, nil
		}

		errors = append(errors, fmt.Sprintf("%s: %v", provider, err))

		// Try key rotation on rate limit
		if isRateLimitError(err) {
			if pm.rotateKey(provider) {
				response, err := pm.queryProviderRaw(provider, prompt)
				if err == nil {
					return response, provider, nil
				}
				errors = append(errors, fmt.Sprintf("%s (retry): %v", provider, err))
			}
		}
	}

	return "", "", fmt.Errorf("all AI providers failed: %s", strings.Join(errors, "; "))
}

// queryProviderRaw queries a provider and returns raw response
func (pm *ProviderManager) queryProviderRaw(provider ProviderType, prompt string) (string, error) {
	pm.mu.RLock()
	var providerCfg *ProviderConfig
	for i := range pm.config.Providers {
		if pm.config.Providers[i].Name == provider {
			providerCfg = &pm.config.Providers[i]
			break
		}
	}
	if providerCfg == nil {
		pm.mu.RUnlock()
		return "", fmt.Errorf("provider %s not configured", provider)
	}

	// Get API key (Ollama doesn't need one)
	var apiKey string
	if len(providerCfg.Keys) > 0 {
		keyIdx := pm.keyIndex[provider]
		if keyIdx >= len(providerCfg.Keys) {
			keyIdx = 0
		}
		apiKey = providerCfg.Keys[keyIdx]
	}
	model := providerCfg.Model
	endpoint := providerCfg.Endpoint
	pm.mu.RUnlock()

	// Skip rate limit check for Ollama (no key) or if key is empty
	if apiKey != "" && pm.isKeyRateLimited(apiKey) {
		return "", fmt.Errorf("key is rate limited")
	}

	var response string
	var err error

	switch provider {
	case ProviderOpenAI:
		response, err = queryOpenAIRaw(prompt, apiKey, model)
	case ProviderClaude:
		response, err = queryClaudeRaw(prompt, apiKey, model)
	case ProviderGemini:
		response, err = queryGeminiRaw(prompt, apiKey, model)
	case ProviderGroq:
		response, err = queryGroqRaw(prompt, apiKey, model)
	case ProviderDeepSeek:
		response, err = queryDeepSeekRaw(prompt, apiKey, model)
	case ProviderOllama:
		response, err = queryOllamaRaw(prompt, endpoint, model)
	default:
		err = fmt.Errorf("unknown provider: %s", provider)
	}

	pm.updateUsage(apiKey, err)
	return response, err
}

// Query sends a prompt to the best available AI provider with automatic rotation/failover
func (pm *ProviderManager) Query(prompt string) (*AIRecommendation, ProviderType, error) {
	providers := pm.GetAvailableProviders()
	if len(providers) == 0 {
		return nil, "", fmt.Errorf("no AI providers configured")
	}

	var lastErr error
	triedProviders := make(map[ProviderType]bool)

	// Start with first available provider
	currentProvider := providers[0]

	for {
		if triedProviders[currentProvider] {
			break // Already tried this one, avoid infinite loop
		}
		triedProviders[currentProvider] = true

		rec, err := pm.queryProvider(currentProvider, prompt)
		if err == nil {
			return rec, currentProvider, nil
		}

		lastErr = err

		// Check if it's a rate limit error - try next key or fallback
		if isRateLimitError(err) {
			// Try rotating to next key for this provider
			if pm.rotateKey(currentProvider) {
				// Try again with new key
				rec, err := pm.queryProvider(currentProvider, prompt)
				if err == nil {
					return rec, currentProvider, nil
				}
			}
		}

		// Get fallback provider
		fallback := pm.getFallback(currentProvider)
		if fallback == "" {
			break
		}
		currentProvider = fallback
	}

	return nil, "", fmt.Errorf("all AI providers failed: %w", lastErr)
}

// queryProvider queries a specific provider
func (pm *ProviderManager) queryProvider(provider ProviderType, prompt string) (*AIRecommendation, error) {
	pm.mu.RLock()
	var providerCfg *ProviderConfig
	for i := range pm.config.Providers {
		if pm.config.Providers[i].Name == provider {
			providerCfg = &pm.config.Providers[i]
			break
		}
	}
	if providerCfg == nil {
		pm.mu.RUnlock()
		return nil, fmt.Errorf("provider %s not configured", provider)
	}

	model := providerCfg.Model
	endpoint := providerCfg.Endpoint

	// Handle Ollama separately (no API key needed)
	if provider == ProviderOllama {
		pm.mu.RUnlock()
		return queryOllamaWithEndpoint(prompt, endpoint, model)
	}

	// For other providers, need API keys
	if len(providerCfg.Keys) == 0 {
		pm.mu.RUnlock()
		return nil, fmt.Errorf("provider %s has no API keys configured", provider)
	}

	keyIdx := pm.keyIndex[provider]
	if keyIdx >= len(providerCfg.Keys) {
		keyIdx = 0
	}
	apiKey := providerCfg.Keys[keyIdx]
	pm.mu.RUnlock()

	// Check if key is rate limited
	if pm.isKeyRateLimited(apiKey) {
		return nil, fmt.Errorf("key is rate limited")
	}

	var rec *AIRecommendation
	var err error

	switch provider {
	case ProviderOpenAI:
		rec, err = queryOpenAIWithKey(prompt, apiKey, model)
	case ProviderClaude:
		rec, err = queryClaudeWithKey(prompt, apiKey, model)
	case ProviderGemini:
		rec, err = queryGeminiWithKey(prompt, apiKey, model)
	case ProviderGroq:
		rec, err = queryGroqWithKey(prompt, apiKey, model)
	case ProviderDeepSeek:
		rec, err = queryDeepSeekWithKey(prompt, apiKey, model)
	default:
		err = fmt.Errorf("unknown provider: %s", provider)
	}

	// Update usage stats
	pm.updateUsage(apiKey, err)

	return rec, err
}

// rotateKey moves to the next API key for a provider
func (pm *ProviderManager) rotateKey(provider ProviderType) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := range pm.config.Providers {
		if pm.config.Providers[i].Name == provider {
			numKeys := len(pm.config.Providers[i].Keys)
			if numKeys <= 1 {
				return false
			}
			pm.keyIndex[provider] = (pm.keyIndex[provider] + 1) % numKeys
			return true
		}
	}
	return false
}

// getFallback returns the fallback provider for a given provider
func (pm *ProviderManager) getFallback(provider ProviderType) ProviderType {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, p := range pm.config.Providers {
		if p.Name == provider {
			return p.Fallback
		}
	}
	return ""
}

// isKeyRateLimited checks if a key is currently rate limited
func (pm *ProviderManager) isKeyRateLimited(key string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	usage, ok := pm.keyUsage[key]
	if !ok {
		return false
	}
	return usage.RateLimited && time.Now().Before(usage.RateLimitEnd)
}

// updateUsage updates usage statistics for an API key
func (pm *ProviderManager) updateUsage(key string, err error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	usage, ok := pm.keyUsage[key]
	if !ok {
		usage = &KeyUsage{}
		pm.keyUsage[key] = usage
	}

	usage.Requests++
	usage.LastUsed = time.Now()

	if err != nil {
		usage.Errors++
		if isRateLimitError(err) {
			usage.RateLimited = true
			usage.RateLimitEnd = time.Now().Add(60 * time.Second) // 1 minute cooldown
		}
	}
}

// GetUsageStats returns usage statistics for all keys
func (pm *ProviderManager) GetUsageStats() map[string]*KeyUsage {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]*KeyUsage)
	for k, v := range pm.keyUsage {
		// Mask the key for security
		maskedKey := maskAPIKey(k)
		stats[maskedKey] = v
	}
	return stats
}

// Helper functions

func getEnvKeys(envNames ...string) []string {
	var keys []string
	seen := make(map[string]bool)

	for _, name := range envNames {
		value := os.Getenv(name)
		if value == "" {
			continue
		}

		// Support comma-separated keys
		for _, k := range strings.Split(value, ",") {
			k = strings.TrimSpace(k)
			if k != "" && !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	return keys
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "rate limit") ||
		strings.Contains(errStr, "Rate limit") ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "quota exceeded")
}

func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// Provider-specific query functions

func queryOpenAIWithKey(prompt, apiKey, model string) (*AIRecommendation, error) {
	if model == "" {
		model = "gpt-4o-mini"
	}

	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  400,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OpenAI error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Choices[0].Message.Content)
}

func queryClaudeWithKey(prompt, apiKey, model string) (*AIRecommendation, error) {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	reqBody := map[string]interface{}{
		"model":      model,
		"max_tokens": 400,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Claude error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Content[0].Text)
}

func queryGeminiWithKey(prompt, apiKey, model string) (*AIRecommendation, error) {
	if model == "" {
		model = "gemini-1.5-flash"
	}

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{"temperature": 0.3, "maxOutputTokens": 400},
	}

	body, _ := json.Marshal(reqBody)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Gemini error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Candidates[0].Content.Parts[0].Text)
}

func queryGroqWithKey(prompt, apiKey, model string) (*AIRecommendation, error) {
	if model == "" {
		model = "llama-3.3-70b-versatile"
	}

	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  400,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Groq error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Choices[0].Message.Content)
}

func queryDeepSeekWithKey(prompt, apiKey, model string) (*AIRecommendation, error) {
	if model == "" {
		model = "deepseek-chat"
	}

	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  400,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DeepSeek error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response")
	}

	return parseAIResponse(result.Choices[0].Message.Content)
}

func queryOllamaWithEndpoint(prompt, endpoint, model string) (*AIRecommendation, error) {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}

	reqBody := map[string]interface{}{
		"model":  model,
		"prompt": "You are a security expert. Respond only with valid JSON.\n\n" + prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 500,
		},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", endpoint+"/api/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second} // Longer for local inference
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Ollama connection failed: %v (is Ollama running?)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Ollama error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Response string `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Response == "" {
		return nil, fmt.Errorf("no response from Ollama")
	}

	return parseAIResponse(result.Response)
}

// Raw query functions - return string response without parsing

func queryOpenAIRaw(prompt, apiKey, model string) (string, error) {
	if model == "" {
		model = "gpt-4o-mini"
	}

	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  4096,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenAI error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response")
	}

	return result.Choices[0].Message.Content, nil
}

func queryClaudeRaw(prompt, apiKey, model string) (string, error) {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	reqBody := map[string]interface{}{
		"model":      model,
		"max_tokens": 4096,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Claude error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Content) == 0 {
		return "", fmt.Errorf("no response")
	}

	return result.Content[0].Text, nil
}

func queryGeminiRaw(prompt, apiKey, model string) (string, error) {
	if model == "" {
		model = "gemini-1.5-flash"
	}

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{"temperature": 0.3, "maxOutputTokens": 4096},
	}

	body, _ := json.Marshal(reqBody)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Gemini error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no response")
	}

	return result.Candidates[0].Content.Parts[0].Text, nil
}

func queryGroqRaw(prompt, apiKey, model string) (string, error) {
	if model == "" {
		model = "llama-3.3-70b-versatile"
	}

	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  4096,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Groq error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response")
	}

	return result.Choices[0].Message.Content, nil
}

func queryDeepSeekRaw(prompt, apiKey, model string) (string, error) {
	if model == "" {
		model = "deepseek-chat"
	}

	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  4096,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("DeepSeek error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response")
	}

	return result.Choices[0].Message.Content, nil
}

func queryOllamaRaw(prompt, endpoint, model string) (string, error) {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}

	reqBody := map[string]interface{}{
		"model":  model,
		"prompt": "You are a security expert. Respond only with valid JSON.\n\n" + prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 4096,
		},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", endpoint+"/api/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Ollama connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama error: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Response string `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Response == "" {
		return "", fmt.Errorf("no response from Ollama")
	}

	return result.Response, nil
}

// GetDefaultConfigPath returns the default path for AI config
func GetDefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".reconator", "ai-config.yaml")
}

// SaveConfig saves the current configuration to a file
func (pm *ProviderManager) SaveConfig(path string) error {
	if path == "" {
		path = GetDefaultConfigPath()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(pm.config)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// CreateDefaultConfigFile creates a template AI config file with examples
func CreateDefaultConfigFile() error {
	path := GetDefaultConfigPath()

	// Don't overwrite existing config
	if _, err := os.Stat(path); err == nil {
		return nil // Already exists
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	template := `# Reconator AI Configuration
# Add your API keys here for AI-powered features
# Multiple keys per provider are supported (for key rotation on rate limits)
# Fallback order: ollama -> openai -> claude -> gemini -> deepseek -> groq

providers:
  # Ollama (local, free, private) - FIRST CHOICE if running
  # Install: https://ollama.ai
  # No API key needed, just run: ollama serve && ollama pull llama3.2
  - name: ollama
    endpoint: http://localhost:11434
    model: llama3.2
    # model: qwen2.5:32b  # Better for complex analysis

  # OpenAI (GPT-4o-mini) - Most reliable cloud option
  # Get key at: https://platform.openai.com/api-keys
  - name: openai
    keys:
      - "sk-your-openai-key-here"
    model: gpt-4o-mini
    rpm_limit: 60

  # Anthropic Claude - Best quality for security analysis
  # Get key at: https://console.anthropic.com/
  - name: claude
    keys:
      - "sk-ant-your-claude-key-here"
    model: claude-sonnet-4-20250514
    rpm_limit: 50

  # Google Gemini
  # Get key at: https://aistudio.google.com/app/apikey
  - name: gemini
    keys:
      - "your-gemini-key-here"
    model: gemini-1.5-flash
    rpm_limit: 60

  # DeepSeek - Affordable alternative
  # Get key at: https://platform.deepseek.com/
  - name: deepseek
    keys:
      - "sk-your-deepseek-key-here"
    model: deepseek-chat
    rpm_limit: 60

  # Groq - Fast inference, generous free tier
  # Get key at: https://console.groq.com/keys
  - name: groq
    keys:
      - "gsk-your-groq-key-here"
    model: llama-3.3-70b-versatile
    rpm_limit: 30

# Alternative: Set via environment variables
# OLLAMA_HOST=http://localhost:11434
# OPENAI_API_KEY=sk-key1
# ANTHROPIC_API_KEY=sk-ant-key1
# GEMINI_API_KEY=key1
# DEEPSEEK_API_KEY=sk-key1
# GROQ_API_KEY=gsk-key1
`

	return os.WriteFile(path, []byte(template), 0600)
}

// EnsureConfigExists creates config file if it doesn't exist and prints a message
func EnsureConfigExists() {
	path := GetDefaultConfigPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := CreateDefaultConfigFile(); err == nil {
			fmt.Printf("Created AI config template: %s\n", path)
			fmt.Println("Add your API keys to enable AI-powered features")
		}
	}
}
