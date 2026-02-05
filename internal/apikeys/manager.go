// Package apikeys provides unified API key management for reconator.
// All API keys (AI providers, OSINT, notifications) are stored in one config file.
// On install, existing keys from subfinder/notify/ai-config are imported.
package apikeys

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the unified configuration with ALL keys in one file
type Config struct {
	// AI provider API keys
	AI AIKeys `yaml:"ai"`

	// OSINT API keys for subdomain enumeration (subfinder)
	OSINT OSINTKeys `yaml:"osint"`

	// Notification provider configuration
	Notify NotifyConfig `yaml:"notify"`

	// ProjectDiscovery Cloud API key (for chaos, cvemap, nuclei cloud)
	PDCPKey string `yaml:"pdcp_api_key,omitempty"`
}

// AIKeys holds API keys for AI providers
type AIKeys struct {
	// OpenAI
	OpenAI []string `yaml:"openai,omitempty"`
	// Anthropic (Claude)
	Claude []string `yaml:"claude,omitempty"`
	// Google Gemini
	Gemini []string `yaml:"gemini,omitempty"`
	// Groq
	Groq []string `yaml:"groq,omitempty"`
	// DeepSeek
	DeepSeek []string `yaml:"deepseek,omitempty"`
	// Ollama (local)
	Ollama OllamaConfig `yaml:"ollama,omitempty"`
}

// OllamaConfig holds Ollama configuration
type OllamaConfig struct {
	URL   string `yaml:"url,omitempty"`
	Model string `yaml:"model,omitempty"`
}

// OSINTKeys holds API keys for OSINT sources (subfinder providers)
type OSINTKeys struct {
	SecurityTrails []string `yaml:"securitytrails,omitempty"`
	Shodan         []string `yaml:"shodan,omitempty"`
	Censys         []string `yaml:"censys,omitempty"` // Format: "api_id:api_secret"
	VirusTotal     []string `yaml:"virustotal,omitempty"`
	GitHub         []string `yaml:"github,omitempty"`
	Chaos          []string `yaml:"chaos,omitempty"`
	BinaryEdge     []string `yaml:"binaryedge,omitempty"`
	Hunter         []string `yaml:"hunter,omitempty"`
	IntelX         []string `yaml:"intelx,omitempty"`
	URLScan        []string `yaml:"urlscan,omitempty"`
	WhoisXMLAPI    []string `yaml:"whoisxmlapi,omitempty"`
	ZoomEye        []string `yaml:"zoomeye,omitempty"`
	Fofa           []string `yaml:"fofa,omitempty"`
	Quake          []string `yaml:"quake,omitempty"`
	Netlas         []string `yaml:"netlas,omitempty"`
	FullHunt       []string `yaml:"fullhunt,omitempty"`
	CertSpotter    []string `yaml:"certspotter,omitempty"`
	BufferOver     []string `yaml:"bufferover,omitempty"`
	C99            []string `yaml:"c99,omitempty"`
	Chinaz         []string `yaml:"chinaz,omitempty"`
	DNSDB          []string `yaml:"dnsdb,omitempty"`
	PassiveTotal   []string `yaml:"passivetotal,omitempty"`
	Robtex         []string `yaml:"robtex,omitempty"`
	ThreatBook     []string `yaml:"threatbook,omitempty"`
}

// NotifyConfig holds notification provider configuration
type NotifyConfig struct {
	Slack    []SlackConfig    `yaml:"slack,omitempty"`
	Discord  []DiscordConfig  `yaml:"discord,omitempty"`
	Telegram []TelegramConfig `yaml:"telegram,omitempty"`
	Custom   []CustomConfig   `yaml:"custom,omitempty"`
}

// SlackConfig represents Slack webhook configuration
type SlackConfig struct {
	ID         string `yaml:"id"`
	WebhookURL string `yaml:"slack_webhook_url"`
	Channel    string `yaml:"slack_channel,omitempty"`
	Username   string `yaml:"slack_username,omitempty"`
	Format     string `yaml:"slack_format,omitempty"`
}

// DiscordConfig represents Discord webhook configuration
type DiscordConfig struct {
	ID         string `yaml:"id"`
	WebhookURL string `yaml:"discord_webhook_url"`
	Channel    string `yaml:"discord_channel,omitempty"`
	Username   string `yaml:"discord_username,omitempty"`
	Format     string `yaml:"discord_format,omitempty"`
}

// TelegramConfig represents Telegram bot configuration
type TelegramConfig struct {
	ID     string `yaml:"id"`
	APIKey string `yaml:"telegram_api_key"`
	ChatID string `yaml:"telegram_chat_id"`
	Format string `yaml:"telegram_format,omitempty"`
}

// CustomConfig represents custom webhook configuration
type CustomConfig struct {
	ID         string            `yaml:"id"`
	WebhookURL string            `yaml:"custom_webhook_url"`
	Method     string            `yaml:"custom_method,omitempty"`
	Format     string            `yaml:"custom_format,omitempty"`
	Headers    map[string]string `yaml:"custom_headers,omitempty"`
}

// Manager handles API key operations
type Manager struct {
	config     *Config
	configPath string
}

// NewManager creates a new API key manager
func NewManager() *Manager {
	return &Manager{
		config:     &Config{},
		configPath: GetDefaultConfigPath(),
	}
}

// GetDefaultConfigPath returns the unified config file path
func GetDefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reconator", "config.yaml")
}

// GetSubfinderConfigPath returns the subfinder config path
func GetSubfinderConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "subfinder", "provider-config.yaml")
}

// GetNotifyConfigPath returns the notify config path
func GetNotifyConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "notify", "provider-config.yaml")
}

// GetAIConfigPath returns the old AI config path (for import)
func GetAIConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reconator", "ai-config.yaml")
}

// Load loads API keys from config file and environment variables
func (m *Manager) Load() error {
	// Load from config file first
	if err := m.loadFromFile(); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	// Override with environment variables
	m.loadFromEnv()

	return nil
}

// loadFromFile loads config from YAML file
func (m *Manager) loadFromFile() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, m.config)
}

// loadFromEnv loads/overrides keys from environment variables
func (m *Manager) loadFromEnv() {
	// AI keys
	aiEnvMappings := map[string]*[]string{
		"OPENAI_API_KEY":    &m.config.AI.OpenAI,
		"ANTHROPIC_API_KEY": &m.config.AI.Claude,
		"CLAUDE_API_KEY":    &m.config.AI.Claude,
		"GEMINI_API_KEY":    &m.config.AI.Gemini,
		"GOOGLE_AI_KEY":     &m.config.AI.Gemini,
		"GROQ_API_KEY":      &m.config.AI.Groq,
		"DEEPSEEK_API_KEY":  &m.config.AI.DeepSeek,
	}

	for envVar, target := range aiEnvMappings {
		if key := os.Getenv(envVar); key != "" {
			if !containsKey(*target, key) {
				*target = append(*target, key)
			}
		}
	}

	// Ollama
	if url := os.Getenv("OLLAMA_HOST"); url != "" {
		m.config.AI.Ollama.URL = url
	}
	if url := os.Getenv("OLLAMA_URL"); url != "" {
		m.config.AI.Ollama.URL = url
	}
	if model := os.Getenv("OLLAMA_MODEL"); model != "" {
		m.config.AI.Ollama.Model = model
	}

	// PDCP key
	if key := os.Getenv("PDCP_API_KEY"); key != "" {
		m.config.PDCPKey = key
	}

	// OSINT keys
	osintEnvMappings := map[string]*[]string{
		"SHODAN_API_KEY":         &m.config.OSINT.Shodan,
		"SECURITYTRAILS_API_KEY": &m.config.OSINT.SecurityTrails,
		"VIRUSTOTAL_API_KEY":     &m.config.OSINT.VirusTotal,
		"CENSYS_API_KEY":         &m.config.OSINT.Censys,
		"GITHUB_TOKEN":           &m.config.OSINT.GitHub,
		"CHAOS_API_KEY":          &m.config.OSINT.Chaos,
		"BINARYEDGE_API_KEY":     &m.config.OSINT.BinaryEdge,
		"HUNTER_API_KEY":         &m.config.OSINT.Hunter,
		"INTELX_API_KEY":         &m.config.OSINT.IntelX,
		"URLSCAN_API_KEY":        &m.config.OSINT.URLScan,
	}

	for envVar, target := range osintEnvMappings {
		if key := os.Getenv(envVar); key != "" {
			if !containsKey(*target, key) {
				*target = append(*target, key)
			}
		}
	}
}

// Save saves the current config to file
func (m *Manager) Save() error {
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(m.config)
	if err != nil {
		return err
	}

	header := `# Reconator Unified Configuration
# All API keys in one place - run 'reconator config sync' to update tool configs
# Run 'reconator config test' to validate keys

`
	return os.WriteFile(m.configPath, []byte(header+string(data)), 0600)
}

// ImportFromExisting imports keys from existing tool config files
// Called during 'reconator install' to consolidate keys
func (m *Manager) ImportFromExisting() (imported int) {
	// Import from subfinder config
	imported += m.importFromSubfinder()

	// Import from notify config
	imported += m.importFromNotify()

	// Import from old AI config
	imported += m.importFromAIConfig()

	// Import from environment variables
	m.loadFromEnv()

	return imported
}

// importFromSubfinder imports keys from ~/.config/subfinder/provider-config.yaml
func (m *Manager) importFromSubfinder() int {
	path := GetSubfinderConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	var subfinderConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &subfinderConfig); err != nil {
		return 0
	}

	imported := 0
	providerMappings := map[string]*[]string{
		"securitytrails": &m.config.OSINT.SecurityTrails,
		"shodan":         &m.config.OSINT.Shodan,
		"censys":         &m.config.OSINT.Censys,
		"virustotal":     &m.config.OSINT.VirusTotal,
		"github":         &m.config.OSINT.GitHub,
		"chaos":          &m.config.OSINT.Chaos,
		"binaryedge":     &m.config.OSINT.BinaryEdge,
		"hunter":         &m.config.OSINT.Hunter,
		"intelx":         &m.config.OSINT.IntelX,
		"urlscan":        &m.config.OSINT.URLScan,
		"whoisxmlapi":    &m.config.OSINT.WhoisXMLAPI,
		"zoomeye":        &m.config.OSINT.ZoomEye,
		"fofa":           &m.config.OSINT.Fofa,
		"quake":          &m.config.OSINT.Quake,
		"netlas":         &m.config.OSINT.Netlas,
		"fullhunt":       &m.config.OSINT.FullHunt,
		"certspotter":    &m.config.OSINT.CertSpotter,
		"bufferover":     &m.config.OSINT.BufferOver,
		"c99":            &m.config.OSINT.C99,
		"chinaz":         &m.config.OSINT.Chinaz,
		"dnsdb":          &m.config.OSINT.DNSDB,
		"passivetotal":   &m.config.OSINT.PassiveTotal,
		"robtex":         &m.config.OSINT.Robtex,
		"threatbook":     &m.config.OSINT.ThreatBook,
	}

	for provider, target := range providerMappings {
		if keys, ok := subfinderConfig[provider]; ok {
			if keyList, ok := keys.([]interface{}); ok {
				for _, k := range keyList {
					if str, ok := k.(string); ok && str != "" && !isPlaceholder(str) {
						if !containsKey(*target, str) {
							*target = append(*target, str)
							imported++
						}
					}
				}
			}
		}
	}

	return imported
}

// importFromNotify imports config from ~/.config/notify/provider-config.yaml
func (m *Manager) importFromNotify() int {
	path := GetNotifyConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	var notifyConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &notifyConfig); err != nil {
		return 0
	}

	imported := 0

	// Import Slack
	if slack, ok := notifyConfig["slack"].([]interface{}); ok {
		for _, item := range slack {
			if cfg, ok := item.(map[string]interface{}); ok {
				id, _ := cfg["id"].(string)
				webhookURL, _ := cfg["slack_webhook_url"].(string)
				if webhookURL != "" && !isPlaceholder(webhookURL) {
					// Check if already exists
					exists := false
					for _, existing := range m.config.Notify.Slack {
						if existing.ID == id || existing.WebhookURL == webhookURL {
							exists = true
							break
						}
					}
					if !exists {
						channel, _ := cfg["slack_channel"].(string)
						username, _ := cfg["slack_username"].(string)
						format, _ := cfg["slack_format"].(string)
						m.config.Notify.Slack = append(m.config.Notify.Slack, SlackConfig{
							ID:         id,
							WebhookURL: webhookURL,
							Channel:    channel,
							Username:   username,
							Format:     format,
						})
						imported++
					}
				}
			}
		}
	}

	// Import Discord
	if discord, ok := notifyConfig["discord"].([]interface{}); ok {
		for _, item := range discord {
			if cfg, ok := item.(map[string]interface{}); ok {
				id, _ := cfg["id"].(string)
				webhookURL, _ := cfg["discord_webhook_url"].(string)
				if webhookURL != "" && !isPlaceholder(webhookURL) {
					exists := false
					for _, existing := range m.config.Notify.Discord {
						if existing.ID == id || existing.WebhookURL == webhookURL {
							exists = true
							break
						}
					}
					if !exists {
						channel, _ := cfg["discord_channel"].(string)
						username, _ := cfg["discord_username"].(string)
						format, _ := cfg["discord_format"].(string)
						m.config.Notify.Discord = append(m.config.Notify.Discord, DiscordConfig{
							ID:         id,
							WebhookURL: webhookURL,
							Channel:    channel,
							Username:   username,
							Format:     format,
						})
						imported++
					}
				}
			}
		}
	}

	// Import Telegram
	if telegram, ok := notifyConfig["telegram"].([]interface{}); ok {
		for _, item := range telegram {
			if cfg, ok := item.(map[string]interface{}); ok {
				id, _ := cfg["id"].(string)
				apiKey, _ := cfg["telegram_api_key"].(string)
				chatID, _ := cfg["telegram_chat_id"].(string)
				if apiKey != "" && !isPlaceholder(apiKey) {
					exists := false
					for _, existing := range m.config.Notify.Telegram {
						if existing.ID == id || existing.APIKey == apiKey {
							exists = true
							break
						}
					}
					if !exists {
						format, _ := cfg["telegram_format"].(string)
						m.config.Notify.Telegram = append(m.config.Notify.Telegram, TelegramConfig{
							ID:     id,
							APIKey: apiKey,
							ChatID: chatID,
							Format: format,
						})
						imported++
					}
				}
			}
		}
	}

	return imported
}

// importFromAIConfig imports keys from ~/.reconator/ai-config.yaml
func (m *Manager) importFromAIConfig() int {
	path := GetAIConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	var aiConfig struct {
		Providers []struct {
			Name     string   `yaml:"name"`
			Keys     []string `yaml:"keys"`
			Endpoint string   `yaml:"endpoint"`
			Model    string   `yaml:"model"`
		} `yaml:"providers"`
	}

	if err := yaml.Unmarshal(data, &aiConfig); err != nil {
		return 0
	}

	imported := 0
	for _, provider := range aiConfig.Providers {
		var target *[]string
		switch strings.ToLower(provider.Name) {
		case "openai":
			target = &m.config.AI.OpenAI
		case "claude", "anthropic":
			target = &m.config.AI.Claude
		case "gemini", "google":
			target = &m.config.AI.Gemini
		case "groq":
			target = &m.config.AI.Groq
		case "deepseek":
			target = &m.config.AI.DeepSeek
		case "ollama":
			if provider.Endpoint != "" {
				m.config.AI.Ollama.URL = provider.Endpoint
			}
			if provider.Model != "" {
				m.config.AI.Ollama.Model = provider.Model
			}
			continue
		default:
			continue
		}

		for _, key := range provider.Keys {
			if key != "" && !isPlaceholder(key) {
				if !containsKey(*target, key) {
					*target = append(*target, key)
					imported++
				}
			}
		}
	}

	return imported
}

// GetConfig returns the current config
func (m *Manager) GetConfig() *Config {
	return m.config
}

// HasAIKeys returns true if any AI keys are configured
func (m *Manager) HasAIKeys() bool {
	a := m.config.AI
	return len(a.OpenAI) > 0 || len(a.Claude) > 0 || len(a.Gemini) > 0 ||
		len(a.Groq) > 0 || len(a.DeepSeek) > 0 || a.Ollama.URL != ""
}

// HasOSINTKeys returns true if any OSINT keys are configured
func (m *Manager) HasOSINTKeys() bool {
	o := m.config.OSINT
	return len(o.SecurityTrails) > 0 || len(o.Shodan) > 0 || len(o.Censys) > 0 ||
		len(o.VirusTotal) > 0 || len(o.GitHub) > 0 || len(o.Chaos) > 0 ||
		len(o.BinaryEdge) > 0 || len(o.Hunter) > 0 || len(o.IntelX) > 0 ||
		len(o.URLScan) > 0 || len(o.WhoisXMLAPI) > 0 || len(o.ZoomEye) > 0
}

// HasNotifyConfig returns true if notification config is present
func (m *Manager) HasNotifyConfig() bool {
	n := m.config.Notify
	return len(n.Slack) > 0 || len(n.Discord) > 0 || len(n.Telegram) > 0 || len(n.Custom) > 0
}

// GetKeyCount returns total number of configured keys
func (m *Manager) GetKeyCount() int {
	count := 0

	// AI keys
	a := m.config.AI
	count += len(a.OpenAI) + len(a.Claude) + len(a.Gemini) + len(a.Groq) + len(a.DeepSeek)
	if a.Ollama.URL != "" {
		count++
	}

	// OSINT keys
	o := m.config.OSINT
	count += len(o.SecurityTrails) + len(o.Shodan) + len(o.Censys) + len(o.VirusTotal)
	count += len(o.GitHub) + len(o.Chaos) + len(o.BinaryEdge) + len(o.Hunter)
	count += len(o.IntelX) + len(o.URLScan) + len(o.WhoisXMLAPI) + len(o.ZoomEye)
	count += len(o.Fofa) + len(o.Quake) + len(o.Netlas) + len(o.FullHunt)
	count += len(o.CertSpotter) + len(o.BufferOver) + len(o.C99) + len(o.Chinaz)
	count += len(o.DNSDB) + len(o.PassiveTotal) + len(o.Robtex) + len(o.ThreatBook)

	// PDCP
	if m.config.PDCPKey != "" {
		count++
	}

	// Notify
	n := m.config.Notify
	count += len(n.Slack) + len(n.Discord) + len(n.Telegram) + len(n.Custom)

	return count
}

// containsKey checks if a key exists in slice
func containsKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// TestResult represents the result of testing an API key
type TestResult struct {
	Provider string
	Key      string
	Valid    bool
	Error    string
	Latency  time.Duration
}

// TestOSINTKey tests a specific OSINT provider key
func (m *Manager) TestOSINTKey(provider string, key string) TestResult {
	result := TestResult{
		Provider: provider,
		Key:      maskKey(key),
	}

	start := time.Now()
	var testURL string
	var headers map[string]string

	switch strings.ToLower(provider) {
	case "shodan":
		testURL = fmt.Sprintf("https://api.shodan.io/api-info?key=%s", key)
	case "securitytrails":
		testURL = "https://api.securitytrails.com/v1/ping"
		headers = map[string]string{"APIKEY": key}
	case "virustotal":
		testURL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
		headers = map[string]string{"x-apikey": key}
	case "censys":
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			result.Error = "invalid format, expected api_id:api_secret"
			return result
		}
		testURL = "https://search.censys.io/api/v2/hosts/search?per_page=1&q=*"
	case "github":
		testURL = "https://api.github.com/user"
		headers = map[string]string{"Authorization": "token " + key}
	case "hunter":
		testURL = fmt.Sprintf("https://api.hunter.io/v2/account?api_key=%s", key)
	case "urlscan":
		testURL = "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1"
		headers = map[string]string{"API-Key": key}
	case "binaryedge":
		testURL = "https://api.binaryedge.io/v2/user/subscription"
		headers = map[string]string{"X-Key": key}
	case "intelx":
		testURL = "https://2.intelx.io/authenticate/info"
		headers = map[string]string{"x-key": key}
	case "chaos":
		testURL = "https://dns.projectdiscovery.io/dns/example.com/subdomains"
		headers = map[string]string{"Authorization": key}
	case "whoisxmlapi":
		testURL = fmt.Sprintf("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=%s&domainName=example.com&outputFormat=JSON", key)
	case "zoomeye":
		testURL = "https://api.zoomeye.org/resources-info"
		headers = map[string]string{"API-KEY": key}
	case "fofa":
		// Fofa uses email:key format
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			result.Error = "invalid format, expected email:key"
			return result
		}
		testURL = fmt.Sprintf("https://fofa.info/api/v1/info/my?email=%s&key=%s", parts[0], parts[1])
	case "quake":
		testURL = "https://quake.360.cn/api/v3/user/info"
		headers = map[string]string{"X-QuakeToken": key}
	case "netlas":
		testURL = "https://app.netlas.io/api/users/current/"
		headers = map[string]string{"X-API-Key": key}
	case "fullhunt":
		testURL = "https://fullhunt.io/api/v1/auth/status"
		headers = map[string]string{"X-API-KEY": key}
	case "certspotter":
		testURL = "https://api.certspotter.com/v1/issuances?domain=example.com"
		headers = map[string]string{"Authorization": "Bearer " + key}
	case "bufferover":
		testURL = fmt.Sprintf("https://tls.bufferover.run/dns?q=example.com&apikey=%s", key)
	case "c99":
		testURL = fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=example.com&json", key)
	case "passivetotal":
		// PassiveTotal uses username:key format
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			result.Error = "invalid format, expected username:api_key"
			return result
		}
		testURL = "https://api.passivetotal.org/v2/account"
	default:
		result.Error = "testing not implemented"
		return result
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Handle special auth formats
	switch provider {
	case "censys", "passivetotal":
		parts := strings.SplitN(key, ":", 2)
		req.SetBasicAuth(parts[0], parts[1])
	}

	resp, err := client.Do(req)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		result.Valid = true
	} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
		result.Error = "invalid or expired key"
	} else if resp.StatusCode == 429 {
		result.Valid = true
		result.Error = "rate limited (key is valid)"
	} else {
		result.Error = fmt.Sprintf("status: %d", resp.StatusCode)
	}

	return result
}

// TestAIKey tests an AI provider key
func (m *Manager) TestAIKey(provider string, key string) TestResult {
	result := TestResult{
		Provider: provider,
		Key:      maskKey(key),
	}

	start := time.Now()
	var testURL string
	var headers map[string]string

	switch strings.ToLower(provider) {
	case "openai":
		testURL = "https://api.openai.com/v1/models"
		headers = map[string]string{"Authorization": "Bearer " + key}
	case "claude", "anthropic":
		testURL = "https://api.anthropic.com/v1/messages"
		headers = map[string]string{
			"x-api-key":         key,
			"anthropic-version": "2023-06-01",
		}
		// Claude requires a POST, just check auth with minimal request
	case "groq":
		testURL = "https://api.groq.com/openai/v1/models"
		headers = map[string]string{"Authorization": "Bearer " + key}
	case "deepseek":
		testURL = "https://api.deepseek.com/v1/models"
		headers = map[string]string{"Authorization": "Bearer " + key}
	case "gemini", "google":
		testURL = fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models?key=%s", key)
	default:
		result.Error = "testing not implemented"
		return result
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		result.Valid = true
	} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
		result.Error = "invalid or expired key"
	} else if resp.StatusCode == 429 {
		result.Valid = true
		result.Error = "rate limited (key is valid)"
	} else if resp.StatusCode == 405 {
		// Method not allowed but auth passed (e.g., Claude)
		result.Valid = true
	} else {
		result.Error = fmt.Sprintf("status: %d", resp.StatusCode)
	}

	return result
}

// TestAllKeys tests all configured API keys
func (m *Manager) TestAllKeys() []TestResult {
	var results []TestResult

	// Test AI keys
	aiKeys := map[string][]string{
		"openai":   m.config.AI.OpenAI,
		"claude":   m.config.AI.Claude,
		"gemini":   m.config.AI.Gemini,
		"groq":     m.config.AI.Groq,
		"deepseek": m.config.AI.DeepSeek,
	}

	for provider, keys := range aiKeys {
		for _, key := range keys {
			if key != "" && !isPlaceholder(key) {
				results = append(results, m.TestAIKey(provider, key))
			}
		}
	}

	// Test Ollama
	if m.config.AI.Ollama.URL != "" {
		result := TestResult{
			Provider: "ollama",
			Key:      m.config.AI.Ollama.URL,
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(m.config.AI.Ollama.URL + "/api/tags")
		if err != nil {
			result.Error = "not reachable"
		} else {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				result.Valid = true
			} else {
				result.Error = fmt.Sprintf("status: %d", resp.StatusCode)
			}
		}
		results = append(results, result)
	}

	// Test OSINT keys
	osintKeys := map[string][]string{
		"securitytrails": m.config.OSINT.SecurityTrails,
		"shodan":         m.config.OSINT.Shodan,
		"censys":         m.config.OSINT.Censys,
		"virustotal":     m.config.OSINT.VirusTotal,
		"github":         m.config.OSINT.GitHub,
		"hunter":         m.config.OSINT.Hunter,
		"urlscan":        m.config.OSINT.URLScan,
	}

	for provider, keys := range osintKeys {
		for _, key := range keys {
			if key != "" && !isPlaceholder(key) {
				results = append(results, m.TestOSINTKey(provider, key))
			}
		}
	}

	// Test PDCP key
	if m.config.PDCPKey != "" && !isPlaceholder(m.config.PDCPKey) {
		result := TestResult{
			Provider: "pdcp",
			Key:      maskKey(m.config.PDCPKey),
			Valid:    true,
			Error:    "configured (full test requires cvemap)",
		}
		results = append(results, result)
	}

	// Mark notify as configured
	for _, slack := range m.config.Notify.Slack {
		if slack.WebhookURL != "" && !isPlaceholder(slack.WebhookURL) {
			results = append(results, TestResult{
				Provider: "slack:" + slack.ID,
				Key:      "webhook",
				Valid:    true,
				Error:    "configured",
			})
		}
	}

	for _, discord := range m.config.Notify.Discord {
		if discord.WebhookURL != "" && !isPlaceholder(discord.WebhookURL) {
			results = append(results, TestResult{
				Provider: "discord:" + discord.ID,
				Key:      "webhook",
				Valid:    true,
				Error:    "configured",
			})
		}
	}

	return results
}

// maskKey masks a key for display
func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// isPlaceholder checks if a key is a placeholder value
func isPlaceholder(key string) bool {
	key = strings.ToLower(key)
	placeholders := []string{
		"your_", "xxx", "your-", "api_key", "api-key",
		"replace", "changeme", "todo", "fixme", "your ",
	}
	for _, p := range placeholders {
		if strings.Contains(key, p) {
			return true
		}
	}
	return false
}

// CreateDefaultConfig creates a template config file
func CreateDefaultConfig() error {
	configPath := GetDefaultConfigPath()

	// Check if already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	template := `# Reconator Unified Configuration
# All API keys in one place - single source of truth
# Run 'reconator config sync' to update tool configs (subfinder, notify)
# Run 'reconator config test' to validate keys

# ============================================================================
# AI PROVIDER KEYS
# ============================================================================
ai:
  # OpenAI - https://platform.openai.com/api-keys
  openai: []

  # Claude (Anthropic) - https://console.anthropic.com
  claude: []

  # Gemini (Google) - https://aistudio.google.com/apikey
  gemini: []

  # Groq - https://console.groq.com/keys (fast, free tier)
  groq: []

  # DeepSeek - https://platform.deepseek.com/api_keys
  deepseek: []

  # Ollama (local AI) - https://ollama.com
  ollama:
    url: ""      # e.g., http://localhost:11434
    model: ""    # e.g., llama3.2, qwen2.5:32b

# ============================================================================
# PROJECTDISCOVERY CLOUD
# ============================================================================
# PDCP key - https://cloud.projectdiscovery.io (for chaos, cvemap, nuclei cloud)
pdcp_api_key: ""

# ============================================================================
# OSINT / SUBFINDER API KEYS
# ============================================================================
# These keys are synced to ~/.config/subfinder/provider-config.yaml
osint:
  # SecurityTrails - https://securitytrails.com/app/signup (50 queries/month free)
  securitytrails: []

  # Shodan - https://account.shodan.io
  shodan: []

  # Censys - https://censys.io/register (250 queries/month free)
  # Format: ["api_id:api_secret"]
  censys: []

  # VirusTotal - https://virustotal.com (500 queries/day free)
  virustotal: []

  # GitHub - Settings > Developer > Personal Access Tokens
  github: []

  # Chaos - ProjectDiscovery Cloud (free with signup)
  chaos: []

  # BinaryEdge - https://binaryedge.io
  binaryedge: []

  # Hunter - https://hunter.io
  hunter: []

  # IntelX - https://intelx.io
  intelx: []

  # URLScan - https://urlscan.io
  urlscan: []

# ============================================================================
# NOTIFICATION PROVIDERS
# ============================================================================
# These are synced to ~/.config/notify/provider-config.yaml
notify:
  # Slack - https://api.slack.com/apps > Create App > Incoming Webhooks
  slack: []
  # Example:
  #  - id: "recon-alerts"
  #    slack_webhook_url: "https://hooks.slack.com/services/XXX/XXX/XXX"
  #    slack_channel: "recon-alerts"
  #    slack_username: "reconator"

  # Discord - Server Settings > Integrations > Webhooks
  discord: []
  # Example:
  #  - id: "recon-alerts"
  #    discord_webhook_url: "https://discord.com/api/webhooks/XXX/XXX"

  # Telegram - @BotFather > /newbot
  telegram: []
  # Example:
  #  - id: "recon-alerts"
  #    telegram_api_key: "BOT_TOKEN"
  #    telegram_chat_id: "CHAT_ID"
`

	return os.WriteFile(configPath, []byte(template), 0600)
}

// CreateAndImport creates config file and imports existing keys
// Called during 'reconator install'
func CreateAndImport() (created bool, imported int, err error) {
	configPath := GetDefaultConfigPath()

	// Check if already exists
	if _, err := os.Stat(configPath); err == nil {
		// Already exists, just import new keys
		mgr := NewManager()
		if err := mgr.Load(); err != nil {
			return false, 0, err
		}
		imported := mgr.ImportFromExisting()
		if imported > 0 {
			mgr.Save()
		}
		return false, imported, nil
	}

	// Create new config
	if err := CreateDefaultConfig(); err != nil {
		return false, 0, err
	}

	// Import existing keys
	mgr := NewManager()
	mgr.Load() // Load the template
	imported = mgr.ImportFromExisting()
	if imported > 0 || mgr.GetKeyCount() > 0 {
		mgr.Save()
	}

	return true, imported, nil
}

// EnsureConfigExists creates config file if it doesn't exist
func EnsureConfigExists() {
	CreateDefaultConfig()
}
