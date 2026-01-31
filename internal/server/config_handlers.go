package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rootsploit/reconator/internal/apikeys"
)

// APIKeyInfo represents masked API key information for the frontend
type APIKeyInfo struct {
	Provider string `json:"provider"`
	Key      string `json:"key"` // Masked
	Enabled  bool   `json:"enabled"`
}

// ConfigResponse represents the configuration response for the frontend
type ConfigResponse struct {
	AI     AIConfigResponse   `json:"ai"`
	OSINT  OSINTConfigResponse `json:"osint"`
	Notify NotifyConfigResponse `json:"notify"`
	PDCP   string              `json:"pdcp"` // Masked
}

// AIConfigResponse represents AI configuration
type AIConfigResponse struct {
	OpenAI   []APIKeyInfo   `json:"openai"`
	Claude   []APIKeyInfo   `json:"claude"`
	Gemini   []APIKeyInfo   `json:"gemini"`
	Groq     []APIKeyInfo   `json:"groq"`
	DeepSeek []APIKeyInfo   `json:"deepseek"`
	Ollama   OllamaConfigInfo `json:"ollama"`
}

// OllamaConfigInfo represents Ollama configuration
type OllamaConfigInfo struct {
	URL     string `json:"url"`
	Model   string `json:"model"`
	Enabled bool   `json:"enabled"`
}

// OSINTConfigResponse represents OSINT configuration
type OSINTConfigResponse struct {
	SecurityTrails []APIKeyInfo `json:"securitytrails"`
	Shodan         []APIKeyInfo `json:"shodan"`
	Censys         []APIKeyInfo `json:"censys"`
	VirusTotal     []APIKeyInfo `json:"virustotal"`
	GitHub         []APIKeyInfo `json:"github"`
	Chaos          []APIKeyInfo `json:"chaos"`
	BinaryEdge     []APIKeyInfo `json:"binaryedge"`
	Hunter         []APIKeyInfo `json:"hunter"`
	IntelX         []APIKeyInfo `json:"intelx"`
	URLScan        []APIKeyInfo `json:"urlscan"`
	WhoisXMLAPI    []APIKeyInfo `json:"whoisxmlapi"`
	ZoomEye        []APIKeyInfo `json:"zoomeye"`
	Fofa           []APIKeyInfo `json:"fofa"`
	Quake          []APIKeyInfo `json:"quake"`
	Netlas         []APIKeyInfo `json:"netlas"`
	FullHunt       []APIKeyInfo `json:"fullhunt"`
	CertSpotter    []APIKeyInfo `json:"certspotter"`
	BufferOver     []APIKeyInfo `json:"bufferover"`
	C99            []APIKeyInfo `json:"c99"`
	Chinaz         []APIKeyInfo `json:"chinaz"`
	DNSDB          []APIKeyInfo `json:"dnsdb"`
	PassiveTotal   []APIKeyInfo `json:"passivetotal"`
	Robtex         []APIKeyInfo `json:"robtex"`
	ThreatBook     []APIKeyInfo `json:"threatbook"`
}

// NotifyConfigResponse represents notification configuration
type NotifyConfigResponse struct {
	Slack    []SlackInfo    `json:"slack"`
	Discord  []DiscordInfo  `json:"discord"`
	Telegram []TelegramInfo `json:"telegram"`
}

// SlackInfo represents Slack configuration
type SlackInfo struct {
	ID      string `json:"id"`
	Webhook string `json:"webhook"` // Masked
	Channel string `json:"channel"`
	Enabled bool   `json:"enabled"`
}

// DiscordInfo represents Discord configuration
type DiscordInfo struct {
	ID      string `json:"id"`
	Webhook string `json:"webhook"` // Masked
	Channel string `json:"channel"`
	Enabled bool   `json:"enabled"`
}

// TelegramInfo represents Telegram configuration
type TelegramInfo struct {
	ID      string `json:"id"`
	APIKey  string `json:"api_key"` // Masked
	ChatID  string `json:"chat_id"`
	Enabled bool   `json:"enabled"`
}

// TestKeyRequest represents a request to test an API key
type TestKeyRequest struct {
	Provider string `json:"provider" binding:"required"`
	Key      string `json:"key" binding:"required"`
}

// TestKeyResponse represents the response of testing an API key
type TestKeyResponse struct {
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
	Latency  int64  `json:"latency"` // milliseconds
	Provider string `json:"provider"`
}

// UpdateKeyRequest represents a request to update an API key
type UpdateKeyRequest struct {
	Provider string `json:"provider" binding:"required"`
	Keys     []string `json:"keys"`
}

// getConfig returns the current configuration with masked keys
func (s *Server) getConfig(c *gin.Context) {
	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration"})
		return
	}

	cfg := mgr.GetConfig()

	// Build response with masked keys
	response := ConfigResponse{
		AI: AIConfigResponse{
			OpenAI:   maskKeyList("openai", cfg.AI.OpenAI),
			Claude:   maskKeyList("claude", cfg.AI.Claude),
			Gemini:   maskKeyList("gemini", cfg.AI.Gemini),
			Groq:     maskKeyList("groq", cfg.AI.Groq),
			DeepSeek: maskKeyList("deepseek", cfg.AI.DeepSeek),
			Ollama: OllamaConfigInfo{
				URL:     cfg.AI.Ollama.URL,
				Model:   cfg.AI.Ollama.Model,
				Enabled: cfg.AI.Ollama.URL != "",
			},
		},
		OSINT: OSINTConfigResponse{
			SecurityTrails: maskKeyList("securitytrails", cfg.OSINT.SecurityTrails),
			Shodan:         maskKeyList("shodan", cfg.OSINT.Shodan),
			Censys:         maskKeyList("censys", cfg.OSINT.Censys),
			VirusTotal:     maskKeyList("virustotal", cfg.OSINT.VirusTotal),
			GitHub:         maskKeyList("github", cfg.OSINT.GitHub),
			Chaos:          maskKeyList("chaos", cfg.OSINT.Chaos),
			BinaryEdge:     maskKeyList("binaryedge", cfg.OSINT.BinaryEdge),
			Hunter:         maskKeyList("hunter", cfg.OSINT.Hunter),
			IntelX:         maskKeyList("intelx", cfg.OSINT.IntelX),
			URLScan:        maskKeyList("urlscan", cfg.OSINT.URLScan),
			WhoisXMLAPI:    maskKeyList("whoisxmlapi", cfg.OSINT.WhoisXMLAPI),
			ZoomEye:        maskKeyList("zoomeye", cfg.OSINT.ZoomEye),
			Fofa:           maskKeyList("fofa", cfg.OSINT.Fofa),
			Quake:          maskKeyList("quake", cfg.OSINT.Quake),
			Netlas:         maskKeyList("netlas", cfg.OSINT.Netlas),
			FullHunt:       maskKeyList("fullhunt", cfg.OSINT.FullHunt),
			CertSpotter:    maskKeyList("certspotter", cfg.OSINT.CertSpotter),
			BufferOver:     maskKeyList("bufferover", cfg.OSINT.BufferOver),
			C99:            maskKeyList("c99", cfg.OSINT.C99),
			Chinaz:         maskKeyList("chinaz", cfg.OSINT.Chinaz),
			DNSDB:          maskKeyList("dnsdb", cfg.OSINT.DNSDB),
			PassiveTotal:   maskKeyList("passivetotal", cfg.OSINT.PassiveTotal),
			Robtex:         maskKeyList("robtex", cfg.OSINT.Robtex),
			ThreatBook:     maskKeyList("threatbook", cfg.OSINT.ThreatBook),
		},
		PDCP: maskSingleKey(cfg.PDCPKey),
	}

	// Add Slack configurations
	for _, slack := range cfg.Notify.Slack {
		response.Notify.Slack = append(response.Notify.Slack, SlackInfo{
			ID:      slack.ID,
			Webhook: maskSingleKey(slack.WebhookURL),
			Channel: slack.Channel,
			Enabled: slack.WebhookURL != "",
		})
	}

	// Add Discord configurations
	for _, discord := range cfg.Notify.Discord {
		response.Notify.Discord = append(response.Notify.Discord, DiscordInfo{
			ID:      discord.ID,
			Webhook: maskSingleKey(discord.WebhookURL),
			Channel: discord.Channel,
			Enabled: discord.WebhookURL != "",
		})
	}

	// Add Telegram configurations
	for _, telegram := range cfg.Notify.Telegram {
		response.Notify.Telegram = append(response.Notify.Telegram, TelegramInfo{
			ID:      telegram.ID,
			APIKey:  maskSingleKey(telegram.APIKey),
			ChatID:  telegram.ChatID,
			Enabled: telegram.APIKey != "",
		})
	}

	c.JSON(http.StatusOK, response)
}

// testAPIKey tests an API key
func (s *Server) testAPIKey(c *gin.Context) {
	var req TestKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration"})
		return
	}

	provider := strings.ToLower(req.Provider)
	var result apikeys.TestResult

	// Determine if it's AI or OSINT key
	aiProviders := map[string]bool{
		"openai": true, "claude": true, "anthropic": true, "gemini": true,
		"google": true, "groq": true, "deepseek": true,
	}

	if aiProviders[provider] {
		result = mgr.TestAIKey(provider, req.Key)
	} else {
		result = mgr.TestOSINTKey(provider, req.Key)
	}

	c.JSON(http.StatusOK, TestKeyResponse{
		Valid:    result.Valid,
		Error:    result.Error,
		Latency:  result.Latency.Milliseconds(),
		Provider: result.Provider,
	})
}

// updateAPIKey updates an API key
func (s *Server) updateAPIKey(c *gin.Context) {
	var req UpdateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := apikeys.NewManager()
	if err := mgr.Load(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration"})
		return
	}

	cfg := mgr.GetConfig()
	provider := strings.ToLower(req.Provider)

	// Update the appropriate provider keys
	switch provider {
	case "openai":
		cfg.AI.OpenAI = req.Keys
	case "claude", "anthropic":
		cfg.AI.Claude = req.Keys
	case "gemini", "google":
		cfg.AI.Gemini = req.Keys
	case "groq":
		cfg.AI.Groq = req.Keys
	case "deepseek":
		cfg.AI.DeepSeek = req.Keys
	case "securitytrails":
		cfg.OSINT.SecurityTrails = req.Keys
	case "shodan":
		cfg.OSINT.Shodan = req.Keys
	case "censys":
		cfg.OSINT.Censys = req.Keys
	case "virustotal":
		cfg.OSINT.VirusTotal = req.Keys
	case "github":
		cfg.OSINT.GitHub = req.Keys
	case "chaos":
		cfg.OSINT.Chaos = req.Keys
	case "binaryedge":
		cfg.OSINT.BinaryEdge = req.Keys
	case "hunter":
		cfg.OSINT.Hunter = req.Keys
	case "intelx":
		cfg.OSINT.IntelX = req.Keys
	case "urlscan":
		cfg.OSINT.URLScan = req.Keys
	case "whoisxmlapi":
		cfg.OSINT.WhoisXMLAPI = req.Keys
	case "zoomeye":
		cfg.OSINT.ZoomEye = req.Keys
	case "fofa":
		cfg.OSINT.Fofa = req.Keys
	case "quake":
		cfg.OSINT.Quake = req.Keys
	case "netlas":
		cfg.OSINT.Netlas = req.Keys
	case "fullhunt":
		cfg.OSINT.FullHunt = req.Keys
	case "certspotter":
		cfg.OSINT.CertSpotter = req.Keys
	case "bufferover":
		cfg.OSINT.BufferOver = req.Keys
	case "c99":
		cfg.OSINT.C99 = req.Keys
	case "chinaz":
		cfg.OSINT.Chinaz = req.Keys
	case "dnsdb":
		cfg.OSINT.DNSDB = req.Keys
	case "passivetotal":
		cfg.OSINT.PassiveTotal = req.Keys
	case "robtex":
		cfg.OSINT.Robtex = req.Keys
	case "threatbook":
		cfg.OSINT.ThreatBook = req.Keys
	case "slack_webhook":
		// Update Slack webhook URL
		if len(req.Keys) > 0 {
			if len(cfg.Notify.Slack) == 0 {
				cfg.Notify.Slack = []apikeys.SlackConfig{{ID: "slack"}}
			}
			cfg.Notify.Slack[0].WebhookURL = req.Keys[0]
		}
	case "discord_webhook":
		// Update Discord webhook URL
		if len(req.Keys) > 0 {
			if len(cfg.Notify.Discord) == 0 {
				cfg.Notify.Discord = []apikeys.DiscordConfig{{ID: "discord"}}
			}
			cfg.Notify.Discord[0].WebhookURL = req.Keys[0]
		}
	case "telegram_api_key":
		// Update Telegram API key
		if len(req.Keys) > 0 {
			if len(cfg.Notify.Telegram) == 0 {
				cfg.Notify.Telegram = []apikeys.TelegramConfig{{ID: "telegram"}}
			}
			cfg.Notify.Telegram[0].APIKey = req.Keys[0]
		}
	case "telegram_chat_id":
		// Update Telegram Chat ID
		if len(req.Keys) > 0 {
			if len(cfg.Notify.Telegram) == 0 {
				cfg.Notify.Telegram = []apikeys.TelegramConfig{{ID: "telegram"}}
			}
			cfg.Notify.Telegram[0].ChatID = req.Keys[0]
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown provider"})
		return
	}

	// Save the configuration
	if err := mgr.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key updated successfully"})
}

// syncConfig syncs configuration from environment variables and config files
func (s *Server) syncConfig(c *gin.Context) {
	mgr := apikeys.NewManager()

	// Load will read from file and override with environment variables
	if err := mgr.Load(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sync configuration"})
		return
	}

	// Save the loaded configuration
	if err := mgr.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save synced configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration synced successfully"})
}

// Helper functions

// maskKeyList masks a list of API keys
func maskKeyList(provider string, keys []string) []APIKeyInfo {
	var result []APIKeyInfo
	for _, key := range keys {
		result = append(result, APIKeyInfo{
			Provider: provider,
			Key:      maskSingleKey(key),
			Enabled:  key != "",
		})
	}
	return result
}

// maskSingleKey masks a single API key
func maskSingleKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}
