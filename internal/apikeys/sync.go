package apikeys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SyncResult represents the result of a sync operation
type SyncResult struct {
	Tool       string
	ConfigPath string
	KeysAdded  int
	KeysKept   int
	Success    bool
	Error      string
}

// Sync syncs API keys to all supported tool configurations
func (m *Manager) Sync() []SyncResult {
	var results []SyncResult

	// Sync to subfinder
	results = append(results, m.SyncSubfinder())

	// Sync to notify
	results = append(results, m.SyncNotify())

	return results
}

// SyncSubfinder syncs OSINT keys to subfinder's provider-config.yaml
// Uses merge approach: only updates keys that are configured in reconator,
// preserves any additional keys/settings user may have added manually
func (m *Manager) SyncSubfinder() SyncResult {
	result := SyncResult{
		Tool:       "subfinder",
		ConfigPath: GetSubfinderConfigPath(),
	}

	// Ensure directory exists
	dir := filepath.Dir(result.ConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		result.Error = err.Error()
		return result
	}

	// Load existing config if present
	existingConfig := make(map[string]interface{})
	if data, err := os.ReadFile(result.ConfigPath); err == nil {
		yaml.Unmarshal(data, &existingConfig)
	}

	// Count existing keys
	for _, v := range existingConfig {
		if keys, ok := v.([]interface{}); ok {
			result.KeysKept += len(keys)
		}
	}

	// Merge reconator keys into existing config
	keysAdded := 0

	osintMappings := map[string][]string{
		"securitytrails": m.config.OSINT.SecurityTrails,
		"shodan":         m.config.OSINT.Shodan,
		"censys":         m.config.OSINT.Censys,
		"virustotal":     m.config.OSINT.VirusTotal,
		"github":         m.config.OSINT.GitHub,
		"chaos":          m.config.OSINT.Chaos,
		"binaryedge":     m.config.OSINT.BinaryEdge,
		"hunter":         m.config.OSINT.Hunter,
		"intelx":         m.config.OSINT.IntelX,
		"urlscan":        m.config.OSINT.URLScan,
		"whoisxmlapi":    m.config.OSINT.WhoisXMLAPI,
		"zoomeye":        m.config.OSINT.ZoomEye,
		"fofa":           m.config.OSINT.Fofa,
		"quake":          m.config.OSINT.Quake,
		"netlas":         m.config.OSINT.Netlas,
		"fullhunt":       m.config.OSINT.FullHunt,
		"certspotter":    m.config.OSINT.CertSpotter,
		"bufferover":     m.config.OSINT.BufferOver,
		"c99":            m.config.OSINT.C99,
		"chinaz":         m.config.OSINT.Chinaz,
		"dnsdb":          m.config.OSINT.DNSDB,
		"passivetotal":   m.config.OSINT.PassiveTotal,
		"robtex":         m.config.OSINT.Robtex,
		"threatbook":     m.config.OSINT.ThreatBook,
	}

	for provider, keys := range osintMappings {
		if len(keys) == 0 {
			continue
		}

		// Filter out placeholders
		validKeys := []string{}
		for _, key := range keys {
			if key != "" && !isPlaceholder(key) {
				validKeys = append(validKeys, key)
			}
		}

		if len(validKeys) == 0 {
			continue
		}

		// Get existing keys for this provider
		existingKeys := []string{}
		if existing, ok := existingConfig[provider]; ok {
			if keyList, ok := existing.([]interface{}); ok {
				for _, k := range keyList {
					if str, ok := k.(string); ok && str != "" && !isPlaceholder(str) {
						existingKeys = append(existingKeys, str)
					}
				}
			}
		}

		// Merge: add new keys not already present
		merged := make([]string, len(existingKeys))
		copy(merged, existingKeys)
		for _, newKey := range validKeys {
			found := false
			for _, existingKey := range merged {
				if existingKey == newKey {
					found = true
					break
				}
			}
			if !found {
				merged = append(merged, newKey)
				keysAdded++
			}
		}

		existingConfig[provider] = merged
	}

	// Write merged config
	data, err := yaml.Marshal(existingConfig)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Add header comment
	header := `# Subfinder Provider Configuration
# Managed by reconator - edit ~/.reconator/config.yaml and run 'reconator config sync'
# See: https://github.com/projectdiscovery/subfinder

`
	finalData := header + string(data)

	if err := os.WriteFile(result.ConfigPath, []byte(finalData), 0600); err != nil {
		result.Error = err.Error()
		return result
	}

	result.KeysAdded = keysAdded
	result.Success = true
	return result
}

// SyncNotify syncs notification config to notify's provider-config.yaml
func (m *Manager) SyncNotify() SyncResult {
	result := SyncResult{
		Tool:       "notify",
		ConfigPath: GetNotifyConfigPath(),
	}

	// Check if there's anything to sync
	if !m.HasNotifyConfig() {
		result.Success = true
		result.Error = "no notification providers configured"
		return result
	}

	// Ensure directory exists
	dir := filepath.Dir(result.ConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		result.Error = err.Error()
		return result
	}

	// Load existing config if present
	existingConfig := make(map[string]interface{})
	if data, err := os.ReadFile(result.ConfigPath); err == nil {
		yaml.Unmarshal(data, &existingConfig)
	}

	keysAdded := 0

	// Sync Slack webhooks
	if len(m.config.Notify.Slack) > 0 {
		slackConfigs := []map[string]interface{}{}

		// Get existing slack configs
		if existing, ok := existingConfig["slack"].([]interface{}); ok {
			for _, item := range existing {
				if cfg, ok := item.(map[string]interface{}); ok {
					slackConfigs = append(slackConfigs, cfg)
				}
			}
		}

		// Add new configs
		for _, slack := range m.config.Notify.Slack {
			if slack.WebhookURL == "" || isPlaceholder(slack.WebhookURL) {
				continue
			}

			// Check if this ID already exists
			found := false
			for _, existing := range slackConfigs {
				if existing["id"] == slack.ID {
					found = true
					// Update existing
					existing["slack_webhook_url"] = slack.WebhookURL
					if slack.Channel != "" {
						existing["slack_channel"] = slack.Channel
					}
					if slack.Username != "" {
						existing["slack_username"] = slack.Username
					}
					if slack.Format != "" {
						existing["slack_format"] = slack.Format
					}
					break
				}
			}

			if !found {
				newConfig := map[string]interface{}{
					"id":                slack.ID,
					"slack_webhook_url": slack.WebhookURL,
				}
				if slack.Channel != "" {
					newConfig["slack_channel"] = slack.Channel
				}
				if slack.Username != "" {
					newConfig["slack_username"] = slack.Username
				}
				if slack.Format != "" {
					newConfig["slack_format"] = slack.Format
				} else {
					newConfig["slack_format"] = "{{data}}"
				}
				slackConfigs = append(slackConfigs, newConfig)
				keysAdded++
			}
		}

		if len(slackConfigs) > 0 {
			existingConfig["slack"] = slackConfigs
		}
	}

	// Sync Discord webhooks
	if len(m.config.Notify.Discord) > 0 {
		discordConfigs := []map[string]interface{}{}

		if existing, ok := existingConfig["discord"].([]interface{}); ok {
			for _, item := range existing {
				if cfg, ok := item.(map[string]interface{}); ok {
					discordConfigs = append(discordConfigs, cfg)
				}
			}
		}

		for _, discord := range m.config.Notify.Discord {
			if discord.WebhookURL == "" || isPlaceholder(discord.WebhookURL) {
				continue
			}

			found := false
			for _, existing := range discordConfigs {
				if existing["id"] == discord.ID {
					found = true
					existing["discord_webhook_url"] = discord.WebhookURL
					if discord.Channel != "" {
						existing["discord_channel"] = discord.Channel
					}
					if discord.Username != "" {
						existing["discord_username"] = discord.Username
					}
					if discord.Format != "" {
						existing["discord_format"] = discord.Format
					}
					break
				}
			}

			if !found {
				newConfig := map[string]interface{}{
					"id":                  discord.ID,
					"discord_webhook_url": discord.WebhookURL,
				}
				if discord.Channel != "" {
					newConfig["discord_channel"] = discord.Channel
				}
				if discord.Username != "" {
					newConfig["discord_username"] = discord.Username
				}
				if discord.Format != "" {
					newConfig["discord_format"] = discord.Format
				} else {
					newConfig["discord_format"] = "{{data}}"
				}
				discordConfigs = append(discordConfigs, newConfig)
				keysAdded++
			}
		}

		if len(discordConfigs) > 0 {
			existingConfig["discord"] = discordConfigs
		}
	}

	// Sync Telegram bots
	if len(m.config.Notify.Telegram) > 0 {
		telegramConfigs := []map[string]interface{}{}

		if existing, ok := existingConfig["telegram"].([]interface{}); ok {
			for _, item := range existing {
				if cfg, ok := item.(map[string]interface{}); ok {
					telegramConfigs = append(telegramConfigs, cfg)
				}
			}
		}

		for _, tg := range m.config.Notify.Telegram {
			if tg.APIKey == "" || isPlaceholder(tg.APIKey) {
				continue
			}

			found := false
			for _, existing := range telegramConfigs {
				if existing["id"] == tg.ID {
					found = true
					existing["telegram_api_key"] = tg.APIKey
					existing["telegram_chat_id"] = tg.ChatID
					if tg.Format != "" {
						existing["telegram_format"] = tg.Format
					}
					break
				}
			}

			if !found {
				newConfig := map[string]interface{}{
					"id":               tg.ID,
					"telegram_api_key": tg.APIKey,
					"telegram_chat_id": tg.ChatID,
				}
				if tg.Format != "" {
					newConfig["telegram_format"] = tg.Format
				} else {
					newConfig["telegram_format"] = "{{data}}"
				}
				telegramConfigs = append(telegramConfigs, newConfig)
				keysAdded++
			}
		}

		if len(telegramConfigs) > 0 {
			existingConfig["telegram"] = telegramConfigs
		}
	}

	// Sync Custom webhooks
	if len(m.config.Notify.Custom) > 0 {
		customConfigs := []map[string]interface{}{}

		if existing, ok := existingConfig["custom"].([]interface{}); ok {
			for _, item := range existing {
				if cfg, ok := item.(map[string]interface{}); ok {
					customConfigs = append(customConfigs, cfg)
				}
			}
		}

		for _, custom := range m.config.Notify.Custom {
			if custom.WebhookURL == "" || isPlaceholder(custom.WebhookURL) {
				continue
			}

			found := false
			for _, existing := range customConfigs {
				if existing["id"] == custom.ID {
					found = true
					existing["custom_webhook_url"] = custom.WebhookURL
					if custom.Method != "" {
						existing["custom_method"] = custom.Method
					}
					if custom.Format != "" {
						existing["custom_format"] = custom.Format
					}
					if len(custom.Headers) > 0 {
						existing["custom_headers"] = custom.Headers
					}
					break
				}
			}

			if !found {
				newConfig := map[string]interface{}{
					"id":                 custom.ID,
					"custom_webhook_url": custom.WebhookURL,
				}
				if custom.Method != "" {
					newConfig["custom_method"] = custom.Method
				} else {
					newConfig["custom_method"] = "POST"
				}
				if custom.Format != "" {
					newConfig["custom_format"] = custom.Format
				}
				if len(custom.Headers) > 0 {
					newConfig["custom_headers"] = custom.Headers
				}
				customConfigs = append(customConfigs, newConfig)
				keysAdded++
			}
		}

		if len(customConfigs) > 0 {
			existingConfig["custom"] = customConfigs
		}
	}

	// Write merged config
	data, err := yaml.Marshal(existingConfig)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Add header comment
	header := `# Notify Provider Configuration
# Managed by reconator - edit ~/.reconator/config.yaml and run 'reconator config sync'
# See: https://github.com/projectdiscovery/notify

`
	finalData := header + string(data)

	if err := os.WriteFile(result.ConfigPath, []byte(finalData), 0600); err != nil {
		result.Error = err.Error()
		return result
	}

	result.KeysAdded = keysAdded
	result.Success = true
	return result
}

// ShowConfig returns a string representation of the current config
func (m *Manager) ShowConfig() string {
	var sb strings.Builder

	sb.WriteString("Reconator Unified Configuration\n")
	sb.WriteString("===============================\n\n")

	sb.WriteString(fmt.Sprintf("Config file: %s\n\n", m.configPath))

	// AI Keys
	sb.WriteString("AI Provider Keys:\n")
	aiMappings := map[string][]string{
		"OpenAI":   m.config.AI.OpenAI,
		"Claude":   m.config.AI.Claude,
		"Gemini":   m.config.AI.Gemini,
		"Groq":     m.config.AI.Groq,
		"DeepSeek": m.config.AI.DeepSeek,
	}

	hasAI := false
	for provider, keys := range aiMappings {
		validKeys := []string{}
		for _, k := range keys {
			if k != "" && !isPlaceholder(k) {
				validKeys = append(validKeys, maskKey(k))
			}
		}
		if len(validKeys) > 0 {
			hasAI = true
			sb.WriteString(fmt.Sprintf("  %-10s: %d key(s) [%s]\n", provider, len(validKeys), strings.Join(validKeys, ", ")))
		}
	}
	if m.config.AI.Ollama.URL != "" {
		hasAI = true
		sb.WriteString(fmt.Sprintf("  %-10s: %s", "Ollama", m.config.AI.Ollama.URL))
		if m.config.AI.Ollama.Model != "" {
			sb.WriteString(fmt.Sprintf(" (model: %s)", m.config.AI.Ollama.Model))
		}
		sb.WriteString("\n")
	}
	if !hasAI {
		sb.WriteString("  (none configured)\n")
	}

	// PDCP Key
	sb.WriteString("\nProjectDiscovery Cloud:\n")
	if m.config.PDCPKey != "" && !isPlaceholder(m.config.PDCPKey) {
		sb.WriteString(fmt.Sprintf("  PDCP Key: %s\n", maskKey(m.config.PDCPKey)))
	} else {
		sb.WriteString("  (not configured)\n")
	}

	// OSINT Keys
	sb.WriteString("\nOSINT / Subfinder Keys:\n")
	osintMappings := map[string][]string{
		"SecurityTrails": m.config.OSINT.SecurityTrails,
		"Shodan":         m.config.OSINT.Shodan,
		"Censys":         m.config.OSINT.Censys,
		"VirusTotal":     m.config.OSINT.VirusTotal,
		"GitHub":         m.config.OSINT.GitHub,
		"Chaos":          m.config.OSINT.Chaos,
		"BinaryEdge":     m.config.OSINT.BinaryEdge,
		"Hunter":         m.config.OSINT.Hunter,
		"IntelX":         m.config.OSINT.IntelX,
		"URLScan":        m.config.OSINT.URLScan,
		"WhoisXMLAPI":    m.config.OSINT.WhoisXMLAPI,
		"ZoomEye":        m.config.OSINT.ZoomEye,
	}

	hasOSINT := false
	for provider, keys := range osintMappings {
		validKeys := []string{}
		for _, k := range keys {
			if k != "" && !isPlaceholder(k) {
				validKeys = append(validKeys, maskKey(k))
			}
		}
		if len(validKeys) > 0 {
			hasOSINT = true
			sb.WriteString(fmt.Sprintf("  %-15s: %d key(s) [%s]\n", provider, len(validKeys), strings.Join(validKeys, ", ")))
		}
	}
	if !hasOSINT {
		sb.WriteString("  (none configured)\n")
	}

	// Notify Config
	sb.WriteString("\nNotification Providers:\n")
	hasNotify := false
	for _, s := range m.config.Notify.Slack {
		if s.WebhookURL != "" && !isPlaceholder(s.WebhookURL) {
			hasNotify = true
			sb.WriteString(fmt.Sprintf("  Slack: %s\n", s.ID))
		}
	}
	for _, d := range m.config.Notify.Discord {
		if d.WebhookURL != "" && !isPlaceholder(d.WebhookURL) {
			hasNotify = true
			sb.WriteString(fmt.Sprintf("  Discord: %s\n", d.ID))
		}
	}
	for _, t := range m.config.Notify.Telegram {
		if t.APIKey != "" && !isPlaceholder(t.APIKey) {
			hasNotify = true
			sb.WriteString(fmt.Sprintf("  Telegram: %s\n", t.ID))
		}
	}
	for _, c := range m.config.Notify.Custom {
		if c.WebhookURL != "" && !isPlaceholder(c.WebhookURL) {
			hasNotify = true
			sb.WriteString(fmt.Sprintf("  Custom: %s\n", c.ID))
		}
	}
	if !hasNotify {
		sb.WriteString("  (none configured)\n")
	}

	// Sync targets
	sb.WriteString("\nSync Targets:\n")
	sb.WriteString(fmt.Sprintf("  Subfinder: %s\n", GetSubfinderConfigPath()))
	sb.WriteString(fmt.Sprintf("  Notify:    %s\n", GetNotifyConfigPath()))

	return sb.String()
}
