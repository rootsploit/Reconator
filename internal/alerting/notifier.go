package alerting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rootsploit/reconator/internal/config"
	"github.com/rootsploit/reconator/internal/exec"
	"github.com/rootsploit/reconator/internal/tools"
)

type Notifier struct {
	cfg *config.Config
	c   *tools.Checker
}

func NewNotifier(cfg *config.Config, checker *tools.Checker) *Notifier {
	return &Notifier{cfg: cfg, c: checker}
}

// Alert represents a notification to be sent
type Alert struct {
	Type        string    `json:"type"`        // subdomain, takeover, vulnerability, etc.
	Severity    string    `json:"severity"`    // info, low, medium, high, critical
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Target      string    `json:"target"`
	Tool        string    `json:"tool,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Summary represents scan results summary for notification
type Summary struct {
	Domain           string         `json:"domain"`
	TotalSubdomains  int            `json:"total_subdomains"`
	NewSubdomains    int            `json:"new_subdomains"`
	AliveHosts       int            `json:"alive_hosts"`
	TakeoverVulns    int            `json:"takeover_vulns"`
	Vulnerabilities  int            `json:"vulnerabilities"`
	CriticalFindings int            `json:"critical_findings"`
	HighFindings     int            `json:"high_findings"`
	ScanDuration     time.Duration  `json:"scan_duration"`
	Alerts           []Alert        `json:"alerts,omitempty"`
}

// NotifyConfig holds notify configuration paths
type NotifyConfig struct {
	ConfigPath   string // Path to provider-config.yaml
	ProviderPath string // Path to notify-config.yaml
}

// Notify sends alerts via ProjectDiscovery notify tool
func (n *Notifier) Notify(summary *Summary) error {
	if !n.c.IsInstalled("notify") {
		return fmt.Errorf("notify tool not installed")
	}

	// Build notification message
	message := n.buildMessage(summary)

	// Use notify to send
	return n.sendNotification(message)
}

// NotifyAlert sends a single alert immediately
func (n *Notifier) NotifyAlert(alert *Alert) error {
	if !n.c.IsInstalled("notify") {
		return fmt.Errorf("notify tool not installed")
	}

	message := n.formatAlert(alert)
	return n.sendNotification(message)
}

// NotifyBulk sends multiple alerts
func (n *Notifier) NotifyBulk(alerts []Alert) error {
	if !n.c.IsInstalled("notify") {
		return fmt.Errorf("notify tool not installed")
	}

	var messages []string
	for _, alert := range alerts {
		messages = append(messages, n.formatAlert(&alert))
	}

	return n.sendNotification(strings.Join(messages, "\n---\n"))
}

func (n *Notifier) buildMessage(summary *Summary) string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("🎯 **Reconator Scan Complete: %s**\n\n", summary.Domain))

	// Quick Stats
	sb.WriteString("📊 **Summary:**\n")
	sb.WriteString(fmt.Sprintf("• Subdomains: %d (new: %d)\n", summary.TotalSubdomains, summary.NewSubdomains))
	sb.WriteString(fmt.Sprintf("• Alive Hosts: %d\n", summary.AliveHosts))
	sb.WriteString(fmt.Sprintf("• Takeover Vulns: %d\n", summary.TakeoverVulns))
	sb.WriteString(fmt.Sprintf("• Total Vulnerabilities: %d\n", summary.Vulnerabilities))
	sb.WriteString(fmt.Sprintf("• Duration: %s\n\n", summary.ScanDuration.Round(time.Second)))

	// Critical/High findings
	if summary.CriticalFindings > 0 || summary.HighFindings > 0 {
		sb.WriteString("🚨 **Priority Findings:**\n")
		if summary.CriticalFindings > 0 {
			sb.WriteString(fmt.Sprintf("• Critical: %d\n", summary.CriticalFindings))
		}
		if summary.HighFindings > 0 {
			sb.WriteString(fmt.Sprintf("• High: %d\n", summary.HighFindings))
		}
		sb.WriteString("\n")
	}

	// Notable alerts
	if len(summary.Alerts) > 0 {
		sb.WriteString("📋 **Notable Findings:**\n")
		count := 0
		for _, alert := range summary.Alerts {
			if count >= 10 { // Limit to 10 alerts in summary
				sb.WriteString(fmt.Sprintf("... and %d more\n", len(summary.Alerts)-10))
				break
			}
			severity := n.severityEmoji(alert.Severity)
			sb.WriteString(fmt.Sprintf("%s %s: %s\n", severity, alert.Type, alert.Title))
			count++
		}
	}

	return sb.String()
}

func (n *Notifier) formatAlert(alert *Alert) string {
	emoji := n.severityEmoji(alert.Severity)
	return fmt.Sprintf("%s **[%s] %s**\n%s\nTarget: %s\nTool: %s",
		emoji,
		strings.ToUpper(alert.Severity),
		alert.Title,
		alert.Description,
		alert.Target,
		alert.Tool,
	)
}

func (n *Notifier) severityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "ℹ️"
	}
}

func (n *Notifier) sendNotification(message string) error {
	// Build notify args
	args := []string{"-silent"}

	// Check for custom config
	configPath := n.getConfigPath()
	if configPath != "" {
		args = append(args, "-pc", configPath)
	}

	// Pipe message to notify via stdin
	r := exec.RunWithInput("notify", args, message, &exec.Options{Timeout: 30 * time.Second})
	if r.Error != nil {
		return fmt.Errorf("notify failed: %v - %s", r.Error, r.Stderr)
	}

	return nil
}

func (n *Notifier) getConfigPath() string {
	// Check in order: config flag, ~/.config/notify/, ~/.reconator/
	if n.cfg.NotifyConfigPath != "" {
		if _, err := os.Stat(n.cfg.NotifyConfigPath); err == nil {
			return n.cfg.NotifyConfigPath
		}
	}

	// Check default locations
	home, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(home, ".config", "notify", "provider-config.yaml"),
		filepath.Join(home, ".reconator", "notify-config.yaml"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// CreateDefaultConfig creates a template notify config file
func CreateDefaultConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".reconator")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	configPath := filepath.Join(configDir, "notify-config.yaml")

	// Check if already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // Already exists
	}

	template := `# Reconator Notify Configuration
# Configure your notification providers below
# See: https://github.com/projectdiscovery/notify

# Slack
slack:
  - id: "slack"
    slack_channel: "recon-alerts"
    slack_username: "reconator"
    slack_format: "{{data}}"
    slack_webhook_url: "https://hooks.slack.com/services/XXX/XXX/XXX"

# Discord
discord:
  - id: "discord"
    discord_channel: "recon-alerts"
    discord_username: "reconator"
    discord_format: "{{data}}"
    discord_webhook_url: "https://discord.com/api/webhooks/XXX/XXX"

# Telegram
telegram:
  - id: "telegram"
    telegram_api_key: "XXX"
    telegram_chat_id: "XXX"
    telegram_format: "{{data}}"

# Custom webhook
custom:
  - id: "custom"
    custom_webhook_url: "https://your-webhook.com/endpoint"
    custom_method: "POST"
    custom_format: '{"text": "{{data}}"}'
    custom_headers:
      Content-Type: application/json
`

	return os.WriteFile(configPath, []byte(template), 0644)
}

// CreateSubfinderConfig creates a template subfinder provider config
func CreateSubfinderConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".config", "subfinder")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	configPath := filepath.Join(configDir, "provider-config.yaml")

	// Check if already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // Already exists
	}

	template := `# Subfinder Provider Configuration
# Add your API keys for passive subdomain enumeration
# See: https://github.com/projectdiscovery/subfinder

# Recommended free sources (no API key needed):
# alienvault, anubis, commoncrawl, crtsh, digitorus, hackertarget, rapiddns, waybackarchive

# API sources - add your keys below:
binaryedge: []
bufferover: []
c99: []
censys: []
certspotter: []
chaos: []
chinaz: []
dnsdb: []
fofa: []
fullhunt: []
github: []
hunter: []
intelx: []
netlas: []
passivetotal: []
quake: []
robtex: []
securitytrails: []
shodan: []
threatbook: []
urlscan: []
virustotal: []
whoisxmlapi: []
zoomeye: []
zoomeyeapi: []

# Example with API key:
# shodan:
#   - YOUR_SHODAN_API_KEY
#
# securitytrails:
#   - YOUR_SECURITYTRAILS_API_KEY
`

	return os.WriteFile(configPath, []byte(template), 0644)
}

// AlertFromVulnerability creates an Alert from vulnerability scan result
func AlertFromVulnerability(host, templateID, name, severity, vulnType string) Alert {
	return Alert{
		Type:        vulnType,
		Severity:    severity,
		Title:       name,
		Description: fmt.Sprintf("Template: %s", templateID),
		Target:      host,
		Tool:        "nuclei",
		Timestamp:   time.Now(),
	}
}

// AlertFromTakeover creates an Alert from takeover finding
func AlertFromTakeover(subdomain, service, severity, tool string) Alert {
	return Alert{
		Type:        "takeover",
		Severity:    severity,
		Title:       fmt.Sprintf("Subdomain Takeover: %s", service),
		Description: fmt.Sprintf("Potential takeover vulnerability on %s", service),
		Target:      subdomain,
		Tool:        tool,
		Timestamp:   time.Now(),
	}
}

// AlertFromNewSubdomain creates an Alert for newly discovered subdomain
func AlertFromNewSubdomain(subdomain string) Alert {
	return Alert{
		Type:        "subdomain",
		Severity:    "info",
		Title:       "New Subdomain Discovered",
		Description: subdomain,
		Target:      subdomain,
		Tool:        "reconator",
		Timestamp:   time.Now(),
	}
}

// WriteAlertLog writes alerts to a JSON log file
func WriteAlertLog(alerts []Alert, outputDir string) error {
	if len(alerts) == 0 {
		return nil
	}

	logPath := filepath.Join(outputDir, "alerts.json")

	// Read existing alerts if file exists
	var existingAlerts []Alert
	if data, err := os.ReadFile(logPath); err == nil {
		json.Unmarshal(data, &existingAlerts)
	}

	// Append new alerts
	allAlerts := append(existingAlerts, alerts...)

	// Write back
	data, err := json.MarshalIndent(allAlerts, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(logPath, data, 0644)
}
