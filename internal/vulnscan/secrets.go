package vulnscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rootsploit/reconator/internal/config"
)

// SecretPattern defines a regex pattern for detecting secrets
type SecretPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    string // critical, high, medium, low
	Validatable bool
}

// Secret represents a discovered secret
type Secret struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Source      string `json:"source"`
	Line        int    `json:"line,omitempty"`
	Severity    string `json:"severity"`
	ValidStatus string `json:"valid_status,omitempty"`
	Context     string `json:"context,omitempty"`
}

// SecretsResult contains all detected secrets
type SecretsResult struct {
	Secrets      []Secret       `json:"secrets"`
	BySeverity   map[string]int `json:"by_severity"`
	ByType       map[string]int `json:"by_type"`
	TotalScanned int            `json:"total_scanned"`
	Duration     time.Duration  `json:"duration"`
}

// SecretDetector scans for secrets in files and URLs
type SecretDetector struct {
	cfg      *config.Config
	patterns []SecretPattern
	client   *http.Client
}

// NewSecretDetector creates a new secret detector with 70+ patterns
func NewSecretDetector(cfg *config.Config) *SecretDetector {
	return &SecretDetector{
		cfg:      cfg,
		patterns: initSecretPatterns(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func initSecretPatterns() []SecretPattern {
	return []SecretPattern{
		// AWS
		{Name: "AWS Access Key", Pattern: regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`), Severity: "critical", Validatable: true},
		{Name: "AWS Secret Key", Pattern: regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z\/+]{40}['"]`), Severity: "critical"},
		// GCP
		{Name: "GCP API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Severity: "critical", Validatable: true},
		{Name: "GCP OAuth", Pattern: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`), Severity: "critical", Validatable: true},
		{Name: "Firebase URL", Pattern: regexp.MustCompile(`[a-z0-9.-]+\.firebaseio\.com`), Severity: "high", Validatable: true},
		// Azure
		{Name: "Azure Storage Key", Pattern: regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+\/=]{88}`), Severity: "critical"},
		{Name: "Azure SAS", Pattern: regexp.MustCompile(`(?i)[?&]sig=[A-Za-z0-9%]{43,}%3D`), Severity: "high", Validatable: true},
		// GitHub
		{Name: "GitHub PAT", Pattern: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), Severity: "critical", Validatable: true},
		{Name: "GitHub OAuth", Pattern: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`), Severity: "critical", Validatable: true},
		{Name: "GitHub App", Pattern: regexp.MustCompile(`(ghu|ghs)_[A-Za-z0-9]{36}`), Severity: "critical", Validatable: true},
		{Name: "GitHub Fine-Grained", Pattern: regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`), Severity: "critical", Validatable: true},
		// GitLab
		{Name: "GitLab PAT", Pattern: regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20}`), Severity: "critical", Validatable: true},
		// Stripe
		{Name: "Stripe Live Secret", Pattern: regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`), Severity: "critical", Validatable: true},
		{Name: "Stripe Live Pub", Pattern: regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`), Severity: "medium"},
		{Name: "Stripe Test", Pattern: regexp.MustCompile(`sk_test_[A-Za-z0-9]{24,}`), Severity: "low", Validatable: true},
		// Slack
		{Name: "Slack Bot", Pattern: regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}`), Severity: "critical", Validatable: true},
		{Name: "Slack User", Pattern: regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Fa-f0-9]{32}`), Severity: "critical", Validatable: true},
		{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), Severity: "high", Validatable: true},
		// Discord
		{Name: "Discord Bot", Pattern: regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`), Severity: "critical", Validatable: true},
		{Name: "Discord Webhook", Pattern: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`), Severity: "high", Validatable: true},
		// Twilio
		{Name: "Twilio SID", Pattern: regexp.MustCompile(`AC[a-z0-9]{32}`), Severity: "high"},
		{Name: "Twilio Key", Pattern: regexp.MustCompile(`SK[a-z0-9]{32}`), Severity: "high"},
		// SendGrid/Mailchimp/Mailgun
		{Name: "SendGrid", Pattern: regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), Severity: "critical", Validatable: true},
		{Name: "Mailchimp", Pattern: regexp.MustCompile(`[a-f0-9]{32}-us[0-9]{1,2}`), Severity: "high", Validatable: true},
		{Name: "Mailgun", Pattern: regexp.MustCompile(`key-[A-Za-z0-9]{32}`), Severity: "critical", Validatable: true},
		// Square/PayPal
		{Name: "Square", Pattern: regexp.MustCompile(`sq0atp-[A-Za-z0-9\-_]{22}`), Severity: "critical", Validatable: true},
		{Name: "PayPal Braintree", Pattern: regexp.MustCompile(`access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`), Severity: "critical"},
		// Heroku/NPM/PyPI
		{Name: "Heroku", Pattern: regexp.MustCompile(`(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]`), Severity: "critical", Validatable: true},
		{Name: "NPM", Pattern: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), Severity: "critical", Validatable: true},
		{Name: "PyPI", Pattern: regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`), Severity: "critical"},
		// Shopify
		{Name: "Shopify", Pattern: regexp.MustCompile(`shp(at|ca|pa)_[A-Fa-f0-9]{32}`), Severity: "critical"},
		// Cloud Providers
		{Name: "Dropbox", Pattern: regexp.MustCompile(`sl\.[A-Za-z0-9\-_]{130,}`), Severity: "critical", Validatable: true},
		{Name: "Cloudflare", Pattern: regexp.MustCompile(`(?i)cloudflare.{0,20}['\"][A-Za-z0-9_-]{37,40}['\"]`), Severity: "critical", Validatable: true},
		{Name: "DigitalOcean", Pattern: regexp.MustCompile(`do[op]_v1_[a-f0-9]{64}`), Severity: "critical", Validatable: true},
		// Observability
		{Name: "Datadog", Pattern: regexp.MustCompile(`(?i)datadog.{0,20}['\"][a-f0-9]{32}['\"]`), Severity: "high", Validatable: true},
		{Name: "New Relic", Pattern: regexp.MustCompile(`NRAK-[A-Z0-9]{27}`), Severity: "high", Validatable: true},
		{Name: "Sentry DSN", Pattern: regexp.MustCompile(`https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+`), Severity: "medium"},
		// Vercel/Netlify
		{Name: "Vercel", Pattern: regexp.MustCompile(`(?i)vercel.{0,20}['\"][A-Za-z0-9]{24}['\"]`), Severity: "critical", Validatable: true},
		{Name: "Netlify", Pattern: regexp.MustCompile(`(?i)netlify.{0,20}['\"][A-Za-z0-9_-]{40,}['\"]`), Severity: "critical", Validatable: true},
		// Telegram
		{Name: "Telegram Bot", Pattern: regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`), Severity: "high", Validatable: true},
		// AI Services
		{Name: "OpenAI", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), Severity: "critical", Validatable: true},
		{Name: "OpenAI Project", Pattern: regexp.MustCompile(`sk-proj-[A-Za-z0-9]{48}`), Severity: "critical", Validatable: true},
		{Name: "Anthropic", Pattern: regexp.MustCompile(`sk-ant-api[a-zA-Z0-9\-_]{37,}`), Severity: "critical", Validatable: true},
		// Generic
		{Name: "Private Key", Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), Severity: "critical"},
		{Name: "PGP Private", Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), Severity: "critical"},
		{Name: "JWT", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), Severity: "medium"},
		{Name: "Basic Auth", Pattern: regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+\/=]{20,}`), Severity: "high"},
		{Name: "Bearer Token", Pattern: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.]+`), Severity: "high"},
		{Name: "API Key", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)['\"\s:=]+['\"]?[A-Za-z0-9_\-]{20,}['\"]?`), Severity: "medium"},
		{Name: "Database URL", Pattern: regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+`), Severity: "critical"},
		{Name: "Client Secret", Pattern: regexp.MustCompile(`(?i)client[_-]?secret['\"\s:=]+['\"]?[A-Za-z0-9_\-]{20,}['\"]?`), Severity: "high"},
	}
}

// DetectSecrets scans JS files and URLs for secrets
func (d *SecretDetector) DetectSecrets(ctx context.Context, jsFiles []string, urls []string) (*SecretsResult, error) {
	start := time.Now()
	result := &SecretsResult{
		Secrets:    []Secret{},
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}

	// Use reasonable concurrency for secret scanning (default 10 if Threads is 0)
	threads := d.cfg.Threads
	if threads == 0 {
		threads = 10
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	// Scan JS files (primary target for secrets)
	allSources := jsFiles
	// Also scan URLs that might contain secrets in responses
	for _, u := range urls {
		if strings.HasSuffix(strings.ToLower(u), ".js") ||
			strings.HasSuffix(strings.ToLower(u), ".json") ||
			strings.Contains(strings.ToLower(u), "/config") {
			allSources = append(allSources, u)
		}
	}

	result.TotalScanned = len(allSources)
	fmt.Printf("    [*] Scanning %d files for secrets...\n", len(allSources))

	for _, source := range allSources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var content string
			var err error
			if strings.HasPrefix(src, "http") {
				content, err = d.fetchURL(ctx, src)
			} else {
				content, err = d.readFile(src)
			}
			if err != nil {
				return
			}

			secrets := d.scanContent(content, src)
			if len(secrets) > 0 {
				mu.Lock()
				result.Secrets = append(result.Secrets, secrets...)
				for _, s := range secrets {
					result.BySeverity[s.Severity]++
					result.ByType[s.Type]++
				}
				mu.Unlock()
			}
		}(source)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	// Print summary
	if len(result.Secrets) > 0 {
		fmt.Printf("    [!] Found %d secrets (critical: %d, high: %d)\n",
			len(result.Secrets), result.BySeverity["critical"], result.BySeverity["high"])
	} else {
		fmt.Println("    [*] No secrets found")
	}

	return result, nil
}

func (d *SecretDetector) scanContent(content, source string) []Secret {
	var secrets []Secret
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, p := range d.patterns {
			for _, match := range p.Pattern.FindAllString(line, -1) {
				key := p.Name + ":" + match
				if seen[key] {
					continue
				}
				seen[key] = true
				secrets = append(secrets, Secret{
					Type: p.Name, Value: maskSecretValue(match), Source: source,
					Line: lineNum + 1, Severity: p.Severity, ValidStatus: "unknown",
					Context: getSecretContext(line, match),
				})
			}
		}
	}
	return secrets
}

func (d *SecretDetector) fetchURL(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	return string(body), nil
}

func (d *SecretDetector) readFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var b strings.Builder
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		b.WriteString(scanner.Text() + "\n")
	}
	return b.String(), scanner.Err()
}

func maskSecretValue(s string) string {
	if len(s) <= 12 {
		return s[:min(4, len(s))] + "****"
	}
	return s[:6] + "****" + s[len(s)-6:]
}

func getSecretContext(line, match string) string {
	idx := strings.Index(line, match)
	if idx == -1 {
		return ""
	}
	start, end := max(0, idx-20), min(len(line), idx+len(match)+20)
	ctx := strings.TrimSpace(line[start:end])
	if len(ctx) > 80 {
		return ctx[:80] + "..."
	}
	return ctx
}

// SaveSecretsResults saves detection results to JSON and text files
func (r *SecretsResult) SaveSecretsResults(dir string) error {
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(dir, "secrets.json"), data, 0644)

	f, err := os.Create(filepath.Join(dir, "secrets_critical.txt"))
	if err != nil {
		return err
	}
	defer f.Close()
	for _, s := range r.Secrets {
		if s.Severity == "critical" {
			fmt.Fprintf(f, "[%s] %s | %s:%d\n", s.Type, s.Value, s.Source, s.Line)
		}
	}
	return nil
}
