package attackpath

import (
	"strings"

	"github.com/rootsploit/reconator/internal/vulnscan"
)

// PatternRule defines a chaining pattern between vulnerability categories
type PatternRule struct {
	ID          string
	Name        string
	Description string
	Weight      float64
	MitreIDs    []string
	Mitigations []string
	Condition   func(src, dst vulnscan.Vulnerability) bool
}

// DefaultRules returns the attack path pattern rules (expanded from 12 to 25+)
func DefaultRules() []PatternRule {
	return []PatternRule{
		{
			ID:          "ssrf-cloud-metadata",
			Name:        "SSRF to Cloud Metadata Theft",
			Description: "Server-Side Request Forgery used to access cloud metadata endpoints and steal IAM credentials",
			Weight:      0.9,
			MitreIDs:    []string{"T1190", "T1552"},
			Mitigations: []string{"Block requests to metadata endpoints (169.254.169.254)", "Use IMDSv2 on AWS", "Implement egress filtering", "Use VPC service controls"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "ssrf") && containsAny(dst, "cloud", "metadata", "aws", "gcp", "s3", "bucket")
			},
		},
		{
			ID:          "sqli-data-exfil",
			Name:        "SQL Injection to Data Exfiltration",
			Description: "SQL injection exploited to extract sensitive data from backend databases",
			Weight:      0.95,
			MitreIDs:    []string{"T1190", "T1041"},
			Mitigations: []string{"Use parameterized queries", "Implement WAF rules for SQLi", "Apply least privilege to database accounts", "Encrypt sensitive data at rest"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "sqli", "sql injection") && containsAny(dst, "data", "exposure", "disclosure", "database")
			},
		},
		{
			ID:          "default-creds-admin-rce",
			Name:        "Default Credentials to Admin RCE",
			Description: "Default credentials on exposed admin panels leading to remote code execution",
			Weight:      0.85,
			MitreIDs:    []string{"T1078", "T1059"},
			Mitigations: []string{"Change all default credentials", "Implement MFA for admin access", "Restrict admin panels to internal networks", "Use credential rotation"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "default", "credential") && containsAny(dst, "admin", "panel", "rce", "command", "console")
			},
		},
		{
			// Fix 8: Removed broad severity match - XSS should only chain to session/auth vulns
			ID:          "xss-session-takeover",
			Name:        "XSS to Session Hijacking",
			Description: "Cross-site scripting chained to steal session tokens and take over accounts",
			Weight:      0.7,
			MitreIDs:    []string{"T1189", "T1539"},
			Mitigations: []string{"Implement Content Security Policy", "Use HttpOnly and Secure cookie flags", "Sanitize all user input", "Implement session binding"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "xss", "cross-site") && containsAny(dst, "session", "cookie", "token", "auth")
			},
		},
		{
			// Fix 6: Removed "key" and "exposure" from dst patterns (too broad)
			ID:          "lfi-source-creds",
			Name:        "LFI to Credential Extraction",
			Description: "Local file inclusion used to read source code and extract hardcoded credentials",
			Weight:      0.8,
			MitreIDs:    []string{"T1005", "T1552"},
			Mitigations: []string{"Validate and sanitize file paths", "Use allowlists for file inclusion", "Remove credentials from source code", "Use secret management solutions"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "lfi", "local file", "path traversal", "directory traversal") && containsAny(dst, "credential", "secret", "config", "env", "password")
			},
		},
		{
			ID:          "lfi-rce",
			Name:        "LFI to RCE via Config/Scripts",
			Description: "LFI used to read config files or scripts, then use credentials to achieve RCE",
			Weight:      0.95,
			MitreIDs:    []string{"T1190", "T1059"},
			Mitigations: []string{"Validate file paths", "Disable allow_url_fopen", "Use WAF", "Regular security audits"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "lfi", "local file", "path traversal", "directory traversal") && containsAny(dst, "rce", "command", "exec", "shell")
			},
		},
		{
			ID:          "lfi-passwd",
			Name:        "LFI to /etc/passwd Disclosure",
			Description: "LFI used to read /etc/passwd revealing valid system users for further attacks",
			Weight:      0.7,
			MitreIDs:    []string{"T1005", "T1087"},
			Mitigations: []string{"Validate and sanitize file paths", "Use allowlists", "Disable dangerous PHP functions"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "lfi", "path traversal", "directory traversal") && containsAny(dst, "passwd", "shadow", "credential")
			},
		},
		{
			ID:          "subdomain-takeover-phishing",
			Name:        "Subdomain Takeover to Phishing",
			Description: "Unclaimed subdomains taken over to host convincing phishing pages for credential harvesting",
			Weight:      0.6,
			MitreIDs:    []string{"T1584", "T1566"},
			Mitigations: []string{"Monitor DNS records for dangling CNAMEs", "Remove unused DNS entries", "Implement DMARC/DKIM/SPF", "Train users on phishing awareness"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "takeover", "cname")
			},
		},
		{
			ID:          "open-redirect-oauth-theft",
			Name:        "Open Redirect to OAuth Token Theft",
			Description: "Open redirect vulnerabilities abused to steal OAuth tokens during authorization flow",
			Weight:      0.65,
			MitreIDs:    []string{"T1528", "T1550"},
			Mitigations: []string{"Validate redirect URLs against allowlist", "Use strict redirect_uri matching", "Implement PKCE for OAuth flows", "Use state parameter validation"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "redirect", "open redirect") && containsAny(dst, "oauth", "token", "auth", "sso", "login")
			},
		},
		{
			ID:          "idor-pii-takeover",
			Name:        "IDOR to PII Exposure and Account Takeover",
			Description: "Insecure direct object references exploited to access PII and escalate to account takeover",
			Weight:      0.75,
			MitreIDs:    []string{"T1087", "T1078"},
			Mitigations: []string{"Implement proper access controls", "Use indirect object references", "Validate authorization on every request", "Add rate limiting"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "idor", "insecure direct", "broken access", "authorization") && containsAny(dst, "user", "account", "profile", "personal", "data")
			},
		},
		{
			ID:          "exposed-api-data-access",
			Name:        "Exposed API to Unauthorized Data Access",
			Description: "Unauthenticated or misconfigured API endpoints leading to unauthorized data access",
			Weight:      0.7,
			MitreIDs:    []string{"T1190", "T1530"},
			Mitigations: []string{"Implement API authentication", "Use API gateway with rate limiting", "Apply input validation", "Implement proper CORS policies"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "api", "graphql", "rest", "swagger", "openapi") && containsAny(dst, "data", "exposure", "disclosure", "unauthorized", "bypass")
			},
		},
		{
			// Fix 7: Removed "version" from src patterns (matches every outdated-software vuln)
			ID:          "misconfig-info-targeted",
			Name:        "Misconfiguration to Information Leak to Targeted Attack",
			Description: "Server misconfiguration leaks internal details enabling targeted exploitation",
			Weight:      0.5,
			MitreIDs:    []string{"T1592", "T1190"},
			Mitigations: []string{"Disable debug mode in production", "Remove verbose error messages", "Implement proper error handling", "Hide server version headers"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "misconfig", "debug", "verbose", "stack trace", "error") && (dst.Severity == "high" || dst.Severity == "critical")
			},
		},
		{
			ID:          "waf-bypass-exploit",
			Name:        "WAF Bypass to Exploit Delivery",
			Description: "WAF bypass techniques enabling delivery of blocked exploits",
			Weight:      0.55,
			MitreIDs:    []string{"T1562", "T1190"},
			Mitigations: []string{"Update WAF rules regularly", "Implement defense-in-depth", "Use application-level validation", "Monitor WAF bypass attempts"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "waf", "bypass", "filter evasion") && containsAny(dst, "rce", "sqli", "xss", "injection", "command")
			},
		},
		{
			ID:          "dns-zone-lateral",
			Name:        "DNS Zone Transfer to Lateral Movement",
			Description: "DNS zone transfer reveals internal network topology enabling lateral movement",
			Weight:      0.6,
			MitreIDs:    []string{"T1590", "T1018"},
			Mitigations: []string{"Disable zone transfers to unauthorized servers", "Use split-horizon DNS", "Implement DNS security extensions (DNSSEC)", "Monitor DNS query patterns"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "zone transfer", "axfr")
			},
		},
		// Additional rules for common attack chains
		{
			ID:          "xss-auth-bypass",
			Name:        "XSS to Authentication Bypass",
			Description: "Cross-site scripting exploited to bypass authentication mechanisms",
			Weight:      0.75,
			MitreIDs:    []string{"T1189", "T1078"},
			Mitigations: []string{"Implement CSP", "Use HttpOnly cookies", "Validate input", "Implement MFA"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "xss", "cross-site") && containsAny(dst, "auth", "bypass", "login", "authentication")
			},
		},
		{
			ID:          "xss-csrf-token-theft",
			Name:        "XSS to CSRF Token Theft",
			Description: "XSS used to steal CSRF tokens and perform actions on behalf of users",
			Weight:      0.7,
			MitreIDs:    []string{"T1189", "T1555"},
			Mitigations: []string{"Implement CSP", "Use double-submit cookies", "Implement SameSite cookies"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "xss", "cross-site") && containsAny(dst, "csrf", "token", "action")
			},
		},
		{
			ID:          "sql-injection-rce",
			Name:        "SQL Injection to Remote Code Execution",
			Description: "SQL injection escalated to OS command execution via database features",
			Weight:      0.95,
			MitreIDs:    []string{"T1190", "T1059"},
			Mitigations: []string{"Use parameterized queries", "Disable dangerous DB features", "Apply least privilege", "Web application firewall"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "sqli", "sql injection", "blind sql") && containsAny(dst, "rce", "command", "exec", "shell")
			},
		},
		{
			ID:          "ssrf-internal-recon",
			Name:        "SSRF to Internal Reconnaissance",
			Description: "SSRF used to scan internal networks and discover services",
			Weight:      0.8,
			MitreIDs:    []string{"T1190", "T1018"},
			Mitigations: []string{"Validate all URLs server-side", "Block private IP ranges", "Disable unused URL schemas", "Use allowlists"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "ssrf") && containsAny(dst, "internal", "local", "private", "localhost", "metadata")
			},
		},
		{
			ID:          "command-injection-rce",
			Name:        "Command Injection to RCE",
			Description: "OS command injection leading to remote code execution",
			Weight:      0.95,
			MitreIDs:    []string{"T1059", "T1204"},
			Mitigations: []string{"Avoid system() calls", "Use safe APIs", "Input validation", "Sandboxing"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "command", "cmdi", "os-command") && containsAny(dst, "rce", "exec", "shell")
			},
		},
		{
			ID:          "xxe-internal-recon",
			Name:        "XXE to Internal Recon",
			Description: "XML External Entity injection used to access internal files and services",
			Weight:      0.8,
			MitreIDs:    []string{"T1190", "T1040"},
			Mitigations: []string{"Disable XML entity processing", "Use safe XML parsers", "Input validation"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "xxe") && containsAny(dst, "internal", "file", "disclosure", "ssrf")
			},
		},
		{
			ID:          "csrf-account-takeover",
			Name:        "CSRF to Account Takeover",
			Description: "Cross-site request forgery leading to account compromise",
			Weight:      0.7,
			MitreIDs:    []string{"T1555", "T1078"},
			Mitigations: []string{"Implement CSRF tokens", "Use SameSite cookies", "Check Origin header"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "csrf") && containsAny(dst, "account", "takeover", "password", "credential")
			},
		},
		{
			ID:          "broken-auth-session-fixation",
			Name:        "Broken Authentication to Session Fixation",
			Description: "Authentication bypass leading to session hijacking",
			Weight:      0.75,
			MitreIDs:    []string{"T1078", "T1539"},
			Mitigations: []string{"Regenerate session IDs", "Use secure cookies", "Implement MFA"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "auth", "login", "bypass") && containsAny(dst, "session", "cookie", "token", "fixation")
			},
		},
		{
			ID:          "s3-bucket-data-exposure",
			Name:        "Exposed S3 Bucket to Data Exposure",
			Description: "Publicly accessible S3 bucket exposing sensitive data",
			Weight:      0.85,
			MitreIDs:    []string{"T1539", "T1041"},
			Mitigations: []string{"Block public access", "Enable server-side encryption", "Use bucket policies", "Regular audits"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "s3", "bucket", "storage") && containsAny(dst, "exposure", "data", "sensitive", "credential")
			},
		},
		{
			ID:          "graphql-introspection-data",
			Name:        "GraphQL Introspection to Data Access",
			Description: "GraphQL introspection enabled exposing schema and enabling attacks",
			Weight:      0.65,
			MitreIDs:    []string{"T1592", "T1004"},
			Mitigations: []string{"Disable introspection in production", "Use depth limiting", "Implement query cost analysis"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "graphql", "introspection") && containsAny(dst, "data", "exposure", "unauthorized")
			},
		},
		{
			ID:          "jenkins-rce",
			Name:        "Exposed Jenkins to RCE",
			Description: "Unauthenticated Jenkins leading to remote code execution",
			Weight:      0.95,
			MitreIDs:    []string{"T1190", "T1059"},
			Mitigations: []string{"Enable authentication", "Use scripts approval", "Network segmentation", "Update Jenkins"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "jenkins") && containsAny(dst, "rce", "command", "exec", "shell", "script")
			},
		},
		{
			ID:          "gitlab-rce",
			Name:        "Exposed GitLab to RCE",
			Description: "Unauthenticated or low-priv GitLab leading to code execution",
			Weight:      0.9,
			MitreIDs:    []string{"T1190", "T1059"},
			Mitigations: []string{"Enable authentication", "Disable registration", "Update GitLab", "Network segmentation"},
			Condition: func(src, dst vulnscan.Vulnerability) bool {
				return containsAny(src, "gitlab") && containsAny(dst, "rce", "command", "exec", "shell")
			},
		},
	}
}

// containsAny checks if a vulnerability's name or template ID contains any of the given patterns
func containsAny(v vulnscan.Vulnerability, patterns ...string) bool {
	combined := strings.ToLower(v.Name + " " + v.TemplateID + " " + v.Type)
	for _, p := range patterns {
		if strings.Contains(combined, p) {
			return true
		}
	}
	return false
}
