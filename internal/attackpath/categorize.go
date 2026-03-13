package attackpath

import (
	"strings"

	"github.com/rootsploit/reconator/internal/vulnscan"
)

// AttackCategory represents a MITRE ATT&CK aligned category
type AttackCategory struct {
	ID       string   // e.g., "initial_access"
	Name     string   // e.g., "Initial Access"
	MitreIDs []string // e.g., ["T1190", "T1189"]
}

// Categories defines all attack categories
var Categories = map[string]AttackCategory{
	"initial_access": {
		ID:       "initial_access",
		Name:     "Initial Access",
		MitreIDs: []string{"T1190", "T1189", "T1133", "T1566"},
	},
	"credential_access": {
		ID:       "credential_access",
		Name:     "Credential Access",
		MitreIDs: []string{"T1078", "T1110", "T1552", "T1539"},
	},
	"privilege_escalation": {
		ID:       "privilege_escalation",
		Name:     "Privilege Escalation",
		MitreIDs: []string{"T1068", "T1548", "T1078"},
	},
	"lateral_movement": {
		ID:       "lateral_movement",
		Name:     "Lateral Movement",
		MitreIDs: []string{"T1021", "T1570", "T1534"},
	},
	"data_exfiltration": {
		ID:       "data_exfiltration",
		Name:     "Data Exfiltration",
		MitreIDs: []string{"T1041", "T1048", "T1567"},
	},
	"persistence": {
		ID:       "persistence",
		Name:     "Persistence",
		MitreIDs: []string{"T1505", "T1136", "T1098"},
	},
	"impact": {
		ID:       "impact",
		Name:     "Impact",
		MitreIDs: []string{"T1486", "T1491", "T1485"},
	},
}

// CategorizeVulnerability maps a vulnerability to its attack category
func CategorizeVulnerability(v vulnscan.Vulnerability) string {
	name := strings.ToLower(v.Name)
	templateID := strings.ToLower(v.TemplateID)
	combined := name + " " + templateID + " " + strings.ToLower(v.Type)

	// CVE patterns - known CVEs are initial access exploits
	if strings.Contains(templateID, "cve-") || strings.Contains(templateID, "cve_") {
		// CVEs with RCE/command patterns -> initial access
		if strings.Contains(combined, "rce") || strings.Contains(combined, "command") ||
			strings.Contains(combined, "execution") || strings.Contains(combined, "injection") {
			return "initial_access"
		}
		// CVEs with path traversal -> can lead to credential access
		if strings.Contains(combined, "path traversal") || strings.Contains(combined, "traversal") {
			return "initial_access"
		}
		// Other CVEs default to initial access (they're exploits)
		return "initial_access"
	}

	// Initial Access patterns
	initialAccessPatterns := []string{
		"ssrf", "sqli", "sql injection", "xss", "cross-site",
		"rce", "command injection", "code execution", "remote code",
		"lfi", "local file", "rfi", "remote file",
		"upload", "deserialization", "template injection",
		"xxe", "xml external", "path traversal",
	}
	for _, p := range initialAccessPatterns {
		if strings.Contains(combined, p) {
			return "initial_access"
		}
	}

	// Credential Access patterns
	credentialPatterns := []string{
		"default", "credential", "password", "login", "auth bypass",
		"authentication bypass", "token", "jwt", "session",
		"exposed secret", "hardcoded", "api key", "apikey",
		".env", "config exposure", "git exposure",
	}
	for _, p := range credentialPatterns {
		if strings.Contains(combined, p) {
			return "credential_access"
		}
	}

	// Privilege Escalation patterns
	privescPatterns := []string{
		"privilege", "escalation", "admin panel", "admin access",
		"role", "permission", "idor", "insecure direct",
		"broken access", "authorization",
	}
	for _, p := range privescPatterns {
		if strings.Contains(combined, p) {
			return "privilege_escalation"
		}
	}

	// Lateral Movement patterns
	lateralPatterns := []string{
		"subdomain takeover", "dns zone transfer", "internal",
		"cloud metadata", "imds", "169.254", "metadata",
		"aws", "gcp", "azure", "s3 bucket",
	}
	for _, p := range lateralPatterns {
		if strings.Contains(combined, p) {
			return "lateral_movement"
		}
	}

	// Data Exfiltration patterns
	exfilPatterns := []string{
		"data leak", "information disclosure", "exposure",
		"directory listing", "backup", "database",
		"dump", "export", "download",
	}
	for _, p := range exfilPatterns {
		if strings.Contains(combined, p) {
			return "data_exfiltration"
		}
	}

	// Persistence patterns
	persistencePatterns := []string{
		"webshell", "backdoor", "cron", "scheduled",
		"reverse shell", "bind shell",
	}
	for _, p := range persistencePatterns {
		if strings.Contains(combined, p) {
			return "persistence"
		}
	}

	// Impact patterns
	impactPatterns := []string{
		"dos", "denial", "ransomware", "wipe",
		"defacement", "deface",
	}
	for _, p := range impactPatterns {
		if strings.Contains(combined, p) {
			return "impact"
		}
	}

	// Default: unknown vulns are categorized as data_exfiltration (info disclosure)
	// rather than initial_access, to prevent them from becoming DFS entry points
	return "data_exfiltration"
}

// GetPreconditions returns preconditions for a vulnerability based on its category
func GetPreconditions(v vulnscan.Vulnerability, category string) []string {
	switch category {
	case "initial_access":
		return []string{"network_access", "target_reachable"}
	case "credential_access":
		return []string{"network_access", "service_exposed"}
	case "privilege_escalation":
		return []string{"authenticated_access", "low_privilege_user"}
	case "lateral_movement":
		return []string{"initial_foothold", "network_access"}
	case "data_exfiltration":
		return []string{"data_access", "read_permission"}
	case "persistence":
		return []string{"code_execution", "write_access"}
	case "impact":
		return []string{"privileged_access", "target_control"}
	default:
		return []string{"network_access"}
	}
}

// GetPostconditions returns postconditions after successful exploitation
func GetPostconditions(v vulnscan.Vulnerability, category string) []string {
	combined := strings.ToLower(v.Name + " " + v.TemplateID)

	switch category {
	case "initial_access":
		if strings.Contains(combined, "rce") || strings.Contains(combined, "command injection") {
			return []string{"code_execution", "server_access", "write_access"}
		}
		if strings.Contains(combined, "ssrf") {
			return []string{"internal_network_access", "metadata_access"}
		}
		if strings.Contains(combined, "sqli") {
			return []string{"data_access", "read_permission", "database_access"}
		}
		if strings.Contains(combined, "lfi") || strings.Contains(combined, "path traversal") || strings.Contains(combined, "directory traversal") {
			return []string{"file_read", "config_read", "credential_obtained", "source_code_access"}
		}
		if strings.Contains(combined, "xss") {
			return []string{"session_theft", "client_code_execution"}
		}
		return []string{"initial_foothold"}
	case "credential_access":
		return []string{"authenticated_access", "credential_obtained"}
	case "privilege_escalation":
		return []string{"privileged_access", "admin_access"}
	case "lateral_movement":
		return []string{"expanded_access", "new_target_access"}
	case "data_exfiltration":
		return []string{"data_obtained", "sensitive_data_leaked"}
	case "persistence":
		return []string{"persistent_access", "backdoor_installed"}
	case "impact":
		return []string{"target_compromised", "mission_complete"}
	default:
		return []string{"unknown_state"}
	}
}
