package osint

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// runWHOIS performs a WHOIS lookup for the target domain
func (s *Scanner) runWHOIS(target string) (*WHOISResult, error) {
	// Execute system whois command
	cmd := exec.Command("whois", target)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("whois lookup failed: %w", err)
	}

	raw := string(output)
	result := &WHOISResult{Raw: raw}

	// Parse WHOIS output
	result.Registrar = extractField(raw, `Registrar:\s*(.+)`)
	result.OrgName = extractField(raw, `(?:Registrant Organization|Org(?:anization)?(?:\s+Name)?):\s*(.+)`)
	result.CreatedDate = extractField(raw, `(?:Creation Date|Created(?:\s+Date)?):\s*(.+)`)
	result.ExpiryDate = extractField(raw, `(?:Registry Expiry Date|Expir(?:y|ation)(?:\s+Date)?):\s*(.+)`)
	result.Country = extractField(raw, `(?:Registrant Country|Country):\s*(.+)`)

	// Extract emails
	emailRegex := regexp.MustCompile(`[\w.+-]+@[\w.-]+\.\w{2,}`)
	emails := emailRegex.FindAllString(raw, -1)
	seen := make(map[string]bool)
	for _, e := range emails {
		e = strings.ToLower(e)
		// Filter out abuse/generic emails
		if !seen[e] && !strings.Contains(e, "abuse@") && !strings.Contains(e, "noreply@") {
			result.Emails = append(result.Emails, e)
			seen[e] = true
		}
	}

	// Extract nameservers
	nsRegex := regexp.MustCompile(`(?i)Name\s*Server:\s*(\S+)`)
	nsMatches := nsRegex.FindAllStringSubmatch(raw, -1)
	nsSeen := make(map[string]bool)
	for _, m := range nsMatches {
		ns := strings.ToLower(strings.TrimRight(m[1], "."))
		// Filter out invalid nameservers (must contain at least one dot and not start with invalid chars)
		if len(ns) < 5 || !strings.Contains(ns, ".") || strings.HasPrefix(ns, "dnssec") {
			continue
		}
		// Filter out entries that are clearly not nameservers
		if ns == "name" || ns == "nameserver" || strings.Contains(ns, ":") {
			continue
		}
		if !nsSeen[ns] {
			result.NameServers = append(result.NameServers, ns)
			nsSeen[ns] = true
		}
	}

	return result, nil
}

// extractField extracts a single field from WHOIS output using regex
func extractField(raw, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(raw)
	if len(match) >= 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
}
