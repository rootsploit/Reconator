package osint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type crtshEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

// runCertTransparency queries crt.sh for certificate transparency logs
func (s *Scanner) runCertTransparency(target string) ([]CTEntry, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse error: %w", err)
	}

	// Deduplicate and convert
	seen := make(map[string]bool)
	var results []CTEntry

	for _, e := range entries {
		// Split name_value which can contain multiple domains separated by newlines
		domains := strings.Split(e.NameValue, "\n")
		for _, domain := range domains {
			domain = strings.TrimSpace(strings.ToLower(domain))
			if domain == "" || seen[domain] {
				continue
			}
			// Skip wildcard prefix for dedup but keep in result
			cleanDomain := strings.TrimPrefix(domain, "*.")
			if seen[cleanDomain] {
				continue
			}
			seen[domain] = true
			seen[cleanDomain] = true

			results = append(results, CTEntry{
				Domain:    domain,
				Issuer:    e.IssuerName,
				NotBefore: e.NotBefore,
				NotAfter:  e.NotAfter,
			})
		}
	}

	// Sort by domain
	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})

	// Cap at 500 entries
	if len(results) > 500 {
		results = results[:500]
	}

	return results, nil
}

// extractCTSubdomains returns unique subdomains found in CT logs
func extractCTSubdomains(entries []CTEntry, baseDomain string) []string {
	seen := make(map[string]bool)
	var subs []string

	for _, e := range entries {
		domain := strings.TrimPrefix(e.Domain, "*.")
		if strings.HasSuffix(domain, "."+baseDomain) && !seen[domain] {
			seen[domain] = true
			subs = append(subs, domain)
		}
	}

	sort.Strings(subs)
	return subs
}
