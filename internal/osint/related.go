package osint

import (
	"sort"
	"strings"
)

// runRelatedDomains discovers domains related to the target
func (s *Scanner) runRelatedDomains(target string, whoisResult *WHOISResult, asnResult *ASNResult, ctEntries []CTEntry) []RelatedDomain {
	var related []RelatedDomain
	seen := make(map[string]bool)
	seen[target] = true

	// 1. From CT logs - domains sharing certificates
	if len(ctEntries) > 0 {
		for _, entry := range ctEntries {
			domain := strings.TrimPrefix(entry.Domain, "*.")
			// Check if domain is NOT a subdomain of target (different TLD/domain)
			if !strings.HasSuffix(domain, "."+target) && domain != target && !seen[domain] {
				// Extract base domain
				parts := strings.Split(domain, ".")
				if len(parts) >= 2 {
					baseDomain := strings.Join(parts[len(parts)-2:], ".")
					if baseDomain != target && !seen[baseDomain] {
						seen[baseDomain] = true
						related = append(related, RelatedDomain{
							Domain:     baseDomain,
							Relation:   "ct_discovered",
							Confidence: 0.7,
							Source:     "crt.sh certificate sharing",
						})
					}
				}
			}
		}
	}

	// 2. From WHOIS - same organization
	// Reverse WHOIS requires paid API access (whoisxmlapi.com etc.)
	// We record the org name for reference in results
	if whoisResult != nil && whoisResult.OrgName != "" {
		// Would be enhanced with whoisxmlapi.com integration
	}

	// 3. From nameservers - same nameserver patterns
	if whoisResult != nil && len(whoisResult.NameServers) > 0 {
		for _, ns := range whoisResult.NameServers {
			parts := strings.Split(ns, ".")
			if len(parts) >= 2 {
				nsBase := strings.Join(parts[len(parts)-2:], ".")
				if nsBase != target && !seen["ns:"+nsBase] {
					seen["ns:"+nsBase] = true
				}
			}
		}
	}

	// 4. From ASN - same ASN (if small ASN, likely same org)
	// Small non-cloud ASN suggests same organization
	// Would need reverse DNS on CIDRs for actual domains
	if asnResult != nil && asnResult.Provider == "" && len(asnResult.CIDRs) < 10 {
		_ = asnResult // Placeholder for future reverse DNS expansion
	}

	// Sort by confidence
	sort.Slice(related, func(i, j int) bool {
		return related[i].Confidence > related[j].Confidence
	})

	// Cap at 100
	if len(related) > 100 {
		related = related[:100]
	}

	return related
}
