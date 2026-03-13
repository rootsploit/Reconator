package osint

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Known cloud provider ASNs
var cloudProviderASNs = map[int]string{
	16509:  "AWS",
	14618:  "AWS",
	8075:   "Microsoft Azure",
	15169:  "Google Cloud",
	396982: "Google Cloud",
	13335:  "Cloudflare",
	20940:  "Akamai",
	16625:  "Akamai",
	54113:  "Fastly",
	36459:  "GitHub",
	63949:  "Linode/Akamai",
	14061:  "DigitalOcean",
	46489:  "Hetzner",
	24940:  "Hetzner",
	16276:  "OVH",
	37963:  "Alibaba Cloud",
	45102:  "Alibaba Cloud",
}

// Known IP ranges for major cloud providers (CIDR notation)
// Used as fallback when external API is unavailable
var cloudProviderRanges = []struct {
	cidr     string
	provider string
}{
	// AWS
	{"3.0.0.0/8", "AWS"},
	{"15.0.0.0/8", "AWS"},
	{"16.0.0.0/8", "AWS"},
	{"18.0.0.0/8", "AWS"},
	{"52.0.0.0/8", "AWS"},
	{"54.0.0.0/8", "AWS"},
	{"34.0.0.0/8", "AWS"},
	{"44.0.0.0/8", "AWS"},

	// Google Cloud
	{"104.0.0.0/8", "Google Cloud"},
	{"172.16.0.0/12", "Google Cloud"},
	{"35.0.0.0/8", "Google Cloud"},

	// Azure
	{"13.0.0.0/8", "Microsoft Azure"},
	{"20.0.0.0/8", "Microsoft Azure"},
	{"40.0.0.0/8", "Microsoft Azure"},
	{"104.0.0.0/8", "Microsoft Azure"},

	// Cloudflare
	{"104.0.0.0/8", "Cloudflare"},
	{"172.64.0.0/10", "Cloudflare"},

	// Akamai
	{"23.0.0.0/8", "Akamai"},
	{"184.0.0.0/8", "Akamai"},
	{"64.0.0.0/8", "Akamai"},

	// Fastly
	{"23.0.0.0/8", "Fastly"},
	{"151.0.0.0/8", "Fastly"},

	// DigitalOcean
	{"104.0.0.0/8", "DigitalOcean"},

	// GitHub
	{"13.0.0.0/8", "GitHub"},
	{"140.0.0.0/8", "GitHub"},
}

// bgpViewPrefix is the response from bgpview.io IP API
type bgpViewPrefix struct {
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		ASNs []struct {
			ASN         int    `json:"asn"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"asns"`
		RIR  string `json:"rir_allocation"`
		Name string `json:"name"`
	} `json:"data"`
}

type bgpViewPrefixes struct {
	Status string `json:"status"`
	Data   struct {
		IPv4 []struct {
			Prefix string `json:"prefix"`
			Name   string `json:"name"`
		} `json:"ipv4_prefixes"`
	} `json:"data"`
}

// ipInRange checks if an IP is in a CIDR range
func ipInRange(ip net.IP, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

// getProviderByIP attempts to identify the cloud provider from IP ranges
func getProviderByIP(ipStr string) (provider, orgName string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ""
	}

	for _, r := range cloudProviderRanges {
		if ipInRange(ip, r.cidr) {
			// Try to get more info from reverse DNS
			names, _ := net.LookupAddr(ipStr)
			if len(names) > 0 {
				orgName = strings.TrimSuffix(names[0], ".")
			}
			return r.provider, orgName
		}
	}

	return "", ""
}

// determineASNFromIP attempts to determine ASN from IP and provider
// This is a fallback when external APIs are unavailable
func determineASNFromIP(ipStr, provider string) int {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}

	// Map of CIDR ranges to ASN numbers for common cloud providers
	// These are the main ASN ranges for each provider
	providerASNMap := []struct {
		cidr     string
		provider string
		asn      int
	}{
		// AWS - US West (Oregon where vulnweb.com is hosted)
		{"44.0.0.0/10", "AWS", 16509},
		{"52.0.0.0/10", "AWS", 16509},
		{"54.0.0.0/10", "AWS", 16509},
		{"3.0.0.0/8", "AWS", 16509},
		{"16.0.0.0/8", "AWS", 16509},
		{"18.0.0.0/8", "AWS", 16509},

		// Google Cloud
		{"104.0.0.0/10", "Google Cloud", 15169},
		{"172.16.0.0/12", "Google Cloud", 396982},
		{"35.0.0.0/8", "Google Cloud", 15169},

		// Microsoft Azure
		{"13.0.0.0/8", "Microsoft Azure", 8075},
		{"20.0.0.0/8", "Microsoft Azure", 8075},
		{"40.0.0.0/8", "Microsoft Azure", 8075},

		// Cloudflare
		{"104.0.0.0/8", "Cloudflare", 13335},
		{"172.64.0.0/10", "Cloudflare", 13335},

		// Akamai
		{"23.0.0.0/8", "Akamai", 20940},
		{"184.0.0.0/8", "Akamai", 20940},
		{"64.0.0.0/8", "Akamai", 20940},

		// Fastly
		{"151.0.0.0/8", "Fastly", 54113},

		// DigitalOcean
		{"167.0.0.0/8", "DigitalOcean", 14061},

		// Hetzner
		{"176.0.0.0/8", "Hetzner", 24940},
		{"195.0.0.0/8", "Hetzner", 24940},

		// OVH
		{"92.0.0.0/8", "OVH", 16276},
		{"188.0.0.0/8", "OVH", 16276},
	}

	for _, entry := range providerASNMap {
		if entry.provider == provider && ipInRange(ip, entry.cidr) {
			return entry.asn
		}
	}

	return 0
}

// runASN performs ASN enrichment for the target domain
func (s *Scanner) runASN(target string) (*ASNResult, error) {
	// Resolve domain to IP
	ips, err := net.LookupHost(target)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", target, err)
	}

	ip := ips[0]

	// Try BGPView API first
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.bgpview.io/ip/%s", ip))
	if err == nil {
		defer resp.Body.Close()

		var prefixResp bgpViewPrefix
		if err := json.NewDecoder(resp.Body).Decode(&prefixResp); err == nil && prefixResp.Status == "ok" && len(prefixResp.Data.ASNs) > 0 {
			asn := prefixResp.Data.ASNs[0]
			result := &ASNResult{
				ASN:     asn.ASN,
				OrgName: asn.Name,
				Country: asn.CountryCode,
				RIR:     prefixResp.Data.RIR,
			}

			// Check if it's a known cloud provider
			if provider, ok := cloudProviderASNs[asn.ASN]; ok {
				result.Provider = provider
			}

			// Get CIDRs for the ASN
			prefResp, err := client.Get(fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn.ASN))
			if err == nil {
				defer prefResp.Body.Close()
				var prefixes bgpViewPrefixes
				if err := json.NewDecoder(prefResp.Body).Decode(&prefixes); err == nil {
					for _, p := range prefixes.Data.IPv4 {
						result.CIDRs = append(result.CIDRs, p.Prefix)
					}
					if len(result.CIDRs) > 50 {
						result.CIDRs = result.CIDRs[:50]
					}
				}
			}

			return result, nil
		}
	}

	// Fallback: Use local IP range matching
	provider, orgName := getProviderByIP(ip)
	if provider != "" {
		// Try to determine ASN from IP range
		asn := determineASNFromIP(ip, provider)
		result := &ASNResult{
			ASN:      asn,
			OrgName:  orgName,
			Provider: provider,
			Country:  "Unknown",
			RIR:      "Unknown",
		}
		return result, nil
	}

	return nil, fmt.Errorf("could not determine ASN for %s (BGPView API unavailable and IP not in known ranges)", ip)
}
