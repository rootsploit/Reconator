package osint

import "time"

// Result contains all OSINT findings for a target
type Result struct {
	Target           string          `json:"target"`
	WHOIS            *WHOISResult    `json:"whois,omitempty"`
	ReverseWHOIS     []ReverseEntry  `json:"reverse_whois,omitempty"`
	ASN              *ASNResult      `json:"asn,omitempty"`
	CertTransparency []CTEntry       `json:"cert_transparency,omitempty"`
	RelatedDomains   []RelatedDomain `json:"related_domains,omitempty"`
	BreachData       []BreachEntry   `json:"breach_data,omitempty"`
	Acquisitions     []Acquisition   `json:"acquisitions,omitempty"`
	DNSRecords       *DNSRecordSet   `json:"dns_records,omitempty"`
	DorksFile        string          `json:"dorks_file,omitempty"`
	Duration         time.Duration   `json:"duration"`
}

// DNSRecordSet contains DNS records collected for the target domain
type DNSRecordSet struct {
	TXT   []string `json:"txt,omitempty"`
	SPF   string   `json:"spf,omitempty"`
	DMARC string   `json:"dmarc,omitempty"`
	DKIM  []string `json:"dkim,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	CAA   []string `json:"caa,omitempty"`
}

// WHOISResult contains WHOIS lookup data
type WHOISResult struct {
	Registrar   string   `json:"registrar"`
	OrgName     string   `json:"org_name"`
	Emails      []string `json:"emails"`
	NameServers []string `json:"nameservers"`
	CreatedDate string   `json:"created_date"`
	ExpiryDate  string   `json:"expiry_date"`
	Country     string   `json:"country"`
	Raw         string   `json:"raw,omitempty"`
}

// ReverseEntry represents a reverse WHOIS match
type ReverseEntry struct {
	Domain  string `json:"domain"`
	MatchOn string `json:"match_on"` // "org", "email", "nameserver"
	Value   string `json:"value"`
}

// ASNResult contains ASN enrichment data
type ASNResult struct {
	ASN      int      `json:"asn"`
	OrgName  string   `json:"org_name"`
	CIDRs    []string `json:"cidrs"`
	Peers    []int    `json:"peers,omitempty"`
	Provider string   `json:"provider"` // AWS, GCP, Azure, Cloudflare, etc.
	Country  string   `json:"country"`
	RIR      string   `json:"rir"` // ARIN, RIPE, APNIC, etc.
}

// CTEntry represents a Certificate Transparency log entry
type CTEntry struct {
	Domain    string   `json:"domain"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	SAN       []string `json:"san,omitempty"`
}

// RelatedDomain represents a domain related to the target
type RelatedDomain struct {
	Domain     string  `json:"domain"`
	Relation   string  `json:"relation"`   // same_org, same_registrant, same_nameserver, same_asn, ct_discovered, acquisition
	Confidence float64 `json:"confidence"` // 0.0-1.0
	Source     string  `json:"source"`
}

// BreachEntry represents a known breach associated with the target domain
type BreachEntry struct {
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	BreachDate  string   `json:"breach_date"`
	DataClasses []string `json:"data_classes,omitempty"` // e.g., "Emails", "Passwords"
	RecordCount int      `json:"record_count,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Acquisition represents a company acquisition
type Acquisition struct {
	Company string `json:"company"`
	Domain  string `json:"domain"`
	Source  string `json:"source"`
}
