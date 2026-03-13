package tools

type Tool struct {
	Name       string
	Binary     string
	InstallCmd string
	Required   bool
}

type ToolStatus struct {
	Name, Version string
	Installed     bool
}

type AllToolsStatus struct {
	Go, Python, Rust []ToolStatus
}

// GoTools - all Go-based tools
func GoTools() []Tool {
	return []Tool{
		// Subdomain enumeration
		{"subfinder", "subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true},
		{"assetfinder", "assetfinder", "github.com/tomnomnom/assetfinder@latest", true},
		{"cero", "cero", "github.com/glebarez/cero@latest", false}, // CT log subdomain discovery
		// Note: github-subdomains removed - subfinder with GitHub API keys handles this

		// IP range to domain discovery
		{"hakrevdns", "hakrevdns", "github.com/hakluke/hakrevdns@latest", false},                // Reverse DNS from IPs
		{"hakip2host", "hakip2host", "github.com/hakluke/hakip2host@latest", false},             // IP to hostname via multiple checks
		{"mapcidr", "mapcidr", "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", false}, // CIDR expansion
		{"asnmap", "asnmap", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest", false},     // ASN to CIDR/domain discovery
		{"CloudRecon", "CloudRecon", "github.com/g0ldencybersec/CloudRecon@latest", false},      // SSL cert recon on cloud IP ranges

		// Favicon reconnaissance
		{"favirecon", "favirecon", "github.com/edoardottt/favirecon/cmd/favirecon@latest", false}, // Favicon hash recon

		// Note: wappalyzergo is used as a Go library (imported directly), not a CLI tool
		// Technology detection happens via the techdetect package using wappalyzergo library

		// DNS tools
		{"dnsx", "dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", true},
		{"puredns", "puredns", "github.com/d3mondev/puredns/v2@latest", true},

		// Permutation & filtering
		{"alterx", "alterx", "github.com/projectdiscovery/alterx/cmd/alterx@latest", true},
		{"mksub", "mksub", "github.com/trickest/mksub@latest", true},
		{"dsieve", "dsieve", "github.com/trickest/dsieve@latest", true},

		// HTTP probing
		{"httpx", "httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", true},

		// Port & TLS scanning
		{"naabu", "naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true},
		{"tlsx", "tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", true},

		// WAF/CDN detection
		{"cdncheck", "cdncheck", "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", true},

		// Vulnerability scanning
		{"nuclei", "nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true},
		{"vulnx", "vulnx", "github.com/projectdiscovery/cvemap/cmd/vulnx@latest", false}, // CVE lookup by technology (next-gen cvemap)

		// Secret scanning
		{"trufflehog", "trufflehog", "github.com/trufflesecurity/trufflehog/v3@latest", true},

		// Historic URLs
		{"waybackurls", "waybackurls", "github.com/tomnomnom/waybackurls@latest", true},
		{"gau", "gau", "github.com/lc/gau/v2/cmd/gau@latest", true},
		{"katana", "katana", "github.com/projectdiscovery/katana/cmd/katana@latest", true},
		{"urlfinder", "urlfinder", "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest", true},

		// Fuzzing
		{"ffuf", "ffuf", "github.com/ffuf/ffuf/v2@latest", true},

		// Takeover
		{"subzy", "subzy", "github.com/PentestPad/subzy@latest", false},
		{"subjack", "subjack", "github.com/haccer/subjack@latest", false},
		{"dnstake", "dnstake", "github.com/pwnesia/dnstake/cmd/dnstake@latest", false}, // DNS takeover detection

		// CRLF Injection
		{"crlfuzz", "crlfuzz", "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest", false}, // CRLF injection scanning

		// Directory bruteforce
		{"feroxbuster", "feroxbuster", "", true}, // Install via package manager or GitHub releases (REQUIRED)

		// URL analysis & quick testing (BB-8)
		{"gf", "gf", "github.com/tomnomnom/gf@latest", false},                      // Pattern matching
		{"qsreplace", "qsreplace", "github.com/tomnomnom/qsreplace@latest", false}, // Query string replace for payload injection

		// XSS scanning
		{"dalfox", "dalfox", "github.com/hahwul/dalfox/v2@latest", false},
		{"sxss", "sxss", "github.com/unstabl3/sxss@latest", false}, // Fast XSS reflection scanner (kxss alternative)

		// Screenshots
		{"gowitness", "gowitness", "github.com/sensepost/gowitness@latest", false},

		// Cloudflare bypass
		{"hakoriginfinder", "hakoriginfinder", "github.com/hakluke/hakoriginfinder@latest", false},
		{"cf-hero", "cf-hero", "github.com/musana/cf-hero/cmd/cf-hero@latest", false}, // Cloudflare origin finder (multiple methods)

		// Alerting
		{"notify", "notify", "github.com/projectdiscovery/notify/cmd/notify@latest", false},

		// Manual install required
		{"massdns", "massdns", "", true},
	}
}

// PythonTools - optional Python tools
func PythonTools() []Tool {
	return []Tool{
		{"waymore", "waymore", "waymore", false},
		{"xnLinkFinder", "xnLinkFinder", "xnLinkFinder", false}, // Endpoint/parameter extraction
		{"uro", "uro", "uro", false},                            // BB-7: URL deduplication (84% reduction)
	}
}

// RustTools - Rust tools (installed via GitHub releases or cargo)
func RustTools() []Tool {
	return []Tool{
		// vita is not available as a binary - removed
		{"findomain", "findomain", "", false},    // GitHub releases only
		{"feroxbuster", "feroxbuster", "", true}, // GitHub releases or package manager (REQUIRED)
	}
}
