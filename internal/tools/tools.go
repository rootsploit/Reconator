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

		// Historic URLs
		{"waybackurls", "waybackurls", "github.com/tomnomnom/waybackurls@latest", true},
		{"gau", "gau", "github.com/lc/gau/v2/cmd/gau@latest", true},
		{"katana", "katana", "github.com/projectdiscovery/katana/cmd/katana@latest", true},

		// Fuzzing
		{"ffuf", "ffuf", "github.com/ffuf/ffuf/v2@latest", true},

		// Takeover
		{"subzy", "subzy", "github.com/PentestPad/subzy@latest", false},

		// Manual install required
		{"massdns", "massdns", "", true},
	}
}

// PythonTools - optional Python tools
func PythonTools() []Tool {
	return []Tool{
		{"waymore", "waymore", "waymore", false},
	}
}

// RustTools - optional Rust tools
func RustTools() []Tool {
	return []Tool{
		{"vita", "vita", "vita", false},
		{"findomain", "findomain", "findomain", false},
		{"feroxbuster", "feroxbuster", "feroxbuster", false},
	}
}
