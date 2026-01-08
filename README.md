# Reconator

Fast reconnaissance tool for bug bounty hunters. Built in Go for easy installation.

---

## 🚀 Overview

Reconator is a streamlined reconnaissance framework that combines multiple best-in-class tools into a single automated pipeline. It runs passive enumeration, DNS bruteforce, port scanning, and vulnerability detection in parallel for maximum speed.

### Key Features

- ✅ **Passive Subdomain Discovery**: subfinder (30+ built-in sources) + assetfinder + optional tools
- ✅ **DNS Bruteforce**: Parallel bruteforce with puredns using quality resolvers
- ✅ **Permutation Generation**: Advanced subdomain permutations using alterx and mksub
- ✅ **Fast DNS Validation**: puredns/dnsx validation with configurable threads
- ✅ **WAF/CDN Detection**: Identify protected vs direct hosts with cdncheck
- ✅ **Port Scanning**: Fast scanning with naabu + HTTP probing with httpx
- ✅ **Subdomain Takeover**: Detection using subzy with fingerprint matching
- ✅ **Historic URLs**: Wayback, CommonCrawl, and live crawling with katana
- ✅ **Stealth Mode**: Passive-only reconnaissance for quiet initial scans

---

## 🛠️ Installation

```bash
# One-shot install
go install github.com/rootsploit/reconator@latest

# Install dependencies (Go tools + wordlists)
reconator install

# Install optional extras (Python/Rust tools)
reconator install --extras

# Verify installation
reconator check
```

---

## 📖 Usage

```bash
# Basic scan
reconator scan example.com

# Or using flags
reconator -t example.com

# Multiple domains from file
reconator scan -l domains.txt

# Custom output directory
reconator scan example.com -o ./output
```

### Phase Selection

```bash
# Run all phases (default)
reconator scan example.com -p all

# Run specific phases
reconator scan example.com -p subdomain,ports,takeover

# Available phases: subdomain, waf, ports, takeover, historic
```

### Mode Options

```bash
# Stealth mode - passive only, no bruteforce
reconator scan example.com --stealth

# Fast mode - skip alterx, limit permutations
reconator scan example.com --fast
```

### ⚡ Performance Tuning

```bash
# Set concurrency for tools (subfinder, naabu, httpx, katana, subzy)
reconator scan example.com -c 100

# Set DNS threads for puredns/dnsx
reconator scan example.com --dns-threads 200

# Set rate limit for port scanning (naabu)
reconator scan example.com -r 50

# Skip DNS validation (faster but less accurate)
reconator scan example.com --skip-validation
```

### Custom Resources

```bash
# Custom resolvers
reconator scan example.com --resolvers /path/to/resolvers.txt

# Custom wordlist
reconator scan example.com --wordlist /path/to/wordlist.txt
```

---

## 📋 Pipeline

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Subdomain Enumeration | Passive sources + DNS bruteforce + permutations + validation |
| 2 | WAF/CDN Detection | Identify CDN-protected vs direct hosts |
| 3 | Port Scanning | naabu port discovery + httpx HTTP probing + TLS analysis |
| 4 | Subdomain Takeover | subzy fingerprint matching for vulnerable subdomains |
| 5 | Historic URLs | waybackurls, gau, katana crawling + subdomain extraction |

**Stealth mode** skips DNS bruteforce, permutations, and scans only direct hosts.

---

## 📂 Output Structure

```
results/
└── example.com/
    ├── summary.json
    ├── 1-subdomains/
    │   ├── subdomains.json       # Full results with sources
    │   ├── subdomains.txt        # Validated subdomains
    │   └── all_subdomains.txt    # All discovered (pre-validation)
    ├── 2-waf/
    │   ├── waf_detection.json
    │   ├── cdn_hosts.txt
    │   └── direct_hosts.txt
    ├── 3-ports/
    │   ├── port_scan.json
    │   ├── open_ports.txt
    │   ├── alive_hosts.txt
    │   └── tls_info.json
    ├── 4-takeover/
    │   ├── takeover.json
    │   └── vulnerable.txt
    └── 5-historic/
        ├── historic_urls.json
        ├── urls.txt
        └── endpoints.txt
```

---

## 🔧 Required Tools

Installed automatically via `reconator install`:

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain discovery (30+ passive sources) |
| assetfinder | Additional subdomain discovery |
| puredns | DNS bruteforce and validation |
| dnsx | DNS toolkit |
| alterx | Subdomain permutation |
| mksub | Permutation generator |
| dsieve | Domain filtering |
| httpx | HTTP probing |
| naabu | Port scanning |
| tlsx | TLS certificate analysis |
| cdncheck | CDN/WAF detection |
| subzy | Subdomain takeover detection |
| waybackurls | Wayback Machine URLs |
| gau | Get All URLs |
| katana | Web crawling |

### Optional Tools

Install with `reconator install --extras`:

| Tool | Language | Purpose |
|------|----------|---------|
| waymore | Python | Extended wayback sources |
| vita | Rust | Additional subdomain sources |
| findomain | Rust | Subdomain enumeration |

---

## 🙏 Credits

Built with:
- [ProjectDiscovery](https://github.com/projectdiscovery) - subfinder, httpx, dnsx, naabu, katana, tlsx, cdncheck, alterx
- [Trickest](https://github.com/trickest) - mksub, dsieve, resolvers
- [d3mondev/puredns](https://github.com/d3mondev/puredns)
- [tomnomnom](https://github.com/tomnomnom) - assetfinder, waybackurls
- [LukaSikic/subzy](https://github.com/LukaSikic/subzy)
- [lc/gau](https://github.com/lc/gau)

---

## ⚠️ Legal Disclaimer

This tool is for authorized security testing and bug bounty programs only. Users are responsible for compliance with applicable laws. Unauthorized testing is illegal.

**Always obtain proper authorization before testing.**

---

## 📄 License

MIT License

---

**Reconator** - Fast reconnaissance for bug bounty hunters 🚀
