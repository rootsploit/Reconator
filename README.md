<p align="center">
  <h1 align="center">Reconator</h1>
  <p align="center">
    <b>Fast reconnaissance tool for bug bounty hunters</b>
  </p>
  <p align="center">
    Built in Go for easy installation and maximum speed
  </p>
</p>

<p align="center">
  <a href="https://github.com/rootsploit/reconator/releases"><img src="https://img.shields.io/github/v/release/rootsploit/reconator?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://github.com/rootsploit/reconator/blob/main/LICENSE"><img src="https://img.shields.io/github/license/rootsploit/reconator?style=flat-square&color=green" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/rootsploit/reconator"><img src="https://goreportcard.com/badge/github.com/rootsploit/reconator?style=flat-square" alt="Go Report Card"></a>
  <a href="https://github.com/rootsploit/reconator/stargazers"><img src="https://img.shields.io/github/stars/rootsploit/reconator?style=flat-square&color=yellow" alt="Stars"></a>
  <a href="https://twitter.com/RootSploit"><img src="https://img.shields.io/twitter/follow/RootSploit?style=flat-square&color=1DA1F2&logo=twitter" alt="Twitter"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#pipeline-phases">Phases</a> •
  <a href="#configuration">Configuration</a>
</p>

---

## Overview

**Reconator** is a streamlined reconnaissance framework that combines multiple best-in-class tools into a single automated pipeline. It runs passive enumeration, DNS bruteforce, port scanning, vulnerability scanning, and AI-guided analysis in parallel for maximum speed.

Created by [@RootSploit](https://twitter.com/RootSploit)

---

## Features

| Feature | Description |
|---------|-------------|
| **10-Phase Pipeline** | Complete reconnaissance from subdomain enumeration to vulnerability scanning |
| **Multiple Input Types** | Supports domains, IPs, CIDR ranges, ASNs |
| **Passive Mode** | Stealth reconnaissance without active scanning |
| **AI-Guided Scanning** | CVEMap integration + AI recommendations for smart nuclei template selection |
| **Real-time Alerts** | Notifications via Slack, Discord, Telegram using ProjectDiscovery notify |
| **Cross-Platform** | Linux, macOS, Windows support |

---

## Installation

```bash
# Install reconator
go install github.com/rootsploit/reconator@latest

# Install all required dependencies
reconator install

# Install optional extras (Python/Rust tools)
reconator install --extras

# Verify installation
reconator check
```

The installer automatically:
- Detects your OS and architecture
- Uses appropriate package manager (apt, brew, dnf, pacman, choco)
- Installs system dependencies (libpcap, nmap)
- Downloads nuclei-templates
- Downloads DNS resolvers and wordlists

### Cross-Platform Support

| OS | Package Manager | Status |
|----|-----------------|--------|
| Ubuntu/Debian | apt | Full support |
| macOS | brew | Full support |
| Fedora/RHEL | dnf/yum | Full support |
| Arch Linux | pacman | Full support |
| Alpine | apk | Full support |
| Windows | choco/winget | Partial (some tools need WSL) |

---

## Usage

### Basic Scan

```bash
# Single domain
reconator scan example.com

# Multiple domains from file
reconator scan -l domains.txt

# Custom output directory
reconator scan example.com -o ./output
```

### IP Range Input

```bash
# Scan IP address (discovers domains via reverse DNS + certs)
reconator scan 192.168.1.1

# Scan CIDR range
reconator scan 10.0.0.0/24
```

### ASN Input

```bash
# Scan by ASN (discovers CIDR ranges + domains via asnmap)
reconator scan AS13335

# Also accepts without AS prefix
reconator scan 15169
```

### Phase Selection

```bash
# Run all phases (default)
reconator scan example.com -p all

# Run specific phases
reconator scan example.com -p subdomain,ports,takeover

# Available: subdomain, waf, ports, takeover, historic, tech, dirbrute, vulnscan, aiguided
```

### Mode Options

```bash
# Passive mode - no active scanning, no port scanning, no crawling
reconator scan example.com --passive

# Skip specific phases
reconator scan example.com --skip-dirbrute --skip-vulnscan --skip-aiguided

# Debug mode - detailed timing logs
reconator scan example.com --debug
```

### Performance Tuning

```bash
# Set concurrency (subfinder, naabu, httpx, katana)
reconator scan example.com -c 100

# Set DNS threads (puredns/dnsx)
reconator scan example.com --dns-threads 200

# Set rate limit for port scanning
reconator scan example.com -r 50

# Skip DNS validation (faster but less accurate)
reconator scan example.com --skip-validation
```

### AI-Guided Scanning

```bash
# Set API keys via environment variables
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="..."

# Or via flags
reconator scan example.com --openai-key "sk-..."
```

### Notifications

```bash
# Enable notifications
reconator scan example.com --notify

# Custom notify config
reconator scan example.com --notify --notify-config ~/.config/notify/provider-config.yaml
```

---

## Pipeline Phases

| Phase | Name | Description | Tools |
|:-----:|------|-------------|-------|
| 0 | **IP/ASN Discovery** | Discover domains from IP/CIDR/ASN via reverse DNS + certs | asnmap, cero, hakrevdns, hakip2host, mapcidr |
| 1 | **Subdomain Enumeration** | Passive sources + DNS bruteforce + permutations + validation | subfinder, assetfinder, findomain, puredns, alterx, mksub |
| 2 | **WAF/CDN Detection** | Identify CDN-protected vs direct hosts, origin IP discovery | cdncheck, cf-hero, hakoriginfinder |
| 3 | **Port Scanning** | Port discovery + HTTP probing + TLS analysis | naabu, httpx, tlsx |
| 4 | **Subdomain Takeover** | Detect vulnerable subdomains | subjack, nuclei (takeover templates), subzy |
| 5 | **Historic URLs** | Archive URL collection + subdomain extraction + URL categorization | waybackurls, gau, waymore, katana, urlfinder, gf |
| 6 | **Technology Detection** | Fingerprint web technologies | wappalyzergo library |
| 7 | **Directory Bruteforce** | Content discovery | feroxbuster, ffuf |
| 8 | **Vulnerability Scanning** | CVE + vulnerability templates + XSS scanning | nuclei, dalfox |
| 9 | **AI-Guided Scanning** | Smart template selection via CVEMap + AI | cvemap, nuclei + OpenAI/Claude/Gemini |
| 10 | **Alerting** | Send notifications for findings | notify (Slack, Discord, Telegram) |

---

## Output Structure

```
results/
└── example.com/
    ├── summary.json
    ├── 0-iprange/
    │   ├── ip_discovery.json
    │   ├── ips.txt
    │   └── domains.txt
    ├── 1-subdomains/
    │   ├── subdomains.json
    │   ├── subdomains.txt          # Validated subdomains
    │   └── all_subdomains.txt      # All discovered
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
    ├── 5-historic/
    │   ├── historic_urls.json
    │   ├── urls.txt
    │   ├── interesting_urls.txt
    │   └── endpoints.txt
    ├── 6-tech/
    │   ├── tech_detection.json
    │   ├── tech_by_host.txt
    │   └── tech_summary.txt
    ├── 7-dirbrute/
    │   ├── dirbrute.json
    │   └── discoveries.txt
    ├── 8-vulnscan/
    │   ├── vulnerabilities.json
    │   ├── critical.txt
    │   ├── high.txt
    │   └── all_vulnerabilities.txt
    └── 9-aiguided/
        ├── ai_guided.json
        ├── ai_recommendations.txt
        └── ai_vulnerabilities.txt
```

---

## Tools

### Required (installed via `reconator install`)

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
| nuclei | Vulnerability scanning |
| waybackurls | Wayback Machine URLs |
| gau | Get All URLs |
| urlfinder | Passive URL discovery |
| katana | Active web crawling |
| ffuf | Fuzzing / directory bruteforce |
| massdns | High-performance DNS resolver |

### Optional (installed via `reconator install --extras`)

| Tool | Type | Purpose |
|------|:----:|---------|
| cero | Go | CT log subdomain discovery |
| github-subdomains | Go | GitHub subdomain discovery |
| hakrevdns | Go | Reverse DNS from IPs |
| hakip2host | Go | IP to hostname resolution |
| mapcidr | Go | CIDR expansion |
| asnmap | Go | ASN to CIDR/domain discovery |
| favirecon | Go | Favicon hash reconnaissance |
| subzy | Go | Subdomain takeover detection |
| subjack | Go | Subdomain takeover detection |
| gf | Go | URL pattern matching |
| qsreplace | Go | Query string replacement |
| dalfox | Go | XSS scanner |
| hakoriginfinder | Go | Cloudflare bypass |
| cf-hero | Go | Cloudflare origin finder (multiple methods) |
| cvemap | Go | CVE lookup by technology |
| notify | Go | Notifications (Slack, Discord, etc.) |
| waymore | Python | Extended wayback sources |
| xnLinkFinder | Python | JS endpoint extraction |
| findomain | Rust | Fast subdomain enumeration |
| feroxbuster | Rust | Fast directory bruteforce |

---

## Configuration

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for detailed configuration including:
- API key setup (subfinder, chaos, securitytrails, shodan)
- Notification configuration (Slack, Discord, Telegram)
- AI provider setup (OpenAI, Claude, Gemini)
- Custom wordlists and resolvers

---

## Credits

Built with tools from:
- [ProjectDiscovery](https://github.com/projectdiscovery) - subfinder, httpx, dnsx, naabu, nuclei, katana, cdncheck, cvemap, asnmap, notify
- [Trickest](https://github.com/trickest) - mksub, dsieve
- [d3mondev/puredns](https://github.com/d3mondev/puredns)
- [tomnomnom](https://github.com/tomnomnom) - assetfinder, waybackurls, gf
- [lc/gau](https://github.com/lc/gau)
- [hahwul/dalfox](https://github.com/hahwul/dalfox)
- [epi052/feroxbuster](https://github.com/epi052/feroxbuster)

---

## Legal Disclaimer

This tool is for **authorized security testing** and **bug bounty programs** only. Users are responsible for compliance with applicable laws. Unauthorized testing is illegal.

**Always obtain proper authorization before testing.**

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Reconator</b> - Fast reconnaissance for bug bounty hunters
  <br>
  Created by <a href="https://twitter.com/RootSploit">@RootSploit</a>
</p>
