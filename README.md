<h1 align="center">🔍 Reconator</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Reconator-AI--Powered%20Recon-blueviolet?style=for-the-badge&logo=target" alt="Reconator">
</p>

<p align="center">
  <a href="https://github.com/rootsploit/reconator/releases"><img src="https://img.shields.io/github/v/release/rootsploit/reconator?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://github.com/rootsploit/reconator/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/rootsploit/reconator"><img src="https://goreportcard.com/badge/github.com/rootsploit/reconator?style=flat-square" alt="Go Report Card"></a>
  <img src="https://img.shields.io/badge/go-%3E%3D1.21-00ADD8?style=flat-square&logo=go" alt="Go Version">
</p>

<p align="center">
  <a href="docs/USAGE.md">Documentation</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Install</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-comparison">Comparison</a>
</p>

---

## Reconator

Reconator is a reconnaissance framework that combines subdomain enumeration, port scanning, and vulnerability detection into a single automated pipeline. It uses AI to analyze findings and recommend targeted security tests.

- 🧠 **AI-Powered Analysis** - Multi-provider AI (Ollama/Groq/DeepSeek/Claude/OpenAI/Gemini) with auto key rotation
- 📊 **Risk Scoring** - 0-100 attack surface score with prioritized findings
- 🎯 **CVEMap Integration** - Real CVE data mapped to detected technologies
- 💡 **Manual Check Suggestions** - AI suggests SQLi/XSS tests even when automated tools miss them
- ⚡ **Easy to Install** - Single Go binary, run `reconator install --extras` to set up all dependencies

---

## ✨ Features

### 🎯 Core Capabilities

- 🕵️ **Subdomain Enumeration** - subfinder, amass, assetfinder, crt.sh, chaos (30+ sources)
- 🌐 **DNS Resolution** - Fast validation with puredns & dnsx
- ⚡ **Port Scanning** - naabu for speed, httpx for HTTP validation
- 🔍 **Web Crawling** - katana, waybackurls, gau for endpoint discovery
- 🛡️ **WAF/CDN Detection** - Identifies Cloudflare, Akamai + origin IP discovery
- 🎭 **Tech Fingerprinting** - Wappalyzer-based technology detection
- ☠️ **Subdomain Takeover** - subjack, subzy for dangling DNS detection

### 🤖 AI-Powered Intelligence

- 🧠 **Smart Template Selection** - AI analyzes tech stack and picks relevant nuclei templates
- 📋 **CVE Mapping** - Maps detected technologies to known CVEs via CVEMap
- 📊 **Risk Scoring** - 0-100 risk score based on attack surface analysis
- 💡 **Manual Test Suggestions** - Recommends SQLi/XSS tests even when automation fails
- 📝 **Attack Surface Report** - Prioritized findings with effort/impact ratings

### 🔐 Advanced Secrets Scanner

- 🔑 **50+ Token Patterns** - Comprehensive regex-based detection
  - **Cloud**: AWS, GCP, Azure, DigitalOcean, Heroku, Cloudflare
  - **Code**: GitHub PAT/OAuth, GitLab, NPM, PyPI tokens
  - **Payment**: Stripe, Square, PayPal, Braintree API keys
  - **Communication**: Slack, Discord, Telegram, Twilio
  - **AI Services**: OpenAI, Anthropic, Cohere API keys
  - **Generic**: Private keys, JWTs, Database URLs, OAuth secrets

### ☁️ Cloud Storage Security

- 🪣 **S3 Bucket Testing** - Multi-region discovery + permission testing
- 📦 **GCS & Azure Blob** - Bucket enumeration + access verification
- 🔄 **Auto Name Generation** - Creates bucket permutations from target domain

### 🚪 Admin Panel Discovery

- 🔍 **25+ Admin Paths** - `/admin`, `/wp-admin`, `/phpmyadmin`, `/jenkins`, `/grafana`
- 🔐 **Login Form Detection** - Identifies auth types and login pages
- 📄 **Title Extraction** - Grabs page titles for quick identification

### ⚛️ GraphQL Detection

- 🔗 **16 Common Paths** - `/graphql`, `/graphiql`, `/playground`, `/v1/graphql`
- 🔓 **Introspection Testing** - Checks if schema is exposed
- 🎯 **Nuclei Integration** - Runs GraphQL-specific vulnerability templates

### 📸 Visual Recon

- 🖼️ **Screenshot Capture** - gowitness integration for visual evidence
- ⚡ **Parallel Processing** - Fast screenshot collection across all hosts

### 🕵️ OSINT Module

- 🔎 **Google Dork Generator** - 15 dork categories with clickable links
- 🆓 **No API Required** - Works without external API keys

### 📊 Reporting

- 📈 **HTML Dashboard** - Modern, responsive report with dark theme
- 📋 **Executive Summary** - Key metrics at a glance
- ⚠️ **Vulnerability Breakdown** - Critical/High findings highlighted
- 🔍 **Per-Subdomain View** - Ports, tech, vulns per host with search/filter
- 🔗 **Attack Chain Analysis** - AI-identified vulnerability chains
- 📊 **Prioritized Findings** - Ranked by exploitability

---

## 📦 Installation

### Quick Install (Recommended)

```bash
# One-liner install script (Linux/macOS)
curl -sSfL https://raw.githubusercontent.com/rootsploit/reconator/main/scripts/install.sh | bash

# Install all dependencies
reconator install --extras
```

### Using Go

```bash
go install github.com/rootsploit/reconator@latest
reconator install --extras
```

### From Releases

Download pre-built binaries from [GitHub Releases](https://github.com/rootsploit/reconator/releases).

### Docker

```bash
# Pull from Docker Hub
docker pull rootsploit/reconator:latest

# Run a scan
docker run --rm -v $(pwd)/results:/home/reconator/results rootsploit/reconator scan target.com
```

### From Source

```bash
git clone https://github.com/rootsploit/reconator.git
cd reconator
go build -o reconator ./cmd/reconator
./reconator install --extras
```

---

## 🚀 Quick Start

```bash
# Basic scan
reconator scan target.com

# With AI analysis
export OPENAI_API_KEY="sk-..."
reconator scan target.com

# Full featured scan
reconator scan target.com --screenshots --graphql --osint

# Multiple targets
reconator scan -l targets.txt

# Passive mode
reconator scan target.com --passive
```

---

## 📊 Comparison

| Feature | Reconator | reconFTW | FinalRecon |
|---------|:---------:|:--------:|:----------:|
| **AI Analysis** | ✅ GPT-4/Claude/Gemini | ❌ | ❌ |
| **CVE Intelligence** | ✅ CVEMap | nuclei only | ❌ |
| **Risk Scoring** | ✅ 0-100 | ❌ | ❌ |
| **Secret Detection** | ✅ 50+ patterns | JS only | ❌ |
| **Cloud Storage** | ✅ S3/GCS/Azure | S3 only | ❌ |
| **Admin Panels** | ✅ 25+ paths | ❌ | Dir brute |
| **GraphQL Detection** | ✅ 16 paths | ❌ | ❌ |
| **Screenshot Capture** | ✅ gowitness | gowitness | ❌ |
| **OSINT Dorks** | ✅ 15 categories | ✅ | ❌ |
| **HTML Reports** | ✅ | ✅ | ❌ |
| **Subdomain Sources** | 30+ | 30+ | 10+ |
| **Single Binary** | ✅ Go | Bash scripts | Python |

---

## 🖥️ Platform Support

| Platform | Status |
|----------|:------:|
| Linux (Ubuntu, Debian, Fedora, Arch) | ✅ Full |
| macOS (Intel + Apple Silicon) | ✅ Full |
| Windows (WSL recommended) | ⚠️ Partial |

---

## 🙏 Credits

Built with tools from:
- [ProjectDiscovery](https://github.com/projectdiscovery) - nuclei, subfinder, httpx, naabu, katana
- [tomnomnom](https://github.com/tomnomnom) - waybackurls, assetfinder
- [hahwul](https://github.com/hahwul) - dalfox
- [OWASP](https://github.com/OWASP) - amass
- [sensepost](https://github.com/sensepost) - gowitness

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create your feature branch
3. Submit a pull request

**Found this useful?** A star helps others discover Reconator.

---

## ⚖️ Legal

**For authorized security testing only.** Always obtain written authorization before scanning.

---

## 📄 License

AGPL-3.0 - See [LICENSE](LICENSE)

---

<p align="center">
  <b>Created by <a href="https://twitter.com/RootSploit">@RootSploit</a></b>
</p>
