# Reconator Configuration Guide

This guide covers all configuration options for Reconator, including API keys, tool configuration, and notification setup.

---

## Table of Contents

- [Installation](#installation)
- [Unified API Key Management](#unified-api-key-management) **(NEW in v0.1.2)**
- [API Keys Setup](#api-keys-setup)
- [Subfinder Provider Configuration](#subfinder-provider-configuration)
- [AI Provider Configuration](#ai-provider-configuration)
- [Notification Configuration](#notification-configuration)
- [Custom Wordlists and Resolvers](#custom-wordlists-and-resolvers)
- [ExploitDB Integration (Optional)](#exploitdb-integration-optional) **(NEW in v0.1.2)**
- [Command Line Reference](#command-line-reference)
- [Environment Variables](#environment-variables)

---

## Installation

### Quick Install

```bash
# Install reconator binary
go install github.com/rootsploit/reconator@latest

# Install all required tools
reconator install

# Install optional tools (Python/Rust)
reconator install --extras

# Verify installation
reconator check
```

### Manual Tool Installation

If automatic installation fails, install tools manually:

```bash
# Go tools (run each with go install)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
# ... (see full list in README.md)

# Python tools (via pipx)
pipx install waymore
pipx install xnLinkFinder

# Rust tools (via cargo or GitHub releases)
cargo install feroxbuster
# Or download from GitHub releases
```

---

## Unified API Key Management

**New in v0.1.2**: Reconator now provides unified API key management. Configure all your API keys in one place and sync them to tool-specific configs automatically.

### Quick Start

```bash
# Initialize config file (creates template)
reconator config init

# Edit the config file
nano ~/.reconator/config.yaml

# Sync keys to subfinder, notify, etc.
reconator config sync

# Validate your keys
reconator config test

# Show current configuration
reconator config show
```

### Config File Location

```
~/.reconator/config.yaml    # Single source of truth
```

This config is automatically synced to:
- `~/.config/subfinder/provider-config.yaml` (OSINT keys)
- `~/.config/notify/provider-config.yaml` (notification webhooks)

### Example Configuration

```yaml
# ~/.reconator/config.yaml - Single source of truth for ALL keys

# ============================================================================
# AI PROVIDER KEYS (for AI-guided scanning)
# ============================================================================
ai:
  openai:
    - "sk-YOUR_OPENAI_KEY"
  claude:
    - "sk-ant-YOUR_CLAUDE_KEY"
  gemini:
    - "YOUR_GEMINI_KEY"
  groq:
    - "gsk_YOUR_GROQ_KEY"
  deepseek:
    - "sk-YOUR_DEEPSEEK_KEY"
  ollama:
    url: "http://localhost:11434"
    model: "qwen2.5:32b"

# ============================================================================
# PROJECTDISCOVERY CLOUD
# ============================================================================
pdcp_api_key: "pdcp_xxxxxxxxxxxx"

# ============================================================================
# OSINT API KEYS (synced to subfinder)
# ============================================================================
osint:
  securitytrails:
    - "your-securitytrails-key"
  shodan:
    - "your-shodan-key"
  censys:
    - "api_id:api_secret"  # Censys format
  virustotal:
    - "your-virustotal-key"
  github:
    - "ghp_xxxxxxxxxxxx"
  chaos:
    - "pdcp_xxxxxxxxxxxx"

# ============================================================================
# NOTIFICATION PROVIDERS (synced to notify)
# ============================================================================
notify:
  slack:
    - id: "recon-alerts"
      slack_webhook_url: "https://hooks.slack.com/services/XXX/XXX/XXX"
      slack_channel: "recon-alerts"
      slack_username: "reconator"
  discord:
    - id: "recon-alerts"
      discord_webhook_url: "https://discord.com/api/webhooks/XXX/XXX"
```

### Config Command Reference

| Command | Description |
|---------|-------------|
| `reconator config init` | Create template config file |
| `reconator config show` | Display current configuration (keys masked) |
| `reconator config sync` | Sync keys to subfinder, notify configs |
| `reconator config test` | Validate API keys by testing endpoints |
| `reconator config test --osint` | Test only OSINT keys |

### Benefits

| Benefit | Description |
|---------|-------------|
| **Single source of truth** | Configure ALL keys (AI, OSINT, notify) in one file |
| **Auto-create on install** | Config created with key import during `reconator install` |
| **Auto-import** | Imports existing keys from subfinder, notify, ai-config |
| **Auto-sync** | Keys synced to tool configs automatically |
| **Merge approach** | Preserves manual edits in tool configs |
| **Key validation** | Test keys before scanning |
| **Secure storage** | Config file has restricted permissions (0600) |

---

## API Keys Setup

### Why API Keys?

API keys significantly improve subdomain enumeration coverage. Without keys, reconator relies on free sources only. With keys, you can access:
- More subdomain sources via subfinder
- CVE data via cvemap
- AI-guided scanning via OpenAI/Claude/Gemini

### Storage Methods (Similar to ProjectDiscovery)

#### Method 1: Environment Variables (Recommended)

Add to `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
# Subfinder API keys
export SUBFINDER_API_KEYS="securitytrails:xxxx,chaos:xxxx,shodan:xxxx"

# CVEMap API key
export PDCP_API_KEY="your-projectdiscovery-cloud-key"

# AI Provider keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="..."
```

#### Method 2: Provider Config Files

Create `~/.config/subfinder/provider-config.yaml`:

```yaml
# Subfinder Provider Configuration
# See: https://github.com/projectdiscovery/subfinder

# Free sources (no API key needed):
# alienvault, anubis, commoncrawl, crtsh, digitorus, hackertarget, rapiddns, waybackarchive

# API sources:
binaryedge:
  - YOUR_API_KEY

bufferover:
  - YOUR_API_KEY

censys:
  - YOUR_API_KEY:YOUR_SECRET

certspotter:
  - YOUR_API_KEY

chaos:
  - YOUR_PDCP_KEY

github:
  - YOUR_GITHUB_TOKEN

hunter:
  - YOUR_API_KEY

intelx:
  - YOUR_API_KEY

passivetotal:
  - YOUR_EMAIL:YOUR_API_KEY

securitytrails:
  - YOUR_API_KEY

shodan:
  - YOUR_API_KEY

virustotal:
  - YOUR_API_KEY

whoisxmlapi:
  - YOUR_API_KEY

zoomeye:
  - YOUR_API_KEY
```

#### Method 3: Command Line Flags

```bash
# Pass API keys via flags
reconator scan example.com \
  --openai-key "sk-..." \
  --claude-key "sk-ant-..." \
  --gemini-key "..."
```

---

## Subfinder Provider Configuration

### Getting API Keys

| Provider | Get Key | Free Tier |
|----------|---------|-----------|
| SecurityTrails | https://securitytrails.com/app/signup | 50 queries/month |
| Shodan | https://account.shodan.io | Limited |
| Censys | https://censys.io/register | 250 queries/month |
| VirusTotal | https://virustotal.com | 500 queries/day |
| GitHub | GitHub Settings > Developer > Tokens | Free |
| Chaos | https://cloud.projectdiscovery.io | Free with signup |
| BinaryEdge | https://binaryedge.io | Limited |
| IntelX | https://intelx.io | Limited |

### Configuration File Location

```
~/.config/subfinder/provider-config.yaml
```

### Verify Configuration

```bash
# Check subfinder sources
subfinder -ls

# Test with a domain
subfinder -d example.com -silent | wc -l
```

---

## AI Provider Configuration

AI providers are used for smart nuclei template selection and vulnerability chain analysis in Phase 9 (AI-Guided Scanning).

### Supported Providers (Priority Order)

| # | Provider | Environment Variable | Get Key | Notes |
|:-:|----------|---------------------|---------|-------|
| 1 | Ollama | - | https://ollama.com | Local, free, private |
| 2 | Groq | `GROQ_API_KEY` | https://console.groq.com/keys | Fast, free tier |
| 3 | DeepSeek | `DEEPSEEK_API_KEY` | https://platform.deepseek.com/api_keys | Cheap, good |
| 4 | Claude | `ANTHROPIC_API_KEY` | https://console.anthropic.com | Best quality |
| 5 | OpenAI | `OPENAI_API_KEY` | https://platform.openai.com/api-keys | Reliable |
| 6 | Gemini | `GEMINI_API_KEY` | https://aistudio.google.com/apikey | Google AI |

### Smart Provider Selection

Reconator intelligently skips unavailable providers:

| Condition | Behavior |
|-----------|----------|
| **Ollama not running** | Skipped in ~3ms (quick reachability check) |
| **Placeholder keys** | Keys containing `YOUR_` or `_KEY` are skipped |
| **Empty keys** | Providers with no keys are skipped |
| **Rate limited** | Automatically rotates to next key or provider |

This means if you only have OpenAI configured, reconator will use it immediately without waiting for Ollama timeouts.

### Setup Option 1: Unified Config File (Recommended)

Add AI keys to `~/.reconator/config.yaml` (created automatically):

```yaml
# AI section in ~/.reconator/config.yaml
ai:
  # Ollama - Local AI (FREE, PRIVATE)
  # Only used if Ollama is actually running
  ollama:
    url: "http://localhost:11434"
    model: "qwen2.5:32b"

  # Cloud providers - add your keys here
  openai:
    - "sk-your-openai-key"
  claude:
    - "sk-ant-your-claude-key"
  gemini:
    - "your-gemini-key"
  groq:
    - "gsk_your-groq-key"
  deepseek:
    - "sk-your-deepseek-key"
```

### Setup Option 2: Environment Variables

```bash
# Add to ~/.bashrc or ~/.zshrc
export GROQ_API_KEY="gsk_..."
export DEEPSEEK_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="..."

# Reload shell
source ~/.bashrc
```

### Priority Order & Key Rotation

Reconator tries providers in this order:
1. Ollama (local) - if running at localhost:11434
2. Groq (llama-3.1-70b-versatile)
3. DeepSeek (deepseek-chat)
4. Claude (claude-sonnet-4-20250514)
5. OpenAI (gpt-4o-mini)
6. Gemini (gemini-1.5-flash)

**Key Rotation**: On rate limit (429), Reconator automatically tries the next key or provider.

If all fail, it falls back to technology-based default recommendations.

---

## CVEMap Configuration

CVEMap (cvemap) requires a ProjectDiscovery Cloud API key for full functionality.

### Get Free API Key

1. Sign up at https://cloud.projectdiscovery.io
2. Go to Settings > API Keys
3. Generate a new key

### Configure

```bash
# Environment variable
export PDCP_API_KEY="your-key"

# Or via cvemap config
cvemap -auth
```

### Verify

```bash
# Test cvemap
cvemap search "product:nginx && severity:critical" --limit 5
```

---

## Notification Configuration

Reconator uses ProjectDiscovery's `notify` tool for sending alerts.

### Configuration File

Create `~/.config/notify/provider-config.yaml`:

```yaml
# Slack
slack:
  - id: "slack"
    slack_channel: "recon-alerts"
    slack_username: "reconator"
    slack_format: "{{data}}"
    slack_webhook_url: "https://hooks.slack.com/services/XXX/XXX/XXX"

# Discord
discord:
  - id: "discord"
    discord_channel: "recon-alerts"
    discord_username: "reconator"
    discord_format: "{{data}}"
    discord_webhook_url: "https://discord.com/api/webhooks/XXX/XXX"

# Telegram
telegram:
  - id: "telegram"
    telegram_api_key: "YOUR_BOT_TOKEN"
    telegram_chat_id: "YOUR_CHAT_ID"
    telegram_format: "{{data}}"

# Custom webhook
custom:
  - id: "custom"
    custom_webhook_url: "https://your-webhook.com/endpoint"
    custom_method: "POST"
    custom_format: '{"text": "{{data}}"}'
    custom_headers:
      Content-Type: application/json
```

### Get Webhook URLs

#### Slack
1. Go to https://api.slack.com/apps
2. Create New App > From scratch
3. Enable Incoming Webhooks
4. Add New Webhook to Workspace
5. Copy webhook URL

#### Discord
1. Server Settings > Integrations > Webhooks
2. New Webhook
3. Copy Webhook URL

#### Telegram
1. Message @BotFather
2. Create new bot with /newbot
3. Copy API token
4. Get chat ID from @userinfobot

### Enable Notifications

```bash
# Enable notifications for scan
reconator scan example.com --notify

# Use custom config path
reconator scan example.com --notify --notify-config /path/to/config.yaml
```

---

## Custom Wordlists and Resolvers

### Default Locations

```
~/.reconator/wordlists/
├── resolvers.txt              # DNS resolvers
├── subdomain-bruteforce-medium.txt  # 20k wordlist
└── subdomain-bruteforce-small.txt   # 5k wordlist
```

### Custom Wordlists

```bash
# Use custom subdomain wordlist
reconator scan example.com --wordlist /path/to/wordlist.txt

# Use custom resolvers
reconator scan example.com --resolvers /path/to/resolvers.txt
```

### Recommended Wordlists

| Wordlist | Size | Source |
|----------|------|--------|
| SecLists DNS | 110k | https://github.com/danielmiessler/SecLists |
| Assetnote | 300k+ | https://wordlists.assetnote.io |
| Trickest | 20k | https://github.com/trickest/resolvers |

### Recommended Resolvers

```bash
# Download fresh resolvers
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -O ~/.reconator/wordlists/resolvers.txt
```

### Resolver Types

Reconator uses two resolver files:

| File | Count | Used By | Purpose |
|------|-------|---------|---------|
| `resolvers.txt` | ~18k | puredns bruteforce | Wide distribution for DNS bruteforce |
| `trusted-resolvers.txt` | ~25 | dnsx validation | Reliable servers for validation |

The trusted resolvers are auto-created on first scan with reliable public DNS servers (Cloudflare, Google, Quad9, etc.) to prevent false positives during DNS validation.

---

## ExploitDB Integration (Optional)

**New in v0.1.2**: Reconator can query ExploitDB via searchsploit for known exploits matching detected technologies.

### Installation

```bash
# Ubuntu/Debian/Kali
sudo apt update
sudo apt install exploitdb

# Update the exploit database
searchsploit -u
```

### How It Works

When searchsploit is installed, the hybrid CVE detection system will:
1. Query ExploitDB for detected product/version combinations
2. Extract CVE IDs from exploit titles
3. Report available exploits with severity based on type (remote/webapps = high)

### Example Output

```
[HIGH] ExploitDB: PHP 5.6 - Remote Code Execution
  Type: remote | Platform: php
  Exploit path: /usr/share/exploitdb/exploits/php/webapps/12345.py
```

### Verification

```bash
# Test searchsploit is working
searchsploit -j "apache 2.4"
```

---

## Command Line Reference

### Scan Command

```bash
reconator scan [target] [flags]

Flags:
  -t, --target string          Target domain or IP
  -l, --list string            File with list of targets
  -o, --output string          Output directory (default "./results")
  -p, --phases string          Phases to run (default "all")
  -c, --threads int            Concurrency (default 50)
      --dns-threads int        DNS threads (default 100)
  -r, --rate int               Rate limit for port scanning
      --passive                Passive mode only
      --debug                  Debug mode with timing logs
      --skip-validation        Skip DNS validation
      --skip-dirbrute          Skip directory bruteforce
      --skip-vulnscan          Skip vulnerability scanning
      --skip-aiguided          Skip AI-guided scanning
      --notify                 Enable notifications
      --notify-config string   Path to notify config
      --openai-key string      OpenAI API key
      --claude-key string      Claude API key
      --gemini-key string      Gemini API key
      --wordlist string        Custom wordlist path
      --resolvers string       Custom resolvers path
```

### Install Command

```bash
reconator install [flags]

Flags:
      --extras    Install optional tools (Python/Rust)
      --force     Force reinstall all tools
```

### Check Command

```bash
reconator check

# Shows status of all required and optional tools
```

### Config Command

```bash
reconator config [subcommand]

Subcommands:
  init   - Create template config file (~/.reconator/config.yaml)
  show   - Display current configuration (keys masked)
  sync   - Sync API keys to tool configs (subfinder, notify)
  test   - Validate API keys by testing endpoints

Flags (for test):
      --osint   Test only OSINT API keys
      --notify  Test notification webhooks (sends test message)

Examples:
  reconator config init              # Create template
  reconator config show              # Show config
  reconator config sync              # Sync to tools
  reconator config test              # Validate all keys
  reconator config test --osint      # Validate OSINT keys only
```

---

## Environment Variables

### AI Providers

| Variable | Purpose | Example |
|----------|---------|---------|
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `ANTHROPIC_API_KEY` | Claude API key | `sk-ant-...` |
| `GEMINI_API_KEY` | Gemini API key | `...` |
| `GROQ_API_KEY` | Groq API key | `gsk_...` |
| `DEEPSEEK_API_KEY` | DeepSeek API key | `sk-...` |

### OSINT Providers

| Variable | Purpose | Example |
|----------|---------|---------|
| `PDCP_API_KEY` | ProjectDiscovery Cloud key | `pdcp_...` |
| `SHODAN_API_KEY` | Shodan API key | `...` |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key | `...` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | `...` |
| `CENSYS_API_KEY` | Censys API key | `api_id:api_secret` |
| `GITHUB_TOKEN` | GitHub personal access token | `ghp_...` |
| `CHAOS_API_KEY` | Chaos (ProjectDiscovery) key | `pdcp_...` |
| `BINARYEDGE_API_KEY` | BinaryEdge API key | `...` |
| `HUNTER_API_KEY` | Hunter.io API key | `...` |
| `INTELX_API_KEY` | IntelX API key | `...` |
| `URLSCAN_API_KEY` | URLScan API key | `...` |

**Note**: Environment variables override values in `~/.reconator/config.yaml`.

---

## Troubleshooting

### Tool Not Found

```bash
# Check if tool is in PATH
which subfinder

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### API Key Not Working

```bash
# Test subfinder with verbose output
subfinder -d example.com -v

# Test cvemap auth
cvemap -auth -pc
```

### Notifications Not Sending

```bash
# Test notify directly
echo "Test message" | notify -silent

# Check notify config
notify -pc ~/.config/notify/provider-config.yaml
```

---

## Example Configurations

### Minimal Setup (Free Only)

```bash
# No API keys needed, uses free sources only
reconator install
reconator scan example.com --passive
```

### Full Setup

```bash
# ~/.bashrc
export OPENAI_API_KEY="sk-..."
export PDCP_API_KEY="..."

# ~/.config/subfinder/provider-config.yaml
# (configure 3-5 providers)

# ~/.config/notify/provider-config.yaml
# (configure Slack/Discord)

# Run full scan with notifications
reconator scan example.com --notify
```

### CI/CD Setup

```yaml
# GitHub Actions example
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  PDCP_API_KEY: ${{ secrets.PDCP_API_KEY }}

steps:
  - run: |
      go install github.com/rootsploit/reconator@latest
      reconator install
      reconator scan ${{ inputs.target }} --passive --skip-dirbrute
```
