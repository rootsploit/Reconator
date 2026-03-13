# Usage Guide

Complete usage documentation for Reconator.

---

## Table of Contents

- [Scanning Pipeline](#scanning-pipeline)
- [Basic Scanning](#basic-scanning)
- [Input Types](#input-types)
- [Phase Selection](#phase-selection)
- [Scan Modes](#scan-modes)
- [Performance Tuning](#performance-tuning)
- [AI-Guided Scanning](#ai-guided-scanning)
- [Notifications](#notifications)
- [Distributed Scanning (Fleet)](#distributed-scanning-fleet)
- [IP Rotation](#ip-rotation)
- [Attack Path Analysis](#attack-path-analysis)
- [Output Structure](#output-structure)
- [Command Reference](#command-reference)
  - [scan](#reconator-scan)
  - [webscan](#reconator-webscan)
  - [report](#reconator-report)
  - [export](#reconator-export)
  - [install](#reconator-install)
  - [check](#reconator-check)
  - [update](#reconator-update)
  - [server](#reconator-server)
  - [monitor](#reconator-monitor)
  - [fleet](#reconator-fleet)
  - [iprotate](#reconator-iprotate)
- [Examples](#examples)
- [Changelog](#changelog)

---

## Scanning Pipeline

Reconator executes phases in optimized parallel groups (levels) for maximum speed.

```mermaid
flowchart TB
    START([Start])

    subgraph Level0["Level 0 - Entry Points"]
        IP["[0] IP Range<br/><i>ASN/CIDR only</i>"] ~~~ SUB["[1] Subdomain<br/>Enumeration"] ~~~ HIST["[6] Historic<br/>URLs"]
    end

    subgraph Level1["Level 1 - Analysis"]
        WAF["[2] WAF/CDN<br/>Detection"] ~~~ TAKE["[5] Subdomain<br/>Takeover"]
    end

    subgraph Level2["Level 2 - Port Discovery"]
        PORTS["[3] Port Scan + TLS"]
    end

    subgraph Level3["Level 3 - Deep Analysis"]
        TECH["[7] Tech<br/>Detection"] ~~~ DIR["[8] Directory<br/>Bruteforce"] ~~~ SCREEN["[10] Screenshot<br/>Capture"] ~~~ VHOST["[4] VHost<br/>Discovery"]
    end

    subgraph Level4["Level 4 - Vulnerability Scan"]
        VULN["[9] Vulnerability Scanning"]
    end

    subgraph Level5["Level 5 - AI Analysis"]
        AI["[11] AI-Guided Scanning"]
    end

    DONE([Done])

    START --> Level0
    Level0 --> Level1
    Level1 --> Level2
    Level2 --> Level3
    Level3 --> Level4
    Level4 --> Level5
    Level5 --> DONE
```

### Phase Dependencies

```mermaid
flowchart LR
    subgraph Independent["No Dependencies"]
        HIST["[6] Historic"]
    end

    IP["[0] IPRange"] -->|TLDs for ASN| SUB["[1] Subdomain"]
    SUB -->|subdomains| WAF["[2] WAF"]
    SUB -->|subdomains| TAKE["[5] Takeover"]
    SUB -->|subdomains| PORTS["[3] Ports"]

    PORTS -->|alive hosts| TECH["[7] Tech"]
    PORTS -->|alive hosts| DIR["[8] DirBrute"]
    PORTS -->|alive hosts| SCREEN["[10] Screenshot"]
    PORTS -->|IPs| VHOST["[4] VHost"]

    TECH -->|tech data| VULN["[9] VulnScan"]
    VULN -->|all findings| AI["[11] AIGuided"]
```

### Phase Details

| Phase | Name | Tools | Output |
|:-----:|------|-------|--------|
| **0** | IP Range Discovery | asnmap, whois, hakip2host | IPs, TLDs |
| **1** | Subdomain Enumeration | subfinder, assetfinder, findomain, puredns, alterx, mksub, dnsx, tlsx | Validated subdomains |
| **2** | WAF/CDN Detection | cdncheck, hakoriginfinder | CDN hosts, direct hosts, origin IPs |
| **3** | Port Scanning | naabu, tlsx | Open ports, TLS info, alive hosts |
| **4** | VHost Discovery | ffuf, tlsx | Virtual hosts |
| **5** | Subdomain Takeover | nuclei, subzy, subjack | Vulnerable takeovers |
| **6** | Historic URLs | waybackurls, gau, waymore, urlfinder, uro, gf | URLs, JS files, params |
| **7** | Tech Detection | httpx | Technologies, versions |
| **8** | DNS & Email Security | dig, nslookup, nuclei | SPF/DKIM/DMARC, CAA/DNSSEC/AXFR, security scores |
| **9** | Directory Bruteforce | feroxbuster, gobuster, ffuf | Hidden paths, admin panels |
| **10** | Vulnerability Scan | nuclei, dalfox, sxss, searchsploit | Vulnerabilities, XSS, CVEs |
| **11** | Screenshot Capture | gowitness | Screenshots, clusters |
| **12** | AI-Guided Scanning | OpenAI/Claude/Gemini + nuclei | CVE analysis, attack chains |

### Key Optimizations

- **Level 0**: Historic runs parallel with Subdomain (no dependency)
- **Level 1**: WAF + Takeover run parallel (both need subdomains, independent of each other)
- **Level 3**: Tech + DirBrute + Screenshot + VHost run parallel (all need ports, independent)
- **Tech-aware VulnScan**: Uses detected technologies to select relevant nuclei templates
- **CDN filtering**: Non-CDN hosts get priority in vuln scanning (3x more vulns found)

---

## Basic Scanning

```bash
# Single domain
reconator scan example.com

# Multiple domains from file
reconator scan -l domains.txt

# Custom output directory
reconator scan example.com -o ./output
```

---

## Input Types

### Domain

```bash
reconator scan example.com
```

### IP Address

```bash
# Discovers domains via reverse DNS + TLS certificates
reconator scan 192.168.1.1
```

### CIDR Range

```bash
# Expands CIDR and discovers all associated domains
reconator scan 10.0.0.0/24
```

### ASN

```bash
# Discovers CIDR ranges + domains via asnmap
reconator scan AS13335

# Also accepts without AS prefix
reconator scan 15169
```

---

## Phase Selection

### Run All Phases

```bash
reconator scan example.com -p all
```

### Run Specific Phases

```bash
reconator scan example.com -p subdomain,ports,takeover
```

### Available Phases

| Phase | Name | Description |
|-------|------|-------------|
| `subdomain` | Subdomain enumeration | 30+ passive sources + DNS bruteforce |
| `waf` | WAF/CDN detection | Identifies CDN-protected vs direct hosts |
| `ports` | Port scanning | naabu + httpx probing |
| `takeover` | Subdomain takeover | Checks for dangling DNS |
| `historic` | Historic URL collection | wayback, gau, katana crawling |
| `tech` | Technology detection | Wappalyzer fingerprinting |
| `dirbrute` | Directory bruteforce | feroxbuster/ffuf |
| `vulnscan` | Vulnerability scanning | nuclei + dalfox |
| `aiguided` | AI-guided scanning | CVEMap + AI recommendations |
| `graphql` | GraphQL detection | 16 common paths + introspection |
| `osint` | OSINT dorks | Google dork generation |

---

## Scan Modes

### Passive Mode

No active scanning, no port scanning, no crawling. Safe for stealth recon.

```bash
reconator scan example.com --passive
```

### Full Featured Scan

```bash
reconator scan example.com --screenshots --graphql --osint
```

### Skip Specific Phases

```bash
reconator scan example.com --skip-dirbrute --skip-vulnscan --skip-aiguided
```

### Debug Mode

Detailed timing logs for performance analysis.

```bash
reconator scan example.com --debug
```

### Silent Mode

Suppress all banner and progress output. Useful for scripting and automation.

```bash
reconator scan example.com --silent
```

### Subdomains Only Mode

Run only the subdomain enumeration phase and output just the list of subdomains. Fastest way to get subdomain list.

```bash
reconator scan example.com --subs-only
```

### Quick Mode

Fast scan that skips slow phases: directory bruteforce, full vuln scan, DNS bruteforce, and permutations. Combines well with `--subs-only` for fastest subdomain enumeration.

```bash
reconator scan example.com --quick
```

### Ultra-Fast Subdomain Enumeration

Combine `--subs-only --quick --silent` for fastest possible subdomain enumeration (~30 seconds):

```bash
reconator scan example.com --subs-only --quick --silent
```

---

## Performance Tuning

### Concurrency

Controls parallel threads for subfinder, naabu, httpx, katana.

```bash
reconator scan example.com -c 100
```

### DNS Threads

Specifically for puredns/dnsx DNS resolution.

```bash
reconator scan example.com --dns-threads 200
```

### Rate Limiting

For port scanning (packets per second).

```bash
reconator scan example.com -r 50
```

### Skip DNS Validation

Faster but may include dead subdomains.

```bash
reconator scan example.com --skip-validation
```

---

## AI-Guided Scanning

### Multi-Provider AI Support

Reconator supports multiple AI providers with automatic failover and key rotation:

| Priority | Provider | Model | Notes |
|:--------:|----------|-------|-------|
| 1 | Ollama | kimi-k2 (local) | Local, free, private |
| 2 | Minimax | MiniMax-M2.5 | Cost-effective, multilingual |
| 3 | Kimi (Moonshot) | kimi-k2.5 | Advanced reasoning |
| 4 | Groq | llama-3.3-70b | Fast, generous free tier |
| 5 | DeepSeek | deepseek-chat | Cheap, good quality |
| 6 | Claude | claude-sonnet-4 | Best for security analysis |
| 7 | OpenAI | gpt-4o-mini | Reliable fallback |
| 8 | Gemini | gemini-1.5-flash | Google AI |

### Configuration

**Option 1: Config File (Recommended)**

Create `~/.reconator/ai-config.yaml`:

```yaml
providers:
  - name: ollama
    endpoint: "http://localhost:11434"
    model: "qwen2.5:32b"
    keys: []

  - name: groq
    keys: ["gsk_YOUR_KEY"]
    model: "llama-3.1-70b-versatile"
    rpm_limit: 30

  - name: claude
    keys: ["sk-ant-YOUR_KEY"]
    model: "claude-sonnet-4-20250514"
    rpm_limit: 50
```

**Option 2: Environment Variables**

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="..."
export GROQ_API_KEY="gsk_..."
export DEEPSEEK_API_KEY="sk-..."
```

### How It Works

1. Collects technology fingerprints from scan results
2. Queries CVEMap for relevant CVEs
3. Uses AI to analyze context and recommend nuclei templates
4. Runs targeted scans based on AI recommendations
5. Generates attack surface report with risk score (0-100)
6. Identifies vulnerability chains for combined exploitation
7. Auto-rotates API keys on rate limit (429 errors)

---

## Notifications

All notification config is in the unified `~/.reconator/config.yaml`. If you already have ProjectDiscovery notify configs, run `reconator config sync` to import them.

### Enable Notifications

```bash
reconator scan example.com --notify
```

### Supported Providers

| Provider | Configuration |
|----------|---------------|
| Slack | Webhook URL |
| Discord | Webhook URL |
| Telegram | Bot token + Chat ID |
| Custom | Webhook URL |

### Configuration (`~/.reconator/config.yaml`)

```yaml
notify:
  slack:
    - id: "recon-alerts"
      slack_webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
      slack_channel: "recon-alerts"
  discord:
    - id: "recon-alerts"
      discord_webhook_url: "https://discord.com/api/webhooks/XXX/XXX"
  telegram:
    - id: "recon-alerts"
      telegram_api_key: "BOT_TOKEN"
      telegram_chat_id: "CHAT_ID"
```

### Importing from ProjectDiscovery notify

If you already have `~/.config/notify/provider-config.yaml` configured:

```bash
# Import existing notify config into unified config
reconator config sync
```

This imports Slack, Discord, and Telegram webhooks from the ProjectDiscovery notify format into `~/.reconator/config.yaml`.

---

## Distributed Scanning

Distribute reconnaissance across multiple cloud workers. One command provisions instances, installs tools, runs the scan, consolidates results, and tears down infrastructure.

### Quick Start (Recommended)

```bash
# AWS — auto-provisions EC2 instances, scans, consolidates, tears down
reconator scan target.com --distributed --provider=aws

# AWS with spot instances and 5 workers
reconator scan target.com --distributed --provider=aws --spot -w 5

# DigitalOcean
reconator scan target.com --distributed --provider=digitalocean --api-key=$DO_TOKEN

# Multiple targets distributed across workers
reconator scan -l targets.txt --distributed --provider=aws -w 10
```

That's it. No separate fleet create/destroy steps. Workers are provisioned, used, and destroyed automatically.

### Distributed Scan Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--distributed` | `false` | Enable distributed scanning |
| `--provider` | `digitalocean` | Cloud provider: `aws`, `digitalocean` |
| `--workers` / `-w` | `3` | Number of cloud workers to provision |
| `--spot` | `false` | Use AWS spot/preemptible instances |
| `--region` | auto | Cloud region for workers |
| `--size` | auto | Instance size (e.g., `t3.micro`, `s-1vcpu-1gb`) |
| `--api-key` | env var | Cloud provider API key (or use `DO_TOKEN`/AWS env vars) |
| `--ssh-key` | | SSH private key path for connecting to workers |
| `--ssh-key-id` | | Pre-uploaded SSH key ID in cloud provider |
| `--setup-cmd` | auto | Custom setup command for workers |

### Configuration via `~/.reconator/config.yaml`

Instead of passing flags every time, set defaults in your config:

```yaml
fleet:
  provider: aws             # or "digitalocean"
  workers: 5
  spot_enabled: true
  region: us-east-1
  size: t3.micro
  ssh_key_file: ~/.ssh/id_rsa
  ssh_key_id: reconator     # Pre-uploaded key ID in cloud provider
  # api_key: $DO_TOKEN      # For DigitalOcean (or set in environment)
```

Then just run:

```bash
reconator scan target.com --distributed
```

All settings are pulled from config.

### Cloud Provider Setup

**AWS EC2:**
1. Install AWS CLI: `brew install awscli` or `apt install awscli`
2. Configure credentials: `aws configure`
3. Create or import an SSH key pair: `aws ec2 import-key-pair --key-name reconator --public-key-material fileb://~/.ssh/id_rsa.pub`
4. (Optional) Create a security group allowing SSH: `aws ec2 create-security-group --group-name reconator --description "Reconator fleet"`

**DigitalOcean:**
1. Get API token from https://cloud.digitalocean.com/account/api/tokens
2. Upload SSH key: `doctl compute ssh-key import reconator --public-key-file ~/.ssh/id_rsa.pub`
3. Note the SSH key ID: `doctl compute ssh-key list`

### Advanced: Persistent Fleet Management

For advanced users who want persistent fleets or custom SSH backends, use the `fleet` command directly:

```bash
# Create fleet with pre-existing SSH hosts
reconator fleet create --backend=ssh \
  --hosts=10.0.0.1,10.0.0.2 \
  --ssh-key=~/.ssh/id_rsa

# Fleet status
reconator fleet status

# Destroy (shows cleanup commands)
reconator fleet destroy
```

---

## IP Rotation

Transparent per-request IP rotation using AWS API Gateway. Each request gets a different source IP from AWS's pool. Based on the [fireprox/IP Rotate technique](https://rhinosecuritylabs.com/aws/bypassing-ip-based-blocking-aws/).

### Quick Start (Recommended)

Just add `--iprotate` to your scan command:

```bash
# Scan with IP rotation — auto-deploys gateways, scans, tears down
reconator scan target.com --iprotate

# With specific AWS regions
reconator scan target.com --iprotate --iprotate-regions=us-east-1,us-west-2,eu-west-1

```

No separate start/stop commands needed. Gateways are deployed before the scan and automatically torn down after.

### IP Rotation Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--iprotate` | `false` | Enable IP rotation via AWS API Gateway |
| `--iprotate-regions` | 10 default regions | Comma-separated AWS regions |

### How It Works

```
Your Machine -> Local Proxy (127.0.0.1:8888)
                  | Round-robin
    -> API Gateway (us-east-1) -> Target  [IP: 3.x.x.x]
    -> API Gateway (us-west-2) -> Target  [IP: 44.x.x.x]
    -> API Gateway (eu-west-1) -> Target  [IP: 52.x.x.x]
    -> ... (10 regions)
```

Each AWS region has a large IP pool. Even within one region, consecutive requests may get different IPs. The `HTTP_PROXY` environment variable is set automatically for all child tools.

### Configuration via `~/.reconator/config.yaml`

```yaml
iprotate:
  regions:
    - us-east-1
    - us-east-2
    - us-west-1
    - us-west-2
    - eu-west-1
    - eu-west-2
    - eu-central-1
    - ap-southeast-1
    - ap-northeast-1
    - ap-south-1
```

### Requirements

- **AWS CLI** installed and configured (`aws configure`)
- **IAM permissions**: `apigateway:*` (CreateRestApi, DeleteRestApi, etc.)

### Advanced: Standalone IP Rotation

For advanced users who want a standalone rotating proxy (e.g., for use with other tools):

```bash
# Start standalone proxy
reconator iprotate start --target https://target.com

# Configure tools manually
export HTTP_PROXY=http://127.0.0.1:8888

# Cleanup
reconator iprotate stop
```

---

## Attack Path Analysis

Reconator v2 includes Graph-of-Thought vulnerability chaining that connects individual findings into multi-step exploitation paths.

### How It Works

After vulnerability scanning, the AI-guided phase:
1. **Classifies** each vulnerability by role (Entry, Pivot, Escalation, Terminal)
2. **Constructs** an attack graph using 12 predefined patterns + AI-discovered chains
3. **Finds** all paths from Entry to Terminal nodes
4. **Scores** paths by impact, likelihood, and exploitability
5. **Generates** human-readable attack narratives

### Attack Roles

| Role | Color | Description | Example |
|------|-------|-------------|---------|
| Entry | Red | Externally accessible attack vector | Open redirect, SSRF, XSS |
| Pivot | Orange | Lateral movement enabler | Internal API access, session hijack |
| Escalation | Yellow | Privilege escalation vector | IDOR, broken auth, path traversal |
| Terminal | Purple | Final objective | RCE, data exfiltration, account takeover |

### Example Chain

```
[SSRF] -> [Cloud Metadata Access] -> [AWS Credentials Leak] -> [S3 Data Exfiltration]
 Entry         Pivot                    Escalation               Terminal
```

### Interactive Visualization

The HTML report includes a force-directed graph:
- Click a path name to highlight its edges
- Hover over nodes for vulnerability details
- Each path gets a unique color
- No external JavaScript dependencies (self-contained SVG)

### Viewing Attack Paths

Attack paths appear in:
- **Terminal output** during scan (summary count)
- **HTML report** in the "Attack Paths" tab with interactive graph
- **JSON output** (`--json` flag) as structured path data

---

## Output Structure

Each scan creates a structured output directory:

```
results/target.com/
├── report_target.com.html          # 📊 HTML Dashboard Report
├── google_dorks.md                 # 🕵️ OSINT Google Dorks
├── summary.json                    # Scan metadata and statistics
│
├── 0-iprange/                      # IP/ASN Discovery
│   ├── ip_discovery.json
│   ├── ips.txt
│   └── domains.txt
│
├── 1-subdomains/                   # Subdomain Enumeration
│   ├── subdomains.json
│   ├── subdomains.txt              # Validated subdomains
│   └── all_subdomains.txt          # All discovered
│
├── 2-waf/                          # WAF/CDN Detection
│   ├── waf_detection.json
│   ├── cdn_hosts.txt
│   └── direct_hosts.txt
│
├── 3-ports/                        # Port Scanning
│   ├── port_scan.json
│   ├── open_ports.txt
│   ├── alive_hosts.txt
│   └── tls_info.json
│
├── 4-takeover/                     # Subdomain Takeover
│   ├── takeover.json
│   └── vulnerable.txt
│
├── 5-historic/                     # Historic URLs
│   ├── historic_urls.json
│   ├── urls.txt
│   ├── categorized_urls.json       # XSS/SQLi/SSRF prone
│   └── endpoints.txt
│
├── 6-tech/                         # Technology Detection
│   ├── tech_detection.json
│   ├── tech_by_host.txt
│   └── tech_summary.txt
│
├── 7-dirbrute/                     # Directory Bruteforce
│   ├── dirbrute.json
│   └── discoveries.txt
│
├── 8-vulnscan/                     # Vulnerability Scanning
│   ├── vulnerabilities.json
│   ├── secrets.json                # 🔐 Detected secrets
│   ├── cloud_storage.json          # ☁️ S3/GCS/Azure buckets
│   ├── admin_panels.json           # 🚪 Admin panels
│   ├── critical.txt
│   ├── high.txt
│   └── all_vulnerabilities.txt
│
├── 9-aiguided/                     # AI-Guided Analysis
│   ├── ai_guided.json
│   ├── ai_recommendations.txt
│   ├── ai_vulnerabilities.txt
│   └── attack_surface_report.txt   # 📋 Risk score + priorities
│
└── screenshots/                    # Screenshot Capture
    └── *.png
```

> **Note:** GraphQL detection results are stored in `8-vulnscan/` folder alongside other vulnerability findings.
```

### Output Formats

| Format | Use Case |
|--------|----------|
| **JSON** | Complete structured data for programmatic access |
| **TXT** | Line-separated lists for piping to other tools |
| **HTML** | Executive report for sharing |
| **Markdown** | OSINT dorks with clickable links |

---

## Command Reference

### `reconator scan`

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output directory | `./results` |
| `--list` | `-l` | File containing targets | - |
| `--phases` | `-p` | Phases to run | `all` |
| `--passive` | - | Passive mode only | `false` |
| `--quick` | - | Quick mode: skip slow phases (dir brute, vuln scan, DNS validation) | `false` |
| `--subs-only` | - | Subdomains only: run subdomain phase only and output just the list | `false` |
| `--silent` | - | Silent mode: suppress banner and progress output | `false` |
| `--threads` | `-c` | Thread count (0=auto) | `0` |
| `--dns-threads` | - | DNS resolver threads (0=auto) | `0` |
| `--rate` | `-r` | Rate limit (pps, 0=auto) | `0` |
| `--skip-validation` | - | Skip DNS validation | `false` |
| `--no-dns-brute` | - | Skip DNS bruteforce & permutations (keeps passive enum + validation) | `false` |
| `--no-screenshots` | - | Disable screenshot capture | `false` |
| `--no-graphql` | - | Disable GraphQL detection | `false` |
| `--no-osint` | - | Disable OSINT dorks | `false` |
| `--no-ai` | - | Disable AI-guided scanning | `false` |
| `--no-report` | - | Disable HTML report generation | `false` |
| `--deep` | - | Deep vuln scan with all templates | `false` |
| `--nuclei-tags` | - | Custom nuclei tags (comma-separated) | - |
| `--notify` | - | Enable notifications | `false` |
| `--notify-config` | - | Notify config path | - |
| `--debug` | - | Enable debug logging | `false` |
| `--iprotate` | - | Enable IP rotation via AWS API Gateway | `false` |
| `--iprotate-regions` | - | AWS regions for IP rotation | 10 default |
| `--distributed` | - | Distribute scan across cloud workers | `false` |
| `--provider` | - | Cloud provider: aws, digitalocean | `digitalocean` |
| `--workers` / `-w` | - | Number of cloud workers | `3` |
| `--spot` | - | Use spot/preemptible instances (AWS) | `false` |
| `--api-key` | - | Cloud provider API key | env var |
| `--ssh-key` | - | SSH key path for workers | - |

### AI Integration Flags

| Flag | Description |
|------|-------------|
| `--json-progress` | Output structured JSON with progress updates (for AI agents) |
| `--progress-file` | Write progress to specified JSON file |
| `--watch` | Watch output directory for incremental results |
| `--mcp` | Run as MCP server (stdin/stdout JSON-RPC) |

### `reconator install`

| Flag | Description |
|------|-------------|
| `--extras` | Install optional Python/Rust tools |

### `reconator check`

Verifies all required tools are installed and working.

### `reconator update`

Update reconator to the latest version from GitHub releases.

```bash
# Check for updates and install
reconator update

# Force update even if already on latest version
reconator update --force

# Rollback to previous version from backup
reconator update --rollback
```

**Features:**
- ✅ Automatic version checking from GitHub releases
- ✅ SHA256 checksum verification for security
- ✅ Progress bar during download
- ✅ Automatic backup of current binary (saved as `reconator.old`)
- ✅ Rollback support if update fails
- ✅ Release notes preview before updating
- ✅ User confirmation before replacing binary

**Update Process:**
1. Checks GitHub API for latest release
2. Compares versions using semantic versioning
3. Downloads binary for your OS/architecture
4. Verifies SHA256 checksum (if available)
5. Creates backup of current binary
6. Replaces binary with new version
7. Verifies installation

| Flag | Description | Default |
|------|-------------|---------|
| `--force` | Force update even if already on latest version | `false` |
| `--rollback` | Restore previous version from backup | `false` |

**Example Output:**
```
Reconator Auto-Updater
═════════════════════

Current version: v1.1.0
Checking for updates...

New version available: v1.1.0 → v1.2.0
Download size: 8.5 MB

Release Notes:
─────────────
- Add CloudFront CDN detection
- Add auto-update feature
- Fix AI prompt optimization

Do you want to update? [Y/n]: y

Downloaded: 8.5 MB / 8.5 MB (100%)
Verifying checksum...
✓ Checksum verified
Installing update...
✓ Successfully updated to v1.2.0
  Backup saved: /usr/local/bin/reconator.old

═════════════════════
Update completed successfully!

The old version has been saved as a backup.
If you experience any issues, you can rollback with:
  reconator update --rollback
```

**Rollback Example:**
```bash
$ reconator update --rollback
Rolling back from backup: /usr/local/bin/reconator.old
✓ Successfully rolled back to previous version
```

### `reconator webscan`

Run vulnerability scanning on a single URL (DAST mode).

```bash
# Basic single URL scan
reconator webscan https://example.com

# Deep scan with all nuclei templates
reconator webscan https://api.example.com/v1 --deep

# Fast mode (skip tech detection, run nuclei -as only)
reconator webscan https://example.com --fast

# Custom nuclei tags
reconator webscan https://example.com --nuclei-tags "cve,rce,sqli"
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--deep` | - | Deep scan with all nuclei templates | `false` |
| `--fast` | - | Fast mode: skip tech detection, run nuclei -as only | `false` |
| `--nuclei-tags` | - | Custom nuclei tags (comma-separated) | - |
| `--nuclei-timeout` | - | Nuclei timeout in minutes | `10` (fast), `30` (deep) |
| `--output` | `-o` | Output directory | `./results` |
| `--threads` | `-c` | Concurrent threads (0=auto) | `0` |
| `--screenshots` | - | Capture screenshots | `false` |
| `--debug` | - | Show detailed timing logs | `false` |

### `reconator report`

Regenerate HTML report from existing scan results.

```bash
# Regenerate report for a target
reconator report ./results/example.com

# Regenerate for ASN scan results
reconator report ./results/AS13335
```

Use this when you need to:
- Recreate a deleted report
- Generate a fresh report after manual data modifications
- Fix a corrupted report file

### `reconator export`

Export scan results to various formats for integration with other tools.

```bash
# Export to all formats (CSV, JSON, Markdown)
reconator export ./results/example.com

# Export only CSV files
reconator export ./results/example.com --format csv

# Export structured JSON
reconator export ./results/example.com --format json

# Export Markdown summary
reconator export ./results/example.com --format markdown
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--format` | `-f` | Export format: csv, json, markdown, all | `all` |

**Export Formats:**

| Format | Output | Use Case |
|--------|--------|----------|
| `csv` | Multiple CSV files | Spreadsheet analysis, data processing |
| `json` | Complete structured data | API integration, custom tooling |
| `markdown` | Summary report | Documentation, sharing |
| `all` | All formats | Comprehensive export |

### `reconator server`

Start the web dashboard server for real-time scan management and visualization.

```bash
# Start server on default port (8888)
reconator server

# Start on custom port
reconator server --port 9000

# Generate and use API key for authentication
reconator server --gen-key

# Allow external connections (use with caution!)
reconator server --host 0.0.0.0

# Use specific API key
reconator server --api-key YOUR_SECRET_KEY
```

**Features:**
- 🎯 Real-time scan progress with WebSocket updates
- 📊 Interactive dashboard with vulnerability statistics
- 🔍 Browse and filter scan results
- 📥 Export results (CSV, JSON, SARIF, HTML)
- ⚙️ Configure API keys for OSINT and AI providers
- 🔐 Optional API key authentication
- 🔄 Automatic JWT key rotation on restart (invalidates stale sessions)
- 🛡️ Built-in security (rate limiting, CORS, CSP headers)

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--port` | `-p` | Server port | `8888` |
| `--host` | `-h` | Server host (use `0.0.0.0` for external access) | `127.0.0.1` |
| `--api-key` | | API key for authentication | none |
| `--gen-key` | | Generate random API key | `false` |

**Access:**
1. Start the server: `reconator server`
2. Open browser: http://127.0.0.1:8888
3. Login with credentials (username: `reconator`, password: API key)
4. Manage scans, view results, configure API keys

**Security Notes:**
- By default, server binds to `127.0.0.1` (localhost only)
- Set `--host 0.0.0.0` to allow external connections
- Always use `--api-key` or `--gen-key` for production deployments
- API keys are stored securely in `~/.reconator/config.yaml` (0600 permissions)
- JWT authentication keys are automatically rotated on server restart for enhanced security
- All existing browser sessions are invalidated when the server restarts

### `reconator monitor`

Monitor attack surface changes over time. Performs periodic scans and alerts when changes are detected (new subdomains, ports, vulnerabilities, etc.).

```bash
# Monitor target every 24 hours
reconator monitor target.com --interval 24h

# Monitor with Slack notifications
reconator monitor target.com --interval 6h --slack https://hooks.slack.com/...

# Single comparison scan (no continuous monitoring)
reconator monitor target.com --once

# Monitor multiple targets
reconator monitor -l targets.txt --interval 12h
```

**Detects:**
- 🆕 New subdomains discovered
- 🔌 New open ports detected
- 🐛 New vulnerabilities found
- ⚠️ Subdomain takeover opportunities
- 🔧 Technology stack changes

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--interval` | | Scan interval (e.g., 6h, 12h, 24h) | `24h` |
| `--once` | | Single comparison scan | `false` |
| `--slack` | | Slack webhook URL for alerts | none |
| `--discord` | | Discord webhook URL for alerts | none |
| `--webhook` | | Custom webhook URL for alerts | none |

### `reconator fleet`

Advanced fleet management. Most users should use `reconator scan --distributed` instead.

```bash
reconator fleet create [flags]    # Create and initialize workers
reconator fleet destroy           # Show cleanup commands
reconator fleet status            # Show fleet status
```

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `local` | Fleet backend: local, ssh |
| `--workers` / `-w` | `1` | Number of workers |
| `--hosts` | | Comma-separated SSH hosts |
| `--ssh-user` | `root` | SSH username |
| `--ssh-key` | | SSH private key path |
| `--ssh-port` | `22` | SSH port |
| `--provider` | | Cloud provider: digitalocean, aws |
| `--api-key` | | Cloud provider API key |
| `--region` | | Cloud region |
| `--size` | | Instance size |
| `--spot` | `false` | Use AWS spot instances |
| `--setup-cmd` | | Post-provision setup command |

### `reconator iprotate`

IP rotation via AWS API Gateway.

```bash
reconator iprotate start [flags]  # Deploy gateways and start proxy
reconator iprotate stop           # Show cleanup commands
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` / `-t` | (required) | Target base URL |
| `--port` / `-p` | `8888` | Local proxy listen port |
| `--regions` | 10 default regions | Comma-separated AWS regions |

### `reconator version`

Display version information.

```bash
reconator version
```

---

## Examples

### Bug Bounty Quick Scan

```bash
reconator scan target.com -p subdomain,ports,takeover,vulnscan
```

### Full Reconnaissance

```bash
reconator scan target.com -p all -c 100 --screenshots --graphql --osint --notify
```

### Passive Recon Only

```bash
reconator scan target.com --passive
```

### ASN Investigation

```bash
reconator scan AS13335 -p all
```

### High-Speed Scan

```bash
reconator scan target.com -c 200 --dns-threads 300 -r 200 --skip-validation
```

### Distributed Scan (AWS)

```bash
reconator scan target.com --distributed --provider=aws --spot -w 5
```

### Distributed Scan (DigitalOcean)

```bash
reconator scan -l targets.txt --distributed --provider=digitalocean --api-key=$DO_TOKEN -w 3
```

---

## Changelog

### v2.1.0 - MCP Integration & Progress Streaming

**New Features:**
- **Native MCP Server**: Run Reconator as MCP server for AI agent integration
  - Flag: `--mcp` - stdin/stdout JSON-RPC communication
  - Supports: initialize, tools/list, tools/call, scan/start, scan/stop, scan/pause, scan/resume, scan/status, scan/progress, scan/results
- **Structured JSON Progress**: `--json-progress` flag for AI agent streaming
  - Outputs: `{"type":"progress", "phase": "...", "progress": 0.35, ...}`
  - Outputs: `{"type":"result", "phase": "...", "data": {...}}`
  - Outputs: `{"type":"complete", "phases_completed": [...], "total_results": {...}}`
- **Progress File**: `--progress-file <path>` - Write progress to JSON file
- **Watch Mode**: `--watch` - Monitor output directory for incremental results
- **Signal Handling**: SIGSTOP/SIGCONT for pause/resume in MCP mode

### v0.1.2 - Hybrid CVE Detection & Fast XSS Scanning

**New Features:**
- **sxss XSS Scanner**: Fast XSS reflection scanning with 150 concurrent threads
  - Runs in parallel with dalfox for comprehensive XSS detection
  - Command: `cat urls.txt | sxss -concurrency 150 -retries 3`
- **Hybrid CVE Detection System**: Dynamic vulnerability lookup from multiple sources
  - Priority chain: vulnx → NVD API → hardcoded database → searchsploit
  - Local CVE cache with 24-hour TTL at `~/.reconator/cve-cache/`
  - ExploitDB integration via searchsploit (optional)
- **JS Analysis Improvements**: File paths in HTML report are now clickable hyperlinks

**Fixes:**
- DNS validation now uses trusted resolvers (~25 reliable servers) instead of full 18k list
- Prevents false positives from unreliable public DNS servers during dnsx validation
- puredns bruteforce still uses full 18k resolvers for better coverage

**New Dependencies:**
```bash
# Required (installed automatically)
go install github.com/unstabl3/sxss@latest

# Optional (for ExploitDB CVE lookup)
sudo apt install exploitdb
searchsploit -u
```

---

### v0.1.1 - DNS Validation & Historic URL Fixes

**Fixes:**
- Fixed DNS validation creating false positives with unreliable resolvers
- Created trusted-resolvers.txt (~25 reliable public DNS servers) for dnsx validation
- Fixed historic subdomain merging not including all sources
- Improved subdomain deduplication logic

**Improvements:**
- Separated resolver files: 18k for puredns bruteforce, ~25 trusted for validation
- Better error handling in historic URL collection
- Improved wayback/gau/waymore result merging

---

### v0.1.0 - Initial Release

**Core Features:**
- 12-phase reconnaissance pipeline with parallel execution
- Multi-input support: domains, IPs, CIDRs, ASNs
- Subdomain enumeration with 30+ passive sources + DNS bruteforce
- WAF/CDN detection and origin IP discovery
- Port scanning with TLS fingerprinting
- Subdomain takeover detection
- Historic URL collection (wayback, gau, waymore)
- Technology detection with version fingerprinting
- Directory bruteforce with smart wordlist selection
- Vulnerability scanning with nuclei + dalfox
- Screenshot capture with clustering
- AI-guided scanning with multi-provider support (Ollama, Groq, Claude, OpenAI, Gemini)

**Configuration:**
- Unified API key management (`~/.reconator/config.yaml`)
- Auto-sync to subfinder and notify configs
- Multi-provider AI with automatic failover and key rotation

**Output:**
- Structured JSON output for all phases
- Interactive HTML dashboard report
- Google dorks generation for OSINT
- Export to CSV, JSON, Markdown formats

---

<p align="center">
  <a href="README.md">Back to README</a>
</p>
