# Reconator - AI-Powered Reconnaissance Skill

## Overview
Reconator is an AI-powered reconnaissance and vulnerability scanning framework for bug bounty hunting and security assessments. This skill enables any LLM agent to conduct professional-grade reconnaissance autonomously.

## Prerequisites
- `reconator` binary installed: `go install github.com/rootsploit/reconator@latest`
- Required tools: `subfinder`, `httpx`, `nuclei` (run `reconator install` to set up)
- Optional: AI API keys for enhanced scanning (OpenAI, Claude, Gemini, Groq)

## Available Commands

### Full Reconnaissance Scan
```bash
reconator -t <domain> --json          # Full scan with JSON output
reconator -t <domain> --jsonl         # Full scan with streaming JSONL output
reconator -t <domain> --passive --json # Passive-only scan (no active probing)
reconator -t <domain> --subs-only --silent  # Quick subdomain enumeration only
reconator -t <domain> --quick --passive --silent  # Fast passive scan
```

### Phase-Specific Scans
```bash
# OSINT and asset discovery
reconator -t <domain> -p osint --json

# Subdomain enumeration
reconator -t <domain> -p subdomain --json

# Port scanning and service detection
reconator -t <domain> -p ports --json

# Technology detection
reconator -t <domain> -p tech --json

# Vulnerability scanning
reconator -t <domain> -p vulnscan --json

# Multiple specific phases
reconator -t <domain> -p "subdomain,ports,vulnscan" --json
```

### Web Application Scan
```bash
reconator webscan -t <url> --json     # Focused web app scan
```

### Scan Management
```bash
reconator check                        # Verify all tools are installed
reconator install                      # Install required tools
reconator config                       # Show/edit configuration
```

## Recommended Recon Workflow

### Phase 1: OSINT & Asset Discovery
```bash
# Start with passive OSINT to understand the target
reconator -t target.com -p osint --json
```
Analyze: Organization name, ASN, related domains, certificate transparency data, known breaches.

### Phase 2: Subdomain Enumeration
```bash
# Enumerate subdomains
reconator -t target.com -p subdomain --json
```
Analyze: Total subdomains found, interesting patterns, potential attack surface.

### Phase 3: Infrastructure Mapping
```bash
# Port scanning, technology detection, WAF identification
reconator -t target.com -p "ports,tech,waf" --json
```
Analyze: Open ports, running services, technology stack, WAF presence, CDN vs direct hosts.

### Phase 4: Full Vulnerability Scan
```bash
# Run complete scan with all phases
reconator -t target.com --json
```
Analyze: Vulnerabilities by severity, attack paths, AI-guided findings, false positive assessment.

### Phase 5: Deep Analysis
```bash
# Deep scan with comprehensive nuclei templates
reconator -t target.com --deep --json
```

## Output Formats

### JSON Output (`--json`)
Returns a single JSON document after scan completion:
```json
{
  "meta": {
    "version": "1.x.x",
    "scan_id": "abc123",
    "start_time": "2025-01-01T00:00:00Z",
    "end_time": "2025-01-01T01:00:00Z",
    "duration_sec": 3600,
    "phases_run": ["subdomain", "ports", "vulnscan"],
    "target": "target.com"
  },
  "target": "target.com",
  "subdomains": ["sub1.target.com", "sub2.target.com"],
  "alive_hosts": ["sub1.target.com", "sub2.target.com"],
  "ports": {"sub1.target.com": [80, 443, 8080]},
  "technologies": {"sub1.target.com": ["nginx", "react"]},
  "vulnerabilities": [...],
  "attack_paths": [...],
  "osint": {...},
  "ai_analysis": {...}
}
```

### JSONL Streaming (`--jsonl`)
Emits one JSON event per line during scan execution:
```jsonl
{"ts":"2025-01-01T00:00:00Z","phase":"scan","type":"scan_start","data":{"target":"target.com"}}
{"ts":"2025-01-01T00:00:01Z","phase":"subdomain","type":"phase_start"}
{"ts":"2025-01-01T00:00:30Z","phase":"subdomain","type":"finding","data":{...}}
{"ts":"2025-01-01T00:01:00Z","phase":"subdomain","type":"phase_complete","data":{"duration_sec":60}}
```

## Analysis Guidelines

When analyzing reconator output, focus on:

1. **Critical/High vulnerabilities first** - These need immediate attention
2. **Attack paths** - Chains of vulnerabilities that can be exploited together
3. **Exposed services** - Unexpected open ports or services
4. **Subdomain takeover opportunities** - Dangling DNS records
5. **Information disclosure** - Exposed configs, secrets, debug endpoints
6. **Technology-specific CVEs** - Known vulnerabilities for detected tech stack
7. **Cloud misconfigurations** - Open S3 buckets, exposed metadata

## Graph-of-Thought (GoT) Reasoning for Attack Paths

Reconator uses **Graph of Thought** reasoning to discover and validate attack chains, which is more powerful than simple Chain of Thought for complex multi-step attacks.

### How GoT Works in Reconator

1. **Node Creation**: Each vulnerability becomes a node with:
   - **Preconditions**: What's needed to exploit (e.g., "network_access", "authenticated_access")
   - **Postconditions**: What access the exploit provides (e.g., "code_execution", "credential_obtained")

2. **Edge Building**: Connections between vulnerabilities are created when:
   - A vulnerability's postconditions satisfy another vulnerability's preconditions
   - Uses MITRE ATT&CK tactics mapping (7 categories)

3. **3-Level Pruning** (Combination Lock Algorithm):
   - **Level 1**: Category ordering (initial_access → credential_access → privilege_escalation → lateral_movement → persistence → impact)
   - **Level 2**: Structural constraints (same host or network-reachable)
   - **Level 3**: Semantic feasibility (pattern matching or LLM-based)

4. **Path Scoring**: Paths are scored using:
   - Category weights (impact/lateral_movement = 1.0, persistence = 0.6)
   - Position weighting (earlier nodes contribute more)
   - Severity weighting (critical = 1.0, high = 0.8, medium = 0.5, low = 0.2)

### Example GoT Attack Chain Reasoning

```
Target: example.com

Vulnerability Graph Construction:
┌─────────────────────────────────────────────────────────────┐
│ Node A: SQL Injection (initial_access)                     │
│   Preconditions: [network_access]                          │
│   Postconditions: [data_obtained, credential_obtained]     │
├─────────────────────────────────────────────────────────────┤
│ Node B: Weak SSH Credentials (credential_access)           │
│   Preconditions: [network_access]                         │
│   Postconditions: [authenticated_access, server_access]   │
├─────────────────────────────────────────────────────────────┤
│ Node C: Sudo Misconfiguration (privilege_escalation)       │
│   Preconditions: [authenticated_access]                   │
│   Postconditions: [privileged_access, code_execution]      │
├─────────────────────────────────────────────────────────────┤
│ Valid Chain: A → B → C (SQLi → SSH as user → sudo root)    │
│ Invalid: A → C (cannot go directly to priv_esc without    │
│          intermediate credential_access)                   │
└─────────────────────────────────────────────────────────────┘
```

### Analyzing Attack Paths

When reviewing attack paths in Reconator output:

1. **Check the chain validity**: Each step's postconditions must satisfy the next step's preconditions
2. **Verify category progression**: Chains should follow MITRE ATT&CK order
3. **Assess feasibility**: Consider network connectivity, authentication requirements
4. **Score interpretation**: Paths scored 8-10 are highly feasible, 5-8 moderate, <5 low

### Semantic Matching Patterns

Reconator uses these pre-built patterns for chaining:

| Postcondition | Enables Preconditions |
|---------------|----------------------|
| code_execution | network_access, target_reachable |
| server_access | network_access |
| authenticated_access | network_access, service_exposed |
| privileged_access | authenticated_access, low_privilege_user |
| data_obtained | data_access |
| persistent_access | code_execution |

## Important Notes

- Always get authorization before scanning a target
- Use `--passive` flag for initial recon to avoid triggering WAF/IDS
- Rate limit with `-r` flag if needed: `reconator -t target.com -r 100`
- For large targets, increase threads: `reconator -t target.com -c 100`
- Scans auto-resume if interrupted - progress is saved automatically
