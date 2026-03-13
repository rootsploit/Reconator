# Reconator - minimax m2.5 CLI Integration

## Overview

minimax m2.5 is a frontier language model with strong tool-use and instruction-following capabilities. This guide shows how to configure the minimax m2.5 CLI to use Reconator as a reconnaissance tool.

## Prerequisites

- Reconator installed: `go install github.com/rootsploit/reconator@latest`
- Required tools set up: `reconator install`
- minimax m2.5 CLI installed and configured with your API key

## Setup

### Option 1: Tool Definition Approach

Add Reconator as a tool in your minimax m2.5 CLI configuration file:

```json
{
  "tools": [
    {
      "name": "reconator",
      "description": "AI-powered reconnaissance and vulnerability scanning framework for bug bounty hunting and security assessments. Runs subdomain enumeration, port scanning, technology detection, and vulnerability scanning against a target domain.",
      "parameters": {
        "type": "object",
        "properties": {
          "target": {
            "type": "string",
            "description": "The target domain to scan (e.g., example.com)"
          },
          "phases": {
            "type": "string",
            "description": "Comma-separated scan phases: osint, subdomain, ports, tech, waf, secheaders, vulnscan. Leave empty for full scan.",
            "default": ""
          },
          "passive": {
            "type": "boolean",
            "description": "Run passive-only scan (no active probing)",
            "default": false
          }
        },
        "required": ["target"]
      },
      "execute": {
        "command": "reconator",
        "args": ["-t", "{target}", "-p", "{phases}", "--json"],
        "args_if_passive": ["-t", "{target}", "--passive", "--json"]
      }
    },
    {
      "name": "reconator_webscan",
      "description": "Focused web application vulnerability scan against a specific URL.",
      "parameters": {
        "type": "object",
        "properties": {
          "url": {
            "type": "string",
            "description": "The target URL to scan (e.g., https://example.com/app)"
          }
        },
        "required": ["url"]
      },
      "execute": {
        "command": "reconator",
        "args": ["webscan", "-t", "{url}", "--json"]
      }
    }
  ]
}
```

### Option 2: System Prompt Approach

If your minimax m2.5 CLI version uses system prompts rather than tool definitions, add the following to your system prompt configuration:

```
You have access to `reconator`, an AI-powered reconnaissance and vulnerability scanning CLI tool. Use it for authorized bug bounty hunting and security assessments.

## Commands

### Full Reconnaissance
reconator -t <domain> --json

### Phase-Specific Scans
reconator -t <domain> -p osint --json          # OSINT and asset discovery
reconator -t <domain> -p subdomain --json      # Subdomain enumeration
reconator -t <domain> -p ports --json          # Port scanning
reconator -t <domain> -p tech --json           # Technology detection
reconator -t <domain> -p vulnscan --json       # Vulnerability scanning
reconator -t <domain> -p "subdomain,ports,vulnscan" --json  # Multiple phases

### Passive Scan (no active probing)
reconator -t <domain> --passive --json

### Web Application Scan
reconator webscan -t <url> --json

### Utility
reconator check     # Verify tools are installed
reconator install   # Install required tools

## Workflow
1. Start with passive OSINT: reconator -t target.com -p osint --json
2. Enumerate subdomains: reconator -t target.com -p subdomain --json
3. Map infrastructure: reconator -t target.com -p "ports,tech,waf" --json
4. Full vulnerability scan: reconator -t target.com --json
5. Analyze output for critical/high vulnerabilities, attack paths, exposed services

Always use the --json flag for structured output. Ensure authorization before scanning any target.
```

### Option 3: Project-Level Configuration

Create a `.minimax` or `minimax.config.json` file in your project root:

```json
{
  "system_prompt_files": ["skills/reconator-skill.md"],
  "allowed_commands": ["reconator"]
}
```

This loads the universal skill definition from `skills/reconator-skill.md` as context for the model.

## Usage Examples

Once configured, interact with minimax m2.5 CLI naturally:

```
> Run reconnaissance on target.com
> Find subdomains for example.com and check for takeover opportunities
> Do a passive OSINT scan on company.com
> Scan https://app.target.com for web vulnerabilities
> Run a full scan on target.com and give me a prioritized list of findings
```

### Example Session

```
User: Run recon on target.com, start with passive OSINT

minimax m2.5: I'll start with passive OSINT to gather information about target.com
without triggering any detection systems.

[Executes: reconator -t target.com -p osint --json]

Based on the OSINT results:
- Organization: Target Corp (AS12345)
- Registrar: GoDaddy
- 47 certificates found in CT logs
- Related domains: target.io, target.dev, target-staging.com
...

Shall I proceed with subdomain enumeration?
```

## Analysis Guidelines

When minimax m2.5 analyzes reconator output, it should:

1. Prioritize critical and high severity vulnerabilities
2. Identify attack paths (chains of exploitable vulnerabilities)
3. Flag subdomain takeover opportunities
4. Note exposed sensitive endpoints (admin panels, APIs, debug interfaces)
5. Check for technology-specific CVEs in the detected stack
6. Assess cloud misconfigurations (open buckets, exposed metadata)
7. Distinguish true positives from likely false positives

## Troubleshooting

### reconator command not found
Ensure the Go bin directory is in your PATH:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Tool not recognized by minimax CLI
- Verify your configuration file syntax is valid JSON
- Restart the minimax CLI after configuration changes
- Try the system prompt approach as a fallback

### JSON output too large for context window
Use phase-specific scans instead of full scans to reduce output size:
```bash
# Instead of full scan
reconator -t target.com --json

# Use targeted phases
reconator -t target.com -p subdomain --json
reconator -t target.com -p vulnscan --json
```
