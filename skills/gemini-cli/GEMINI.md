# Reconator - Gemini CLI Integration

## Setup

Add the following to your Gemini CLI configuration to enable Reconator as a tool:

### Option 1: GEMINI.md (Project-level)
Place this file as `GEMINI.md` in your project root or copy the tool definitions to your existing `GEMINI.md`.

### Option 2: Global Configuration
Add to `~/.gemini/GEMINI.md` for global access.

## Tool Definition

You have access to `reconator`, an AI-powered reconnaissance and vulnerability scanning tool. Use it for bug bounty hunting and security assessments.

### Available Commands

Run reconnaissance on a target domain:
```bash
# Full scan with JSON output
reconator -t <domain> --json

# Passive OSINT only
reconator -t <domain> -p osint --json

# Specific phases
reconator -t <domain> -p "subdomain,ports,vulnscan" --json

# Web application scan
reconator webscan -t <url> --json
```

### Recon Workflow
1. Start with OSINT: `reconator -t target.com -p osint --json` - analyze organization, ASN, related domains
2. Enumerate subdomains: `reconator -t target.com -p subdomain --json`
3. Map infrastructure: `reconator -t target.com -p "ports,tech" --json`
4. Scan for vulns: `reconator -t target.com --json` (full pipeline)
5. Analyze results: Review JSON output for vulnerabilities, attack paths, and findings

### Analysis Guidelines
- Prioritize critical/high severity vulnerabilities
- Look for vulnerability chains (attack paths)
- Check for subdomain takeover opportunities
- Identify exposed sensitive endpoints
- Verify findings are not false positives
- Always ensure authorization before scanning
