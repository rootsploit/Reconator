# Reconator - Kimi k2.5 Integration

## Setup

Kimi k2.5 CLI tool can use Reconator for reconnaissance by adding tool definitions to its configuration.

### Configuration

Add the following to your Kimi CLI tool configuration:

```yaml
tools:
  - name: reconator
    description: AI-powered reconnaissance and vulnerability scanning framework
    command: reconator
    args:
      - "-t"
      - "{target}"
      - "--json"
```

### Usage

Once configured, you can ask Kimi to:
- "Run recon on target.com"
- "Find subdomains for example.com"
- "Scan target.com for vulnerabilities"
- "Do OSINT on company.com"

### Manual Integration

If your Kimi CLI version doesn't support tool configuration, use system prompts:

```
You have access to the `reconator` command-line tool for reconnaissance.

Commands:
- `reconator -t <domain> --json` - Full recon scan
- `reconator -t <domain> -p osint --json` - OSINT only
- `reconator -t <domain> -p "subdomain,ports" --json` - Specific phases
- `reconator webscan -t <url> --json` - Web app scan

Always use --json flag for structured output. Analyze results systematically.
```
