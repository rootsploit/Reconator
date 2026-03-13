# Reconator LLM Skills

Universal skill definitions for using Reconator with any LLM CLI tool.

## Quick Start

1. Install Reconator:
```bash
go install github.com/rootsploit/reconator@latest
reconator install  # Install required tools (subfinder, httpx, nuclei, etc.)
```

2. Choose your LLM tool and follow the installation below.

## Installation by LLM Tool

### Claude Code

Copy the skill file to your Claude Code commands directory:

```bash
# Project-level (available in this project only)
mkdir -p .claude/commands
cp skills/claude-code/reconator.md .claude/commands/reconator.md

# Global (available in all projects)
mkdir -p ~/.claude/commands
cp skills/claude-code/reconator.md ~/.claude/commands/reconator.md
```

**Usage:** In Claude Code, type `/reconator target.com`

### Gemini CLI

Copy the Gemini configuration to your project or global config:

```bash
# Project-level
cp skills/gemini-cli/GEMINI.md ./GEMINI.md

# Or append to existing GEMINI.md
cat skills/gemini-cli/GEMINI.md >> ./GEMINI.md
```

**Usage:** Ask Gemini to "run recon on target.com" or "scan target.com for vulnerabilities"

### Kimi k2.5

Follow the configuration instructions in `skills/kimi-k2/README.md`.

### Ollama (Local Models)

Reconator supports Ollama for fully offline, private AI-powered reconnaissance. Configure Reconator to use your local Ollama instance:

```bash
# Pull a model
ollama pull llama3.1:8b

# Configure reconator to use Ollama
reconator config set ai.provider ollama
reconator config set ai.model llama3.1:8b
reconator config set ai.ollama_url http://localhost:11434

# Run a scan with local AI analysis
reconator -t target.com --json
```

For the full setup guide, recommended models, and usage workflows, see `skills/ollama/README.md`.

**Usage:** Run reconator commands as normal -- AI analysis uses your local Ollama model instead of a cloud API.

### minimax m2.5

Configure the minimax m2.5 CLI to use Reconator via tool definitions or system prompts:

```bash
# Option 1: Add tool definition to minimax CLI config (see skills/minimax-m2/README.md)
# Option 2: Load the universal skill as a system prompt
#   Add skills/reconator-skill.md content to your minimax system prompt config
```

For full configuration with tool definitions, system prompt setup, and usage examples, see `skills/minimax-m2/README.md`.

**Usage:** Ask minimax to "run recon on target.com" or "scan target.com for vulnerabilities"

### Any Other LLM CLI

The universal skill definition in `skills/reconator-skill.md` can be adapted for any LLM tool:

1. **System prompt approach:** Copy the content of `reconator-skill.md` into your LLM's system prompt
2. **Tool definition approach:** Register `reconator` as an available tool with the command patterns described in the skill file
3. **Custom integration:** Use the JSONL streaming mode (`--jsonl`) for real-time event processing

## Skill Files

| File | Purpose |
|------|---------|
| `reconator-skill.md` | Universal, provider-agnostic skill definition |
| `claude-code/reconator.md` | Claude Code slash command format |
| `gemini-cli/GEMINI.md` | Gemini CLI integration |
| `kimi-k2/README.md` | Kimi k2.5 integration guide |
| `ollama/README.md` | Ollama local model integration and configuration |
| `minimax-m2/README.md` | minimax m2.5 CLI integration guide |
| `README.md` | This installation guide |

## How It Works

The skill teaches LLM agents to:
1. Use `reconator` CLI commands with `--json` or `--jsonl` flags
2. Follow a structured recon methodology (OSINT -> Enumeration -> Scanning -> Analysis)
3. Analyze JSON output to identify vulnerabilities, attack paths, and security issues
4. Generate actionable security reports

## AI Integration

Reconator provides native MCP (Model Context Protocol) server support for AI agent integration:

### Quick Start with MCP
```bash
# Run as MCP server
reconator scan --mcp

# Or with JSON progress output
reconator scan target.com --json-progress --progress-file ./progress.json
```

### MCP Methods Supported
- `initialize` - Returns protocol version and capabilities
- `tools/list` - Lists available tools
- `scan/start` - Start a scan
- `scan/stop` - Stop current scan
- `scan/pause` - Pause scan gracefully
- `scan/resume` - Resume paused scan
- `scan/status` - Get scan status
- `scan/progress` - Get detailed progress
- `scan/results` - Get scan results

### Example: Running Scan with Progress
```bash
# JSON progress to stdout
reconator scan target.com --json-progress

# Progress to file (for polling)
reconator scan target.com --progress-file ./progress.json

# Watch mode - incremental results
reconator scan target.com --watch
```

## Requirements

- Go 1.21+ (for installing reconator)
- Linux or macOS (Windows via WSL)
- Network access to target (with authorization)
- Optional: AI API keys for enhanced scanning (set via `reconator config`)
