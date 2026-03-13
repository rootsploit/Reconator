# Reconator - Ollama Integration

Use Reconator with locally-hosted Ollama models for fully offline, private AI-powered reconnaissance.

## Overview

Ollama runs large language models locally on your machine. When paired with Reconator, you get AI-guided vulnerability analysis without sending scan data to external API providers. This is ideal for:

- Air-gapped or restricted environments
- Sensitive targets where data must not leave the network
- Cost-free AI analysis (no API billing)
- Experimentation with different models

## Prerequisites

- Reconator installed: `go install github.com/rootsploit/reconator@latest`
- Ollama installed: https://ollama.com/download
- A pulled model (see recommendations below)

## Setup

### Step 1: Install and Start Ollama

```bash
# Install Ollama (macOS/Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull a recommended model
ollama pull llama3.1:8b        # Good balance of speed and quality
ollama pull qwen2.5:14b        # Stronger reasoning, needs more RAM
ollama pull deepseek-r1:14b    # Strong at code/security analysis

# Verify Ollama is running
ollama list
```

### Step 2: Configure Reconator to Use Ollama

```bash
# Set Ollama as the AI provider
reconator config set ai.provider ollama

# Set the model (must match a model you've pulled)
reconator config set ai.model llama3.1:8b

# Set the Ollama API endpoint (default is localhost:11434)
reconator config set ai.ollama_url http://localhost:11434

# Verify configuration
reconator config
```

Alternatively, use environment variables:

```bash
export RECONATOR_AI_PROVIDER=ollama
export RECONATOR_AI_MODEL=llama3.1:8b
export RECONATOR_AI_OLLAMA_URL=http://localhost:11434
```

### Step 3: Verify the Setup

```bash
# Check that reconator can reach Ollama
reconator check

# Run a quick test scan
reconator -t example.com -p osint --json
```

## Recommended Models

| Model | Size | RAM Needed | Best For |
|-------|------|-----------|----------|
| `llama3.1:8b` | 4.7 GB | 8 GB | General recon, fast analysis |
| `llama3.1:70b` | 40 GB | 48 GB | Deep analysis, complex targets |
| `qwen2.5:14b` | 9 GB | 16 GB | Balanced speed and quality |
| `deepseek-r1:14b` | 9 GB | 16 GB | Security-focused reasoning |
| `codestral:22b` | 13 GB | 24 GB | Code review, tech stack analysis |
| `mistral:7b` | 4.1 GB | 8 GB | Lightweight, fast responses |

For security analysis, models with 14B+ parameters generally produce better vulnerability assessments.

## Usage Workflows

### Workflow 1: Local AI + Full Recon

Run a complete recon scan with local AI analysis:

```bash
# Ensure Ollama is running
ollama serve &

# Full scan with AI-guided analysis
reconator -t target.com --json
```

The AI analysis phases (vulnerability correlation, attack path generation, false positive filtering) will use your local Ollama model instead of a cloud API.

### Workflow 2: Scan First, Analyze Locally

Separate scanning from analysis to use different models:

```bash
# Run scan without AI analysis (faster, no model needed)
reconator -t target.com --no-ai --json > scan_results.json

# Switch to a larger model for deeper analysis
reconator config set ai.model qwen2.5:14b

# Re-analyze with AI
reconator analyze --input scan_results.json --json
```

### Workflow 3: Ollama + LLM CLI Agent

Use Ollama as both the reconator AI backend and as the agent driving the recon:

```bash
# Terminal 1: Ensure Ollama is running
ollama serve

# Terminal 2: Use any Ollama-compatible CLI agent
# Configure the agent with the reconator-skill.md as system prompt
# and let it drive the recon workflow using reconator commands
```

For example, with an Ollama-compatible chat CLI:

```bash
# Start a chat session with recon context
ollama run llama3.1:8b --system "$(cat skills/reconator-skill.md)"
```

Then interact conversationally:
```
> Run OSINT on target.com and tell me what you find
> Now enumerate subdomains
> What vulnerabilities did you find?
```

## Configuration Reference

All Ollama-related configuration keys:

| Key | Default | Description |
|-----|---------|-------------|
| `ai.provider` | `openai` | Set to `ollama` for local models |
| `ai.model` | - | Ollama model name (e.g., `llama3.1:8b`) |
| `ai.ollama_url` | `http://localhost:11434` | Ollama API endpoint |
| `ai.temperature` | `0.1` | Model temperature (lower = more deterministic) |
| `ai.max_tokens` | `4096` | Maximum response tokens |
| `ai.timeout` | `120` | Request timeout in seconds (increase for large models) |

## Troubleshooting

### Ollama connection refused
```bash
# Make sure Ollama is running
ollama serve
# Or check if it's already running
curl http://localhost:11434/api/tags
```

### Model not found
```bash
# List available models
ollama list
# Pull the model if missing
ollama pull llama3.1:8b
```

### Slow analysis
- Use a smaller model (7B-8B) for faster results
- Increase timeout: `reconator config set ai.timeout 300`
- Consider running on a machine with GPU acceleration

### Out of memory
- Use a smaller model variant (e.g., `llama3.1:8b` instead of `llama3.1:70b`)
- Close other applications to free RAM
- Use quantized variants (e.g., `llama3.1:8b-q4_0`) for reduced memory usage
