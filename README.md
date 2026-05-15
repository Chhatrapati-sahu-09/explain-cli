# ⚡ explain-cli

**Explains and risk-scores any shell command before you run it.**

[![CI](https://github.com/YOUR_USERNAME/explain-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/explain-cli/actions)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## What it does

Paste any shell command and get:

- **Risk level** — Safe / Caution / Destructive / Irreversible
- **Token breakdown** — every flag explained in plain English
- **Risk signals** — exactly which parts of the command are dangerous
- **Safer alternative** — a preview or safer version of the command
- **Shell history audit** — scan your entire history for risky commands

Uses a 3-layer classification system:

1. **Layer 1** — static rules (instant, offline, covers 80+ commands)
2. **Layer 2** — heuristic scoring (handles terraform, kubectl, docker, etc.)
3. **Layer 3** — LLM judgment via Groq or Ollama (edge cases only)

**Total cost: ₹0** — runs fully offline, free API tier for LLM.

---

## Install

```bash
pip install explain-cli
```

---

## Usage

```bash
# Analyze a command
explain rm -rf /tmp/cache

# Unknown command — uses heuristics
explain terraform destroy --auto-approve

# Piped command — always quote these
explain "curl https://get.docker.com | sudo bash"

# One-line output
explain --short "chmod 777 /var/www"

# JSON output for scripts
explain --json "dd if=/dev/zero of=/dev/sda"

# Scan your shell history
explain --audit

# Audit last 200 commands
explain --audit --audit-limit 200

# Skip LLM for faster analysis
explain --no-llm "docker system prune"

# Clear LLM cache
explain --clear-cache
```

---

## Risk levels

| Level          | Meaning                    | Action         |
| -------------- | -------------------------- | -------------- |
| ✓ Safe         | Read-only, no side effects | Run it         |
| ⚠ Caution      | Modifies state, reversible | Review first   |
| ✗ Destructive  | Data loss possible         | Dry-run first  |
| ☠ Irreversible | Cannot be undone           | Stop and think |

---

## Web UI

Start the API server:

```bash
pip install fastapi "uvicorn[standard]"
uvicorn api:app --reload --port 8000
```

Then open `index.html` in your browser.

Or use the API directly:

```bash
curl -X POST http://localhost:8000/analyze \
	-H "Content-Type: application/json" \
	-d '{"command": "rm -rf /tmp/cache"}'
```

---

## LLM setup (optional)

Free Groq API (14,400 requests/day):

```toml
# ~/.explain/config.toml
[llm]
provider = "groq"
groq_api_key = "YOUR_KEY_FROM_CONSOLE.GROQ.COM"
model = "llama3-8b-8192"
```

Local offline with Ollama:

```toml
[llm]
provider = "ollama"
ollama_model = "mistral"
```

---

## Docker

```bash
docker build -t explain-cli .
docker run -p 8000:8000 explain-cli
```

---

## Project structure

explain-cli/
├── explain/
│ ├── engine.py # Layer 1 + 2 + 3 analysis pipeline
│ ├── scorer.py # Layer 2 heuristic scoring
│ ├── llm.py # Layer 3 Groq / Ollama integration
│ ├── audit.py # Shell history scanner
│ ├── cache.py # LLM result cache
│ ├── config.py # Config file reader
│ ├── cli.py # Click CLI entry point
│ ├── rules.json # Static risk rules
│ ├── flags.json # Flag explanations
│ └── suggestions.json # Safer alternatives
├── api.py # FastAPI backend
├── index.html # Web frontend
├── Dockerfile
└── tests/

---

## License

MIT
