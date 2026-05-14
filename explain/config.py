"""
config.py — Reads ~/.explain/config.toml

If the config file does not exist, returns safe defaults.
All other modules import from here instead of reading
environment variables directly.
"""

import os
from pathlib import Path
from dataclasses import dataclass

# tomllib is built-in on Python 3.11+
# on 3.10 install: pip install tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

CONFIG_PATH = Path.home() / ".explain" / "config.toml"


@dataclass
class Config:
    # LLM settings
    provider: str = "offline"       # "groq" | "ollama" | "offline"
    groq_api_key: str = ""
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "mistral"
    groq_model: str = "llama3-8b-8192"
    timeout: int = 10

    # Risk thresholds for LLM escalation
    llm_threshold_low: int = 40
    llm_threshold_high: int = 69

    # Output preferences
    color: bool = True
    show_tokens: bool = True
    show_flags: bool = True


def load() -> Config:
    """
    Loads config from ~/.explain/config.toml.
    Falls back to defaults if file does not exist or cannot be parsed.
    Also checks environment variables as overrides.
    """
    cfg = Config()

    # Load from file
    if CONFIG_PATH.exists() and tomllib is not None:
        try:
            with open(CONFIG_PATH, "rb") as f:
                data = tomllib.load(f)

            llm = data.get("llm", {})
            cfg.provider       = llm.get("provider",       cfg.provider)
            cfg.groq_api_key   = llm.get("groq_api_key",   cfg.groq_api_key)
            cfg.ollama_url     = llm.get("ollama_url",     cfg.ollama_url)
            cfg.ollama_model   = llm.get("ollama_model",   cfg.ollama_model)
            cfg.groq_model     = llm.get("model",          cfg.groq_model)
            cfg.timeout        = llm.get("timeout",        cfg.timeout)

            risk = data.get("risk", {})
            cfg.llm_threshold_low  = risk.get("llm_threshold_low",  cfg.llm_threshold_low)
            cfg.llm_threshold_high = risk.get("llm_threshold_high", cfg.llm_threshold_high)

            output = data.get("output", {})
            cfg.color        = output.get("color",        cfg.color)
            cfg.show_tokens  = output.get("show_tokens",  cfg.show_tokens)
            cfg.show_flags   = output.get("show_flags",   cfg.show_flags)

        except Exception:
            pass  # bad toml — use defaults silently

    # Environment variable overrides (useful for CI and Docker)
    if os.environ.get("EXPLAIN_GROQ_KEY"):
        cfg.groq_api_key = os.environ["EXPLAIN_GROQ_KEY"]
        if cfg.provider == "offline":
            cfg.provider = "groq"

    if os.environ.get("EXPLAIN_PROVIDER"):
        cfg.provider = os.environ["EXPLAIN_PROVIDER"]

    return cfg


def create_default_config():
    """
    Writes a default config file to ~/.explain/config.toml.
    Called on first run if no config exists.
    """
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = '''[llm]
# Options: "groq" (fast, free API) | "ollama" (local, offline) | "offline" (no LLM)
provider = "offline"

# Get your free key at console.groq.com — 14,400 requests/day free
groq_api_key = ""

# Groq model to use
model = "llama3-8b-8192"

# Ollama settings (if using local LLM)
ollama_url   = "http://localhost:11434"
ollama_model = "mistral"

# Seconds before giving up on LLM call
timeout = 10

[risk]
# Heuristic score range that triggers LLM analysis (Layer 3)
llm_threshold_low  = 40
llm_threshold_high = 69

[output]
color       = true
show_tokens = true
show_flags  = true
'''
    CONFIG_PATH.write_text(content)
    return CONFIG_PATH
