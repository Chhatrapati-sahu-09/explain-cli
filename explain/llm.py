"""
llm.py — Layer 3 LLM integration

Supports:
  - Groq API   (fast, free tier, 14,400 req/day)
  - Ollama     (local, fully offline, no API key)
  - Offline    (returns None — falls back to Layer 2 result)

The LLM is only called when the heuristic score is in the
ambiguous range (40-69) where Layer 2 is uncertain.

The prompt is structured to return a strict JSON response
so we never need to parse free-form text.
"""

import json
import re
from typing import Optional

import httpx

from explain import cache as cache_module
from explain.config import load as load_config


# ── Prompt template ────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a shell command safety analyzer.
Your job is to classify the risk level of shell commands.

You MUST respond with ONLY a valid JSON object — no explanation,
no markdown, no backticks. Just raw JSON.

Risk levels:
- "safe"        : read-only, no side effects
- "caution"     : modifies state but reversible
- "destructive" : can cause data loss, hard to undo
- "irreversible": permanent, cannot be undone (disk wipes, remote exec, etc.)

JSON format:
{
  "risk": "safe|caution|destructive|irreversible",
  "verdict": "One sentence explaining what this command does and why it has this risk level.",
  "reversible": "Yes|No|Depends",
  "key_concern": "The single most dangerous aspect of this command, or empty string if safe."
}"""

USER_PROMPT_TEMPLATE = """Analyze this shell command and classify its risk:

Command: {command}

Heuristic signals already detected (use these as hints):
{signals}

Respond with ONLY the JSON object."""


def _build_user_prompt(command: str, signals: list) -> str:
    if signals:
        signal_lines = "\n".join(f"- {s}" for s in signals[:5])
    else:
        signal_lines = "- No specific signals detected"
    return USER_PROMPT_TEMPLATE.format(
        command=command,
        signals=signal_lines
    )


def _parse_llm_response(text: str) -> Optional[dict]:
    """
    Parses the LLM response text into a dict.
    Handles cases where the model adds backticks or extra text.
    """
    # Strip markdown code fences if present
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*', '', text)
    text = text.strip()

    # Try to extract JSON object
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _validate_response(data: dict) -> bool:
    """Checks that the LLM returned a valid risk response."""
    valid_risks = {"safe", "caution", "destructive", "irreversible"}
    return (
        isinstance(data, dict)
        and data.get("risk") in valid_risks
        and "verdict" in data
    )


# ── Groq provider ──────────────────────────────────────────────────────────

def _call_groq(command: str, signals: list, cfg) -> Optional[dict]:
    """
    Calls the Groq API with LLaMA 3.
    Returns parsed dict or None on failure.
    """
    if not cfg.groq_api_key:
        return None

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {cfg.groq_api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": cfg.groq_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_prompt(command, signals)},
        ],
        "max_tokens": 300,
        "temperature": 0.1,
    }

    try:
        with httpx.Client(timeout=cfg.timeout) as client:
            response = client.post(url, headers=headers, json=body)
            response.raise_for_status()
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            parsed = _parse_llm_response(text)
            if parsed and _validate_response(parsed):
                return parsed
    except httpx.TimeoutException:
        pass
    except httpx.HTTPStatusError:
        pass
    except Exception:
        pass

    return None


# ── Ollama provider ────────────────────────────────────────────────────────

def _call_ollama(command: str, signals: list, cfg) -> Optional[dict]:
    """
    Calls a local Ollama instance.
    Install Ollama: curl https://ollama.ai/install.sh | sh
    Then run: ollama pull mistral
    """
    url = f"{cfg.ollama_url}/api/generate"
    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"{_build_user_prompt(command, signals)}"
    )
    body = {
        "model": cfg.ollama_model,
        "prompt": full_prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }

    try:
        with httpx.Client(timeout=cfg.timeout) as client:
            response = client.post(url, json=body)
            response.raise_for_status()
            data = response.json()
            text = data.get("response", "")
            parsed = _parse_llm_response(text)
            if parsed and _validate_response(parsed):
                return parsed
    except Exception:
        pass

    return None


# ── Main public API ────────────────────────────────────────────────────────

def analyze(command: str, signals: list) -> Optional[dict]:
    """
    Attempts to get an LLM risk verdict for a command.

    Steps:
    1. Check cache — return immediately if already analyzed
    2. Try configured provider (Groq or Ollama)
    3. Cache the result
    4. Return dict with risk/verdict/reversible/key_concern
       or None if LLM is unavailable
    """
    cfg = load_config()

    # Step 1: check cache
    cached = cache_module.get(command)
    if cached:
        cached["from_cache"] = True
        return cached

    # Step 2: offline mode — skip LLM entirely
    if cfg.provider == "offline":
        return None

    # Step 3: call configured provider
    result = None
    if cfg.provider == "groq":
        result = _call_groq(command, signals, cfg)
    elif cfg.provider == "ollama":
        result = _call_ollama(command, signals, cfg)

    # Step 4: cache and return
    if result:
        result["from_cache"] = False
        cache_module.set(command, result)

    return result
