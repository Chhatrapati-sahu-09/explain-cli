"""
cache.py — Simple disk cache for LLM results

Stores results in ~/.explain/cache/ as JSON files named
by the SHA256 hash of the command string.

This means:
- Same command never hits the LLM API twice
- Cache survives between terminal sessions
- No database needed — just plain JSON files
- Easy to clear: rm -rf ~/.explain/cache/
"""

import json
import hashlib
from pathlib import Path
from typing import Optional

CACHE_DIR = Path.home() / ".explain" / "cache"


def _key(command: str) -> str:
    """Returns a safe filename derived from the command string."""
    return hashlib.sha256(command.encode()).hexdigest()


def get(command: str) -> Optional[dict]:
    """
    Returns cached LLM result for a command, or None if not cached.
    """
    path = CACHE_DIR / f"{_key(command)}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return None
    return None


def set(command: str, result: dict) -> None:
    """
    Stores an LLM result for a command.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{_key(command)}.json"
    try:
        path.write_text(json.dumps(result, indent=2))
    except Exception:
        pass  # cache write failure is non-fatal


def clear() -> int:
    """
    Deletes all cached results.
    Returns the number of files deleted.
    """
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
        count += 1
    return count


def size() -> int:
    """Returns the number of cached entries."""
    if not CACHE_DIR.exists():
        return 0
    return len(list(CACHE_DIR.glob("*.json")))
