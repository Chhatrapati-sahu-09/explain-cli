"""
engine.py — Core parsing and risk classification engine (Layer 1)

This module takes a raw shell command string and returns a structured
RiskResult containing the risk level, signals, token annotations,
and per-flag explanations.

Flow:
  raw command string
      → parse with bashlex (AST)
      → extract tokens (command, flags, args, operators)
      → match against rules.json (Layer 1 static rules)
      → check pipe patterns (curl | bash, etc.)
      → check path patterns (/dev/sda, /etc/, etc.)
      → aggregate signals and determine final risk level
      → return RiskResult
"""

import json
import re
import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

import bashlex

# ── Load rule databases ────────────────────────────────────────────────────

_HERE = Path(__file__).parent

with open(_HERE / "rules.json") as f:
    RULES = json.load(f)

with open(_HERE / "flags.json") as f:
    FLAGS_DB = json.load(f)

# ── Risk level ordering (for comparison) ──────────────────────────────────

RISK_ORDER = {"safe": 0, "caution": 1, "destructive": 2, "irreversible": 3}


def _max_risk(a: str, b: str) -> str:
    """Returns whichever risk level is higher."""
    return a if RISK_ORDER.get(a, 0) >= RISK_ORDER.get(b, 0) else b


# ── Data structures ────────────────────────────────────────────────────────

@dataclass
class Token:
    """A single parsed token from the command with its type and annotation."""
    text: str
    kind: str          # "command" | "flag" | "path" | "operator" | "url" | "arg"
    risk: str = "safe" # token-level risk for colorization
    explanation: str = ""


@dataclass
class Signal:
    """A risk signal detected in the command."""
    text: str          # Short label shown in the UI
    risk: str          # "safe" | "caution" | "destructive" | "irreversible"
    detail: str = ""   # Longer explanation


@dataclass
class RiskResult:
    """Complete analysis result for a command."""
    raw: str                          # Original command string
    risk: str                         # Overall risk level
    layer: int                        # Which layer determined the risk (1, 2, 3)
    tokens: list[Token] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    verdict: str = ""                 # Human-readable summary
    reversible: str = "Yes"
    scope: str = "Unknown"
    network: str = "None"
    privilege: str = "User"
    dry_run_suggestion: Optional[str] = None  # Safer alternative command


# ── Bashlex helpers ────────────────────────────────────────────────────────

def _extract_tokens_from_ast(command: str) -> list[str]:
    """
    Uses bashlex to parse a shell command into its component tokens.
    Falls back to simple whitespace splitting if bashlex fails
    (handles exotic syntax like heredocs, process substitution, etc.)
    """
    try:
        parts = bashlex.parse(command)
        tokens = []
        for part in parts:
            _walk_ast(part, tokens, command)
        return tokens if tokens else command.split()
    except Exception:
        # bashlex fails on some valid bash like process substitution <()
        # Simple split is good enough for Layer 1 matching
        return command.split()


def _walk_ast(node, tokens: list, original: str):
    """Recursively walks a bashlex AST node and collects word tokens."""
    if node.kind == "word":
        tokens.append(original[node.pos[0]:node.pos[1]])
    if hasattr(node, "parts"):
        for part in node.parts:
            _walk_ast(part, tokens, original)


# ── Token classification ───────────────────────────────────────────────────

def _classify_token(token: str, command_name: str) -> tuple[str, str]:
    """
    Returns (kind, risk) for a single token.
    kind: "command" | "flag" | "path" | "operator" | "url" | "arg"
    """
    # Shell operators
    if token in ("|", "||", "&&", ";", ">", ">>", "<", "2>", "&"):
        risk = "caution" if token == "|" else "safe"
        return "operator", risk

    # Flags (start with -)
    if token.startswith("-"):
        return "flag", _get_flag_risk(token, command_name)

    # URLs
    if token.startswith(("http://", "https://", "ftp://")):
        return "url", "safe"

    # Paths
    if token.startswith("/") or token.startswith("~/") or token == "~":
        return "path", _get_path_risk(token)

    # Known commands (first token or after pipe)
    if token in RULES["commands"]:
        return "command", RULES["commands"][token].get("base_risk", "safe")

    return "arg", "safe"


def _get_flag_risk(flag: str, command_name: str) -> str:
    """Looks up the risk level for a specific flag on a specific command."""
    cmd_rules = RULES["commands"].get(command_name, {})
    flag_rules = cmd_rules.get("flags", {})

    # Direct flag match
    if flag in flag_rules:
        return flag_rules[flag]["risk"]

    # Combined flags like -rf: check each component
    if len(flag) > 2 and not flag.startswith("--"):
        chars = flag[1:]  # strip leading -
        risks = []
        for char in chars:
            f = f"-{char}"
            if f in flag_rules:
                risks.append(flag_rules[f]["risk"])
        if risks:
            return max(risks, key=lambda r: RISK_ORDER.get(r, 0))

    return "safe"


def _get_path_risk(path: str) -> str:
    """Checks a path against known dangerous path patterns."""
    for pp in RULES["path_patterns"]:
        if pp["pattern"] in path:
            return pp["risk"]
    return "safe"


# ── Flag explanation ───────────────────────────────────────────────────────

def _explain_flag(flag: str, command_name: str) -> str:
    """Returns a plain-English explanation for a flag."""
    # Check command-specific flags first
    cmd_flags = FLAGS_DB.get("command_flags", {}).get(command_name, {})
    if flag in cmd_flags:
        return cmd_flags[flag]

    # Handle combined flags like -rf by explaining each component
    if len(flag) > 2 and not flag.startswith("--") and flag.startswith("-"):
        parts = []
        for char in flag[1:]:
            f = f"-{char}"
            if f in cmd_flags:
                parts.append(f"{f}: {cmd_flags[f]}")
            elif f in FLAGS_DB.get("global_flags", {}):
                parts.append(f"{f}: {FLAGS_DB['global_flags'][f]}")
        if parts:
            return " | ".join(parts)

    # Fall back to global flags
    global_flags = FLAGS_DB.get("global_flags", {})
    if flag in global_flags:
        return global_flags[flag]

    return "No description available"


# ── Signal detection ───────────────────────────────────────────────────────

def _detect_pipe_signals(raw: str) -> list[Signal]:
    """Checks the full command string for dangerous pipe patterns."""
    signals = []
    for pp in RULES["pipe_patterns"]:
        if re.search(pp["pattern"], raw, re.IGNORECASE):
            signals.append(Signal(
                text=pp["signal"].split(":")[0],
                risk=pp["risk"],
                detail=pp["signal"]
            ))
    return signals


def _detect_path_signals(tokens: list[str]) -> list[Signal]:
    """Checks all tokens for dangerous path patterns."""
    signals = []
    seen = set()
    for token in tokens:
        for pp in RULES["path_patterns"]:
            if pp["pattern"] in token and pp["pattern"] not in seen:
                seen.add(pp["pattern"])
                signals.append(Signal(
                    text=pp["pattern"].rstrip("/"),
                    risk=pp["risk"],
                    detail=pp["signal"]
                ))
    return signals


def _detect_sudo(raw: str) -> Optional[Signal]:
    """Detects sudo usage anywhere in the command."""
    if re.search(r'\bsudo\b', raw):
        return Signal(
            text="sudo: runs as root",
            risk="caution",
            detail="Superuser execution — mistakes have system-wide consequences"
        )
    return None


def _detect_command_signals(command_name: str, all_tokens: list[str]) -> list[Signal]:
    """Detects signals based on the primary command and its flags."""
    signals = []
    cmd_rules = RULES["commands"].get(command_name, {})

    if not cmd_rules:
        return signals

    # Command-level note
    if cmd_rules.get("always_warn") and "note" in cmd_rules:
        signals.append(Signal(
            text=f"{command_name}: {cmd_rules['note'][:50]}",
            risk=cmd_rules["base_risk"],
            detail=cmd_rules["note"]
        ))

    # Flag-level signals
    flag_rules = cmd_rules.get("flags", {})
    for token in all_tokens:
        if token.startswith("-"):
            # Direct match
            if token in flag_rules:
                rule = flag_rules[token]
                signals.append(Signal(
                    text=f"{token}: {rule['note'][:50]}",
                    risk=rule["risk"],
                    detail=rule["note"]
                ))
            # Combined short flags
            elif len(token) > 2 and not token.startswith("--"):
                for char in token[1:]:
                    f = f"-{char}"
                    if f in flag_rules:
                        rule = flag_rules[f]
                        signals.append(Signal(
                            text=f"{f} (in {token}): {rule['note'][:45]}",
                            risk=rule["risk"],
                            detail=rule["note"]
                        ))

    # Pattern matching (e.g. chmod 777)
    for pattern_rule in cmd_rules.get("patterns", []):
        for token in all_tokens:
            if pattern_rule["match"] in token:
                signals.append(Signal(
                    text=f"{pattern_rule['match']}: {pattern_rule['note'][:50]}",
                    risk=pattern_rule["risk"],
                    detail=pattern_rule["note"]
                ))

    return signals


# ── Verdict builder ────────────────────────────────────────────────────────

def _build_verdict(command_name: str, risk: str, signals: list[Signal],
                   raw: str) -> str:
    """Constructs the final human-readable verdict string."""
    cmd_rules = RULES["commands"].get(command_name, {})
    cmd_desc = cmd_rules.get("description", f"Runs the {command_name} command")

    if risk == "safe":
        return (f"{cmd_desc}. No destructive operations detected — "
                f"safe to run as written.")

    if risk == "caution":
        signal_texts = [s.detail for s in signals if s.detail]
        detail = signal_texts[0] if signal_texts else "Review the flags carefully."
        return f"{cmd_desc}. {detail} Double-check before running."

    if risk == "destructive":
        signal_texts = [s.detail for s in signals if s.risk in ("destructive", "irreversible")]
        detail = signal_texts[0] if signal_texts else "This command can cause data loss."
        return (f"{cmd_desc}. {detail} "
                f"Consider a dry-run or preview first.")

    # irreversible
    signal_texts = [s.detail for s in signals if s.risk == "irreversible"]
    detail = signal_texts[0] if signal_texts else "This operation cannot be undone."
    return (f"{cmd_desc}. {detail} "
            f"Make absolutely sure this is what you intend.")


def _infer_properties(raw: str, risk: str, signals: list[Signal]) -> dict:
    """Infers metadata properties from the command for the output table."""
    props = {
        "reversible": "Yes",
        "scope": "Local",
        "network": "None",
        "privilege": "User",
    }

    if risk in ("destructive", "irreversible"):
        props["reversible"] = "No" if risk == "irreversible" else "Depends"

    if "sudo" in raw or re.search(r'\bsu\b', raw):
        props["privilege"] = "Root (sudo)"

    if re.search(r'https?://|ftp://', raw):
        props["network"] = "External"

    # Scope detection
    for sig in signals:
        if any(p in sig.detail for p in ["/dev/", "disk", "filesystem", "partition"]):
            props["scope"] = "Entire disk"
            break
        if any(p in sig.detail for p in ["/etc/", "/usr/", "/bin/", "system"]):
            props["scope"] = "System-wide"
            break
        if "recursive" in sig.detail.lower() or "directory tree" in sig.detail.lower():
            props["scope"] = "Directory tree"
            break

    return props


# ── Main public API ────────────────────────────────────────────────────────

def analyze(raw: str) -> RiskResult:
    """
    Main entry point. Takes a raw shell command string and returns
    a complete RiskResult.

    Usage:
        result = analyze("rm -rf /tmp/cache")
        print(result.risk)       # "destructive"
        print(result.verdict)    # human-readable explanation
    """
    raw = raw.strip()
    if not raw:
        return RiskResult(raw="", risk="safe", layer=1,
                          verdict="Empty command.")

    # ── Step 1: Parse tokens ───────────────────────────────────────────────
    raw_tokens = _extract_tokens_from_ast(raw)

    # Find the primary command (first non-sudo/env token)
    command_name = ""
    for t in raw_tokens:
        if t not in ("sudo", "env", "time", "nice", "nohup") and not t.startswith("-"):
            command_name = t.split("/")[-1]  # handle /usr/bin/rm → rm
            break

    # ── Step 2: Build annotated token list ────────────────────────────────
    annotated_tokens = []
    for tok in raw_tokens:
        kind, risk = _classify_token(tok, command_name)
        explanation = _explain_flag(tok, command_name) if kind == "flag" else ""
        annotated_tokens.append(Token(
            text=tok,
            kind=kind,
            risk=risk,
            explanation=explanation
        ))

    # ── Step 3: Collect signals ────────────────────────────────────────────
    signals: list[Signal] = []

    # Pipe patterns (curl | bash, etc.)
    signals.extend(_detect_pipe_signals(raw))

    # Path patterns (/dev/sda, /etc/, etc.)
    signals.extend(_detect_path_signals(raw_tokens))

    # Sudo signal
    sudo_signal = _detect_sudo(raw)
    if sudo_signal:
        signals.append(sudo_signal)

    # Command + flag signals
    signals.extend(_detect_command_signals(command_name, raw_tokens))

    # Remove duplicate signals
    seen_texts = set()
    unique_signals = []
    for s in signals:
        if s.text not in seen_texts:
            seen_texts.add(s.text)
            unique_signals.append(s)
    signals = unique_signals

    # ── Step 4: Determine overall risk ────────────────────────────────────
    cmd_rules = RULES["commands"].get(command_name, {})
    base_risk = cmd_rules.get("base_risk", "safe")

    overall_risk = base_risk
    for sig in signals:
        overall_risk = _max_risk(overall_risk, sig.risk)
    for tok in annotated_tokens:
        overall_risk = _max_risk(overall_risk, tok.risk)

    # ── Step 5: Build verdict + properties ────────────────────────────────
    verdict = _build_verdict(command_name, overall_risk, signals, raw)
    props = _infer_properties(raw, overall_risk, signals)

    # ── Step 6: Dry-run suggestion ─────────────────────────────────────────
    dry_run = None
    if "-delete" in raw:
        dry_run = raw.replace("-delete", "").strip() + "  # preview first"
    elif command_name == "rm" and ("-r" in raw or "-rf" in raw):
        dry_run = f"ls {raw.split()[-1]}  # preview what would be deleted"

    return RiskResult(
        raw=raw,
        risk=overall_risk,
        layer=1,
        tokens=annotated_tokens,
        signals=signals,
        verdict=verdict,
        reversible=props["reversible"],
        scope=props["scope"],
        network=props["network"],
        privilege=props["privilege"],
        dry_run_suggestion=dry_run,
    )