"""
engine.py — Core parsing and risk classification engine (Layer 1 + 2)
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

import bashlex

from explain import scorer

_HERE = Path(__file__).parent

with open(_HERE / "rules.json") as f:
    RULES = json.load(f)

with open(_HERE / "flags.json") as f:
    FLAGS_DB = json.load(f)

with open(_HERE / "suggestions.json") as f:
    SUGGESTIONS = json.load(f)

RISK_ORDER = {"safe": 0, "caution": 1, "destructive": 2, "irreversible": 3}


def _max_risk(a: str, b: str) -> str:
    return a if RISK_ORDER.get(a, 0) >= RISK_ORDER.get(b, 0) else b


@dataclass
class Token:
    text: str
    kind: str
    risk: str = "safe"
    explanation: str = ""


@dataclass
class Signal:
    text: str
    risk: str
    detail: str = ""


@dataclass
class RiskResult:
    raw: str
    risk: str
    layer: int
    tokens: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    verdict: str = ""
    reversible: str = "Yes"
    scope: str = "Unknown"
    network: str = "None"
    privilege: str = "User"
    dry_run_suggestion: Optional[str] = None
    heuristic_score: int = 0


def _extract_tokens_from_ast(command: str) -> list:
    try:
        parts = bashlex.parse(command)
        tokens = []
        for part in parts:
            _walk_ast(part, tokens, command)
        return tokens if tokens else command.split()
    except Exception:
        return command.split()


def _walk_ast(node, tokens: list, original: str):
    if node.kind == "word":
        tokens.append(original[node.pos[0]:node.pos[1]])
    if hasattr(node, "parts"):
        for part in node.parts:
            _walk_ast(part, tokens, original)


def _classify_token(token: str, command_name: str) -> tuple:
    if token in ("|", "||", "&&", ";", ">", ">>", "<", "2>", "&"):
        return "operator", "caution" if token == "|" else "safe"
    if token.startswith("-"):
        return "flag", _get_flag_risk(token, command_name)
    if token.startswith(("http://", "https://", "ftp://")):
        return "url", "safe"
    if token.startswith("/") or token.startswith("~/") or token == "~":
        return "path", _get_path_risk(token)
    if token in RULES["commands"]:
        return "command", RULES["commands"][token].get("base_risk", "safe")
    return "arg", "safe"


def _get_flag_risk(flag: str, command_name: str) -> str:
    cmd_rules = RULES["commands"].get(command_name, {})
    flag_rules = cmd_rules.get("flags", {})
    if flag in flag_rules:
        return flag_rules[flag]["risk"]
    if len(flag) > 2 and not flag.startswith("--"):
        risks = []
        for char in flag[1:]:
            f = f"-{char}"
            if f in flag_rules:
                risks.append(flag_rules[f]["risk"])
        if risks:
            return max(risks, key=lambda r: RISK_ORDER.get(r, 0))
    return "safe"


def _get_path_risk(path: str) -> str:
    for pp in RULES["path_patterns"]:
        if pp["pattern"] in path:
            return pp["risk"]
    return "safe"


def _explain_flag(flag: str, command_name: str) -> str:
    cmd_flags = FLAGS_DB.get("command_flags", {}).get(command_name, {})
    if flag in cmd_flags:
        return cmd_flags[flag]
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
    global_flags = FLAGS_DB.get("global_flags", {})
    if flag in global_flags:
        return global_flags[flag]
    return "No description available"


def _detect_pipe_signals(raw: str) -> list:
    signals = []
    for pp in RULES["pipe_patterns"]:
        if re.search(pp["pattern"], raw, re.IGNORECASE):
            signals.append(Signal(text=pp["signal"].split(":")[0], risk=pp["risk"], detail=pp["signal"]))
    return signals


def _detect_path_signals(tokens: list) -> list:
    signals = []
    seen = set()
    for token in tokens:
        for pp in RULES["path_patterns"]:
            if pp["pattern"] in token and pp["pattern"] not in seen:
                seen.add(pp["pattern"])
                signals.append(Signal(text=pp["pattern"].rstrip("/"), risk=pp["risk"], detail=pp["signal"]))
    return signals


def _detect_sudo(raw: str):
    if re.search(r'\bsudo\b', raw):
        return Signal(text="sudo: runs as root", risk="caution", detail="Superuser execution — mistakes have system-wide consequences")
    return None


def _detect_command_signals(command_name: str, all_tokens: list) -> list:
    signals = []
    cmd_rules = RULES["commands"].get(command_name, {})
    if not cmd_rules:
        return signals
    if cmd_rules.get("always_warn") and "note" in cmd_rules:
        signals.append(Signal(text=f"{command_name}: {cmd_rules['note'][:50]}", risk=cmd_rules["base_risk"], detail=cmd_rules["note"]))
    flag_rules = cmd_rules.get("flags", {})
    for token in all_tokens:
        if token.startswith("-"):
            if token in flag_rules:
                rule = flag_rules[token]
                signals.append(Signal(text=f"{token}: {rule['note'][:50]}", risk=rule["risk"], detail=rule["note"]))
            elif len(token) > 2 and not token.startswith("--"):
                for char in token[1:]:
                    f = f"-{char}"
                    if f in flag_rules:
                        rule = flag_rules[f]
                        signals.append(Signal(text=f"{f} (in {token}): {rule['note'][:45]}", risk=rule["risk"], detail=rule["note"]))
    for pattern_rule in cmd_rules.get("patterns", []):
        for token in all_tokens:
            if pattern_rule["match"] in token:
                signals.append(Signal(text=f"{pattern_rule['match']}: {pattern_rule['note'][:50]}", risk=pattern_rule["risk"], detail=pattern_rule["note"]))
    return signals


def _find_suggestion(raw: str):
    for item in SUGGESTIONS["patterns"]:
        if re.search(item["match"], raw, re.IGNORECASE):
            return f"{item['tip']}\n  Safer: {item['safer']}\n  Why:   {item['explain']}"
    return None


def _build_verdict(command_name: str, risk: str, signals: list, raw: str, layer: int, h_score: int = 0) -> str:
    cmd_rules = RULES["commands"].get(command_name, {})
    cmd_desc = cmd_rules.get("description", f"Runs '{command_name}'")
    layer_note = f" (heuristic score: {h_score})" if layer == 2 else ""
    if risk == "safe":
        return f"{cmd_desc}. No destructive operations detected — safe to run."
    if risk == "caution":
        detail = next((s.detail for s in signals if s.detail), "Review the flags carefully.")
        return f"{cmd_desc}{layer_note}. {detail} Double-check before running."
    if risk == "destructive":
        detail = next((s.detail for s in signals if s.risk in ("destructive", "irreversible")), "This command can cause data loss.")
        return f"{cmd_desc}{layer_note}. {detail} Consider a dry-run or preview first."
    detail = next((s.detail for s in signals if s.risk == "irreversible"), "This operation cannot be undone.")
    return f"{cmd_desc}{layer_note}. {detail} Make absolutely sure before running."


def _infer_properties(raw: str, risk: str, signals: list) -> dict:
    props = {"reversible": "Yes", "scope": "Local", "network": "None", "privilege": "User"}
    if risk == "irreversible":
        props["reversible"] = "No"
    elif risk == "destructive":
        props["reversible"] = "Depends"
    if "sudo" in raw or re.search(r'\bsu\b', raw):
        props["privilege"] = "Root (sudo)"
    if re.search(r'https?://|ftp://', raw):
        props["network"] = "External"
    for sig in signals:
        if any(p in sig.detail for p in ["/dev/", "disk", "filesystem", "partition"]):
            props["scope"] = "Entire disk"; break
        if any(p in sig.detail for p in ["/etc/", "/usr/", "/bin/", "system-wide"]):
            props["scope"] = "System-wide"; break
        if "recursive" in sig.detail.lower() or "directory tree" in sig.detail.lower():
            props["scope"] = "Directory tree"; break
    return props


def _dedup_signals(signals: list) -> list:
    seen = set()
    result = []
    for s in signals:
        if s.text not in seen:
            seen.add(s.text)
            result.append(s)
    return result


def analyze(raw: str) -> RiskResult:
    """
    Main entry point. Layer 1 → Layer 2 → Layer 3 (LLM).
    """
    raw = raw.strip()
    if not raw:
        return RiskResult(raw="", risk="safe", layer=1, verdict="Empty command.")

    raw_tokens = _extract_tokens_from_ast(raw)

    command_name = ""
    for t in raw_tokens:
        if t not in ("sudo", "env", "time", "nice", "nohup") and not t.startswith("-"):
            command_name = t.split("/")[-1]
            break

    annotated_tokens = []
    for tok in raw_tokens:
        kind, risk = _classify_token(tok, command_name)
        explanation = _explain_flag(tok, command_name) if kind == "flag" else ""
        annotated_tokens.append(Token(text=tok, kind=kind, risk=risk,
                                      explanation=explanation))

    signals = []
    signals.extend(_detect_pipe_signals(raw))
    signals.extend(_detect_path_signals(raw_tokens))
    sudo_sig = _detect_sudo(raw)
    if sudo_sig:
        signals.append(sudo_sig)
    signals.extend(_detect_command_signals(command_name, raw_tokens))

    is_known = command_name in RULES["commands"]
    h_score = 0
    layer = 1

    if is_known:
        base_risk = RULES["commands"][command_name].get("base_risk", "safe")
        overall_risk = base_risk
        for sig in signals:
            overall_risk = _max_risk(overall_risk, sig.risk)
        for tok in annotated_tokens:
            overall_risk = _max_risk(overall_risk, tok.risk)
    else:
        layer = 2
        h_result = scorer.score(raw)
        h_score = h_result.score
        overall_risk = h_result.risk
        for sig_text, points, detail in h_result.signals:
            signals.append(Signal(
                text=f"{sig_text} (+{points}pts)",
                risk=scorer.score_to_risk(points) if points >= 40 else "caution",
                detail=detail
            ))
        for sig in signals:
            overall_risk = _max_risk(overall_risk, sig.risk)

    signals = _dedup_signals(signals)

    # ── Layer 3: LLM for ambiguous heuristic scores ────────────────────────
    llm_from_cache = False
    if layer == 2 and scorer.should_escalate_to_llm(h_score):
        try:
            from explain import llm as llm_module
            signal_texts = [s.text for s in signals]
            llm_result = llm_module.analyze(raw, signal_texts)
            if llm_result:
                layer = 3
                llm_risk = llm_result.get("risk", overall_risk)
                overall_risk = _max_risk(overall_risk, llm_risk)
                llm_from_cache = llm_result.get("from_cache", False)
                # Override verdict with LLM's explanation if available
                llm_verdict = llm_result.get("verdict", "")
                if llm_verdict:
                    return RiskResult(
                        raw=raw,
                        risk=overall_risk,
                        layer=3,
                        tokens=annotated_tokens,
                        signals=signals,
                        verdict=llm_verdict,
                        reversible=llm_result.get("reversible", "Depends"),
                        scope=_infer_properties(raw, overall_risk, signals)["scope"],
                        network=_infer_properties(raw, overall_risk, signals)["network"],
                        privilege=_infer_properties(raw, overall_risk, signals)["privilege"],
                        dry_run_suggestion=_find_suggestion(raw),
                        heuristic_score=h_score,
                        llm_from_cache=llm_from_cache,
                    )
        except Exception:
            pass  # LLM failure is non-fatal — fall back to Layer 2 result

    verdict    = _build_verdict(command_name, overall_risk, signals, raw, layer, h_score)
    props      = _infer_properties(raw, overall_risk, signals)
    suggestion = _find_suggestion(raw)

    return RiskResult(
        raw=raw,
        risk=overall_risk,
        layer=layer,
        tokens=annotated_tokens,
        signals=signals,
        verdict=verdict,
        reversible=props["reversible"],
        scope=props["scope"],
        network=props["network"],
        privilege=props["privilege"],
        dry_run_suggestion=suggestion,
        heuristic_score=h_score,
        llm_from_cache=llm_from_cache,
    )