"""
scorer.py — Layer 2 heuristic scoring for unknown commands
"""
import re
from dataclasses import dataclass, field

@dataclass
class ScoreResult:
    raw: str
    score: int
    risk: str
    signals: list = field(default_factory=list)

def score_to_risk(points: int) -> str:
    if points < 20: return "safe"
    if points < 40: return "caution"
    if points < 70: return "destructive"
    return "irreversible"

def should_escalate_to_llm(points: int) -> bool:
    return 40 <= points < 70

def score(raw: str) -> ScoreResult:
    """Calculates a heuristic risk score for an unknown command."""
    points = 0
    signals = []
    
    # Check for sudo
    if re.search(r'\bsudo\b', raw):
        points += 25
        signals.append(("sudo", 25, "Runs with administrative privileges"))
        
    # Check for pipe to bash/sh
    if re.search(r'\|.*\b(bash|sh)\b', raw):
        points += 70
        signals.append(("pipe to shell", 70, "Executes downloaded payload"))
        
    # Detect dd to block device
    if re.search(r'\bdd\b.*of=/dev/', raw):
        points += 90
        signals.append(("dd to device", 90, "Direct write to raw block device"))
        
    # Destructive keywords
    destructive_keywords = ["destroy", "delete", "remove", "prune", "flush", "drop"]
    for kw in destructive_keywords:
        if re.search(rf'\b{kw}\b', raw.lower()):
            points += 20
            signals.append((f"{kw} operation", 20, f"Command implies {kw} action"))
            
    # Force/Auto-approve flags
    force_flags = ["--force", "-f", "--auto-approve", "-y"]
    for flag in force_flags:
        if re.search(rf'\s{flag}\b', raw):
            points += 15
            signals.append((f"{flag} flag", 15, "Bypasses confirmation prompts"))
            
    # Pipeline complexity
    num_pipes = raw.count('|')
    if num_pipes > 0:
        pts = num_pipes * 5
        points += pts
        signals.append(("complex pipeline", pts, f"Contains {num_pipes} pipe(s)"))
        
    # Export PATH manipulation
    if re.search(r'\bexport\s+PATH=', raw):
        points += 20
        signals.append(("PATH modification", 20, "Changes executable search path"))
        
    risk = score_to_risk(points)
    return ScoreResult(raw=raw, score=points, risk=risk, signals=signals)
