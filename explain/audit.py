"""
audit.py — Shell history scanner

Reads ~/.bash_history or ~/.zsh_history, analyzes every command,
and prints a sorted risk report showing which commands in your
history are the most dangerous.

Usage:
    explain --audit
    explain --audit --limit 50
    explain --audit --show-safe
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from explain.engine import analyze, RiskResult

RISK_ORDER = {"safe": 0, "caution": 1, "destructive": 2, "irreversible": 3}

RISK_COLORS = {
    "safe":         "green",
    "caution":      "yellow",
    "destructive":  "red",
    "irreversible": "bright_red",
}

RISK_ICONS = {
    "safe":         "✓",
    "caution":      "⚠",
    "destructive":  "✗",
    "irreversible": "☠",
}


@dataclass
class AuditEntry:
    command: str
    result: RiskResult
    line_number: int


@dataclass
class AuditReport:
    history_file: str
    total_commands: int
    analyzed: int
    entries: list = field(default_factory=list)  # list of AuditEntry
    skipped: int = 0


def _find_history_file() -> Optional[Path]:
    if os.environ.get("HISTFILE"):
        p = Path(os.environ["HISTFILE"])
        if p.exists():
            return p

    candidates = [
        Path.home() / ".zsh_history",
        Path.home() / ".bash_history",
        Path.home() / ".history",
    ]
    for p in candidates:
        if p.exists():
            return p

    return None


def _read_history(path: Path) -> list[tuple[int, str]]:
    lines = []
    try:
        raw = path.read_text(errors="ignore")
    except Exception:
        return lines

    for i, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith(": ") and ";" in line:
            _, _, cmd = line.partition(";")
            cmd = cmd.strip()
            if cmd:
                lines.append((i, cmd))
        else:
            lines.append((i, line))

    return lines


def _deduplicate(entries: list[tuple[int, str]]) -> list[tuple[int, str]]:
    seen = {}
    for line_no, cmd in entries:
        seen[cmd] = line_no
    return [(line_no, cmd) for cmd, line_no in seen.items()]


def run(
    limit: int = 100,
    show_safe: bool = False,
    history_file: Optional[str] = None,
) -> AuditReport:
    if history_file:
        path = Path(history_file)
    else:
        path = _find_history_file()

    if not path or not path.exists():
        return AuditReport(
            history_file="not found",
            total_commands=0,
            analyzed=0,
        )

    raw_entries = _read_history(path)
    total = len(raw_entries)

    recent = raw_entries[-limit:]
    deduped = _deduplicate(recent)

    report = AuditReport(
        history_file=str(path),
        total_commands=total,
        analyzed=len(deduped),
    )

    for line_no, cmd in deduped:
        if len(cmd) < 2:
            report.skipped += 1
            continue

        try:
            result = analyze(cmd)
        except Exception:
            report.skipped += 1
            continue

        if not show_safe and result.risk == "safe":
            continue

        report.entries.append(AuditEntry(
            command=cmd,
            result=result,
            line_number=line_no,
        ))

    report.entries.sort(
        key=lambda e: RISK_ORDER.get(e.result.risk, 0),
        reverse=True
    )

    return report


def render_report(report: AuditReport, console) -> None:
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich import box

    console.print()
    console.print(Panel(
        f"[dim]History file:[/dim] {report.history_file}\n"
        f"[dim]Total commands in history:[/dim] {report.total_commands}\n"
        f"[dim]Unique commands analyzed:[/dim]  {report.analyzed}\n"
        f"[dim]Risky commands found:[/dim]      {len(report.entries)}",
        title="[bold]Shell History Audit[/bold]",
        border_style="blue",
        padding=(0, 1)
    ))
    console.print()

    if not report.entries:
        console.print("[green]✓ No risky commands found in recent history.[/green]")
        return

    counts = {"irreversible": 0, "destructive": 0, "caution": 0, "safe": 0}
    for e in report.entries:
        counts[e.result.risk] = counts.get(e.result.risk, 0) + 1

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary.add_column("Level", style="bold", no_wrap=True)
    summary.add_column("Count", no_wrap=True)

    for level in ("irreversible", "destructive", "caution", "safe"):
        if counts[level] > 0:
            color = RISK_COLORS[level]
            icon  = RISK_ICONS[level]
            summary.add_row(
                Text(f"{icon} {level.upper()}", style=f"bold {color}"),
                Text(str(counts[level]), style=f"bold {color}")
            )
    console.print(summary)
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
    )
    table.add_column("Risk",    no_wrap=True, width=14)
    table.add_column("Command", no_wrap=False)
    table.add_column("Concern", style="dim")

    for entry in report.entries:
        risk   = entry.result.risk
        color  = RISK_COLORS[risk]
        icon   = RISK_ICONS[risk]

        cmd_display = entry.command
        if len(cmd_display) > 60:
            cmd_display = cmd_display[:57] + "..."

        concern = ""
        if entry.result.signals:
            concern = entry.result.signals[0].text
            if len(concern) > 50:
                concern = concern[:47] + "..."

        table.add_row(
            Text(f"{icon} {risk.upper()}", style=f"bold {color}"),
            Text(cmd_display, style="white"),
            concern
        )

    console.print(table)
    console.print()
    console.print(
        "[dim]Tip: run [/dim][cyan]explain \"<command>\"[/cyan]"
        "[dim] on any entry above for a full breakdown.[/dim]"
    )
    console.print()
