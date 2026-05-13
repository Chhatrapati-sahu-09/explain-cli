"""
cli.py — Rich terminal UI for explain-cli
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from explain.engine import analyze, RiskResult

console = Console()

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
    "irreversible": "✗",
}

RISK_LABELS = {
    "safe":         "SAFE",
    "caution":      "CAUTION",
    "destructive":  "DESTRUCTIVE",
    "irreversible": "IRREVERSIBLE",
}

TOKEN_COLORS = {
    "command":  "bold white",
    "flag":     "cyan",
    "path":     "yellow",
    "operator": "bold red",
    "url":      "blue",
    "arg":      "white",
}

TOKEN_RISK_OVERRIDE = {
    "destructive":  "bold red",
    "irreversible": "bold bright_red",
    "caution":      "yellow",
}

LAYER_LABELS = {
    1: "Layer 1 — static rules",
    2: "Layer 2 — heuristic scoring",
    3: "Layer 3 — LLM judgment",
}


def _render_banner(result: RiskResult):
    risk = result.risk
    color = RISK_COLORS[risk]
    icon = RISK_ICONS[risk]
    label = RISK_LABELS[risk]
    layer_txt = LAYER_LABELS.get(result.layer, "")

    t = Text()
    t.append(f"  {icon}  {label}", style=f"bold {color}")
    t.append(f"   [{layer_txt}]", style="dim")
    if result.layer == 2 and result.heuristic_score > 0:
        t.append(f"  score: {result.heuristic_score}", style="dim")
    console.print(Panel(t, border_style=color, padding=(0, 1)))


def _render_tokens(result: RiskResult):
    console.print()
    console.rule("[dim]Token Breakdown[/dim]", style="dim")
    console.print()
    line = Text("  $ ")
    for tok in result.tokens:
        if tok.risk in TOKEN_RISK_OVERRIDE:
            style = TOKEN_RISK_OVERRIDE[tok.risk]
        else:
            style = TOKEN_COLORS.get(tok.kind, "white")
        line.append(tok.text, style=style)
        line.append(" ")
    console.print(line)
    console.print()


def _render_flag_table(result: RiskResult):
    flags = [t for t in result.tokens if t.kind == "flag" and t.explanation]
    if not flags:
        return
    console.rule("[dim]Flag Explanations[/dim]", style="dim")
    console.print()
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim", padding=(0, 1))
    table.add_column("Flag", style="cyan", no_wrap=True)
    table.add_column("What it does", style="white")
    table.add_column("Risk", no_wrap=True)
    for tok in flags:
        risk_color = RISK_COLORS.get(tok.risk, "white")
        table.add_row(
            tok.text,
            tok.explanation,
            Text(tok.risk.upper(), style=f"bold {risk_color}")
        )
    console.print(table)


def _render_signals(result: RiskResult):
    if not result.signals:
        return
    console.rule("[dim]Risk Signals[/dim]", style="dim")
    console.print()
    for sig in result.signals:
        color = RISK_COLORS.get(sig.risk, "white")
        console.print(f"  [{color}]●[/{color}] [bold]{sig.text}[/bold]")
        if sig.detail and sig.detail != sig.text:
            console.print(f"    [dim]{sig.detail}[/dim]")
    console.print()


def _render_properties(result: RiskResult):
    console.rule("[dim]Properties[/dim]", style="dim")
    console.print()
    props = [
        ("Reversible", result.reversible),
        ("Scope",      result.scope),
        ("Network",    result.network),
        ("Privilege",  result.privilege),
    ]
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="dim",   no_wrap=True)
    table.add_column("Value", style="white", no_wrap=True)
    for key, val in props:
        if val in ("No", "Root (sudo)", "Entire disk", "System-wide"):
            val_text = Text(val, style="bold red")
        elif val in ("Depends", "Directory tree", "External"):
            val_text = Text(val, style="yellow")
        else:
            val_text = Text(val, style="green")
        table.add_row(key, val_text)
    console.print(table)


def _render_verdict(result: RiskResult):
    color = RISK_COLORS[result.risk]
    console.print(Panel(
        f"[dim]{result.verdict}[/dim]",
        title="[bold]Verdict[/bold]",
        border_style=color,
        padding=(0, 1)
    ))


def _render_suggestion(result: RiskResult):
    if not result.dry_run_suggestion:
        return
    console.print()
    console.print(Panel(
        result.dry_run_suggestion,
        title="[bold yellow]💡 Safer Alternative[/bold yellow]",
        border_style="yellow",
        padding=(0, 1)
    ))


@click.command()
@click.argument("command", nargs=-1, required=False)
@click.option("--json", "as_json", is_flag=True,
              help="Output result as JSON")
@click.option("--short", is_flag=True,
              help="Show only the risk level — one line")
def main(command, as_json, short):
    """
    \b
    Explain and risk-score any shell command.

    Examples:
      explain rm -rf /tmp/cache
      explain "curl https://get.docker.com | sudo bash"
      explain --short "chmod 777 /var/www"
      explain --json "dd if=/dev/zero of=/dev/sda"
    """
    if not command:
        click.echo(click.get_current_context().get_help())
        return

    raw = " ".join(command)
    result = analyze(raw)

    if as_json:
        import json as jsonlib
        output = {
            "command":         result.raw,
            "risk":            result.risk,
            "layer":           result.layer,
            "verdict":         result.verdict,
            "reversible":      result.reversible,
            "scope":           result.scope,
            "network":         result.network,
            "privilege":       result.privilege,
            "heuristic_score": result.heuristic_score,
            "signals": [
                {"text": s.text, "risk": s.risk, "detail": s.detail}
                for s in result.signals
            ],
            "tokens": [
                {"text": t.text, "kind": t.kind, "risk": t.risk,
                 "explanation": t.explanation}
                for t in result.tokens
            ],
            "suggestion": result.dry_run_suggestion,
        }
        click.echo(jsonlib.dumps(output, indent=2))
        return

    if short:
        color = RISK_COLORS[result.risk]
        console.print(f"[bold {color}]{RISK_LABELS[result.risk]}[/bold {color}]  {raw}")
        return

    console.print()
    console.print(f"[dim]Analyzing:[/dim] [bold]{raw}[/bold]")
    console.print()

    _render_banner(result)
    _render_tokens(result)
    _render_flag_table(result)
    _render_signals(result)
    _render_properties(result)
    _render_verdict(result)
    _render_suggestion(result)

    console.print()