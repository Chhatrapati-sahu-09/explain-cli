"""
cli.py — Full Rich terminal UI with flag tooltips, Layer badge, suggestion panel
"""
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout
from rich.align import Align

from explain.engine import analyze

console = Console()

RISK_COLORS = {
    "safe": "bold green",
    "caution": "bold yellow",
    "destructive": "bold orange3",
    "irreversible": "bold red"
}

@click.command()
@click.argument("command", nargs=-1, required=True)
def main(command):
    """Analyze a bash command and show risk, token details, and suggestions."""
    raw_command = " ".join(command)
    result = analyze(raw_command)

    # Header Panel with overall verdict
    color = RISK_COLORS.get(result.risk, "white")
    layer_badge = f"[dim white](Layer {result.layer} Analysis)[/dim white]"
    header_text = Text()
    header_text.append(f"RISK: {result.risk.upper()}\n", style=color)
    header_text.append(result.verdict, style="white")

    console.print(Panel(header_text, title=f"[bold]Explain CLI[/bold] {layer_badge}", border_style=color))

    # Token Table (Breakdown & tooltips)
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Token")
    table.add_column("Type", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Explanation / Note")

    for token in result.tokens:
        tok_color = RISK_COLORS.get(token.risk, "white")
        table.add_row(
            token.text,
            token.kind,
            f"[{tok_color}]{token.risk.upper()}[/{tok_color}]" if token.risk != "safe" else "SAFE",
            token.explanation or ""
        )
    
    console.print(table)
    
    # Context / Signals Panel
    if result.signals or result.reversible != "Yes":
        context_table = Table.grid(padding=(0, 2))
        context_table.add_column(style="bold magenta", justify="right")
        context_table.add_column()
        
        context_table.add_row("Reversible?", result.reversible)
        context_table.add_row("Privilege:", result.privilege)
        context_table.add_row("Network:", result.network)
        context_table.add_row("Scope:", result.scope)
        
        console.print(Panel(context_table, title="Context & Signals", border_style="magenta"))

    # Suggestions / Alternatives
    if result.dry_run_suggestion:
        console.print(Panel(result.dry_run_suggestion, title="💡 Suggestion / Safer Alternative", border_style="cyan"))
        
if __name__ == "__main__":
    main()