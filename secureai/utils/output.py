"""
SecureAI Platform — Terminal Output Utilities
=============================================
Handles all colored terminal output using Rich.

Rich is a Python library for beautiful terminal formatting.
It provides: colored text, tables, panels, progress bars.

Why Rich over print():
- Professional looking output
- Severity-colored findings (RED for CRITICAL, YELLOW for HIGH)
- Tables for multiple findings
- Consistent styling across all commands
"""

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

# Global console instance
# All output goes through this — never use print() directly
console = Console()

# Severity color mapping
# Maps each severity level to a Rich color string
# CRITICAL = bold red (immediate attention)
# HIGH     = red (urgent)
# MEDIUM   = yellow (important)
# LOW      = blue (informational)
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "cyan"
}


def severity_color(severity: str) -> str:
    """
    Returns the Rich color string for a given severity level.
    Used to color-code findings in terminal output.
    """
    return SEVERITY_COLORS.get(severity.upper(), "white")


def display_findings(findings: list) -> None:
    """
    Displays a list of security findings as a formatted table.

    Each finding is a dict with:
        severity:    CRITICAL, HIGH, MEDIUM, LOW
        title:       short description of the finding
        description: detailed explanation
        file:        which file the issue was found in
        line:        line number (if applicable)
        remediation: how to fix it

    Args:
        findings: list of finding dictionaries
    """
    if not findings:
        console.print("[bold green]✓ No findings to display.[/bold green]")
        return

    # Count findings by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1

    # Print summary line
    console.print(
        f"\n[bold]Findings:[/bold] "
        f"[bold red]{counts['CRITICAL']} CRITICAL[/bold red]  "
        f"[red]{counts['HIGH']} HIGH[/red]  "
        f"[yellow]{counts['MEDIUM']} MEDIUM[/yellow]  "
        f"[blue]{counts['LOW']} LOW[/blue]\n"
    )

    # Build findings table
    # Rich Table automatically handles column widths and borders
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="bright_black"
    )

    # Define columns
    table.add_column("Severity", width=10)
    table.add_column("Title", width=35)
    table.add_column("File", width=25)
    table.add_column("Remediation", width=35)

    # Add each finding as a row
    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        color = severity_color(severity)

        table.add_row(
            Text(severity, style=color),
            finding.get("title", "Unknown"),
            finding.get("file", "N/A"),
            finding.get("remediation", "See documentation")
        )

    console.print(table)


def display_banner() -> None:
    """
    Displays the SecureAI Platform banner.
    Called on startup to identify the tool.
    """
    console.print(r"""
[bold blue]
  ____                           _    ___ 
 / ___|  ___  ___ _   _ _ __ ___  / \  |_ _|
 \___ \ / _ \/ __| | | | '__/ _ \/  /   | | 
  ___) |  __/ (__| |_| | | |  __/\_/  _ | | 
 |____/ \___|\___|\__,_|_|  \___(_) (_)|___|
[/bold blue]
[dim]AI-powered cloud security auditing platform[/dim]
    """)