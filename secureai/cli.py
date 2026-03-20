"""
SecureAI Platform — CLI Entry Point
====================================
All commands are defined here using Click.
Click is the industry standard Python CLI framework.

Commands:
    secureai scan docker    — scans Dockerfile + docker-compose.yml
    secureai scan secrets   — detects hardcoded credentials
    secureai analyze cve    — AI CVE analysis via Claude API
    secureai report         — generates HTML security report
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Rich console — handles all colored terminal output
# Console() creates a global instance we use throughout the CLI
console = Console()


# ── ROOT COMMAND ─────────────────────────────────────────────────────
# @click.group() turns this function into a command group
# A command group is a parent command that holds subcommands
# Example: secureai scan docker — "secureai" is the group

@click.group()
@click.version_option(version="1.0.0", prog_name="SecureAI Platform")
def cli():
    """
    SecureAI Platform — AI-powered cloud security auditing.

    Find vulnerabilities before attackers do.
    """
    pass


# ── SCAN COMMAND GROUP ───────────────────────────────────────────────
# This creates the "secureai scan" subgroup
# Which holds: secureai scan docker, secureai scan secrets

@cli.group()
def scan():
    """
    Scan your infrastructure for security issues.

    Commands:
        docker    — scan Dockerfile and docker-compose.yml
        secrets   — detect hardcoded credentials
    """
    pass


# ── SCAN DOCKER ──────────────────────────────────────────────────────
# @scan.command() registers this as a subcommand of "scan"
# @click.option() defines a CLI flag the user can pass
# --path defaults to "./" (current directory)

@scan.command()
@click.option(
    "--path",
    default="./",
    help="Path to scan. Defaults to current directory.",
    show_default=True
)
@click.option(
    "--severity",
    default="HIGH",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    help="Minimum severity level to report.",
    show_default=True
)
def docker(path, severity):
    """
    Scan Dockerfile and docker-compose.yml for security issues.

    Checks for:
    - Hardcoded credentials in compose files
    - Containers running as root
    - Missing health checks
    - Privileged containers
    - Exposed sensitive ports
    - Floating image tags (no digest pinning)
    """
    from secureai.scanners.docker import DockerScanner

    console.print(Panel(
        Text("SecureAI — Docker Scanner", style="bold blue"),
        subtitle=f"Scanning: {path}"
    ))

    scanner = DockerScanner(path=path, severity_threshold=severity)
    findings = scanner.scan()

    if not findings:
        console.print("[bold green]✓ No issues found.[/bold green]")
        return

    # Display findings using the output utility
    from secureai.utils.output import display_findings
    display_findings(findings)


# ── SCAN SECRETS ─────────────────────────────────────────────────────

@scan.command()
@click.option(
    "--path",
    default="./",
    help="Path to scan for secrets.",
    show_default=True
)
def secrets(path):
    """
    Scan codebase for hardcoded credentials and secrets.

    Detects:
    - API keys and tokens
    - Passwords in code
    - AWS access keys
    - Private keys
    - Database connection strings
    """
    from secureai.scanners.secrets import SecretsScanner

    console.print(Panel(
        Text("SecureAI — Secrets Scanner", style="bold red"),
        subtitle=f"Scanning: {path}"
    ))

    scanner = SecretsScanner(path=path)
    findings = scanner.scan()

    if not findings:
        console.print("[bold green]✓ No secrets detected.[/bold green]")
        return

    from secureai.utils.output import display_findings
    display_findings(findings)


# ── ANALYZE COMMAND GROUP ────────────────────────────────────────────

@cli.group()
def analyze():
    """
    AI-powered security analysis.

    Commands:
        cve    — analyze a CVE using Claude AI
    """
    pass


# ── ANALYZE CVE ──────────────────────────────────────────────────────

@analyze.command()
@click.argument("cve_id")
@click.option(
    "--stack",
    default=None,
    help="Path to requirements.txt for stack context.",
)
def cve(cve_id, stack):
    """
    Analyze a CVE using AI.

    CVE_ID is the CVE identifier to analyze.
    Example: secureai analyze cve CVE-2024-23342

    The AI analyzes:
    - Exploitability in your specific stack
    - Blast radius if exploited
    - Remediation path
    - Similar CVEs to watch
    """
    from secureai.analyzers.cve import CVEAnalyzer

    console.print(Panel(
        Text(f"SecureAI — AI CVE Analysis: {cve_id}", style="bold yellow"),
        subtitle="Powered by Claude AI"
    ))

    analyzer = CVEAnalyzer(stack_path=stack)
    result = analyzer.analyze(cve_id)

    console.print(result)


# ── REPORT COMMAND ───────────────────────────────────────────────────

@cli.command()
@click.option(
    "--path",
    default="./",
    help="Path to scan for report.",
    show_default=True
)
@click.option(
    "--output",
    default="reports/",
    help="Output directory for HTML report.",
    show_default=True
)
def report(path, output):
    """
    Generate a professional HTML security report.

    Runs all scanners and compiles findings into
    a professional HTML report with:
    - Executive summary
    - All findings by severity
    - AI remediation recommendations
    - CVSS-style severity scoring
    """
    from secureai.scanners.docker import DockerScanner
    from secureai.scanners.secrets import SecretsScanner
    from secureai.reporters.html import HTMLReporter

    console.print(Panel(
        Text("SecureAI — Security Report Generator", style="bold green"),
        subtitle=f"Scanning: {path} → Output: {output}"
    ))

    # Run all scanners
    docker_findings = DockerScanner(path=path).scan()
    secrets_findings = SecretsScanner(path=path).scan()

    all_findings = docker_findings + secrets_findings

    # Generate report
    reporter = HTMLReporter(output_dir=output)
    report_path = reporter.generate(all_findings)

    console.print(
        f"[bold green]✓ Report generated:[/bold green] {report_path}"
    )


# ── ENTRY POINT ──────────────────────────────────────────────────────
# This allows running: python -m secureai.cli
# As well as the installed command: secureai

if __name__ == "__main__":
    cli()