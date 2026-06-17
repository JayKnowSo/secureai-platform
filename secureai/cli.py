"""
SecureAI Platform — CLI Entry Point
====================================
Phase 4, Day 5: AWS Cloud-Native Integration
All commands are defined here using Click.
Click is the industry standard Python CLI framework.
"""

import click
import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from secureai.scanners.docker import DockerScanner
from secureai.scanners.secrets import SecretsScanner

# Rich console — handles all colored terminal output
console = Console()

# ── AWS SECRET LOADER ────────────────────────────────────────────────
def get_ai_api_key():
    """
    Fetches the Anthropic API key from AWS SSM Parameter Store.
    This replaces insecure local .env files.
    """
    ssm = boto3.client('ssm', region_name='us-east-1') # Ensure region matches your TF
    parameter_name = "/secureai/dev/anthropic_api_key"
    
    try:
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return response['Parameter']['Value']
    except ClientError as e:
        console.print(f"[bold red]AWS Error:[/bold red] Could not retrieve secret {parameter_name}")
        console.print(f"[yellow]Reason:[/yellow] {e.response['Error']['Code']}")
        return None
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return None

# ── ROOT COMMAND ─────────────────────────────────────────────────────
@click.group()
@click.version_option(version="1.0.0", prog_name="SecureAI Platform")
def cli():
    """
    SecureAI Platform — AI-powered cloud security auditing.
    Find vulnerabilities before attackers do.
    """
    pass

# ── SCAN COMMAND GROUP ───────────────────────────────────────────────
@cli.group()
def scan():
    """Scan your infrastructure for security issues."""
    pass


# ── SCAN DOCKER ──────────────────────────────────────────────────────
@scan.command()
@click.option("--path", default="./", help="Path to scan.", show_default=True)
@click.option("--severity", default="HIGH", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), show_default=True)
def docker(path, severity):
    """Scan Dockerfile and docker-compose.yml for security issues."""
    console.print(Panel(Text("SecureAI — Docker Scanner", style="bold blue"), subtitle=f"Scanning: {path}"))

    scanner = DockerScanner(path=path, severity_threshold=severity)
    findings = scanner.scan()

    if not findings:
        console.print("[bold green]✓ No issues found.[/bold green]")
        return

    from secureai.utils.output import display_findings
    display_findings(findings)

# ── SCAN SECRETS ─────────────────────────────────────────────────────
@scan.command()
@click.option("--path", default="./", help="Path to scan for secrets.", show_default=True)
def secrets(path):
    """Scan codebase for hardcoded credentials."""
    console.print(Panel(Text("SecureAI — Secrets Scanner", style="bold red"), subtitle=f"Scanning: {path}"))

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
    """AI-powered security analysis."""
    pass

# ── ANALYZE CVE ──────────────────────────────────────────────────────
@analyze.command()
@click.argument("cve_id")
@click.option("--stack", default=None, help="Path to requirements.txt for context.")
def cve(cve_id, stack):
    """Analyze a CVE using Claude AI (Cloud-Stored API Key)."""
    
    # FETCH SECRET FROM AWS
    api_key = get_ai_api_key()
    
    if not api_key or "REPLACE_ME" in api_key:
        console.print("[bold red]Aborting:[/bold red] Valid Anthropic API Key not found in AWS SSM.")
        console.print("[dim]Note: Run 'aws ssm put-parameter' or use the console to set the real value.[/dim]")
        return

    from secureai.analyzers.cve import CVEAnalyzer
    console.print(Panel(
        Text(f"SecureAI — AI CVE Analysis: {cve_id}", style="bold yellow"),
        subtitle="Powered by Claude AI (AWS SSM Auth)"
    ))

    # Pass the secret directly to the analyzer
    analyzer = CVEAnalyzer(api_key=api_key, stack_path=stack)
    result = analyzer.analyze(cve_id)
    console.print(result)

# --- REPORT COMMAND ---
@cli.command()
@click.option("--path", default="./", help="Path to scan.", show_default=True)
@click.option("--output", default="reports/", help="Output directory.", show_default=True)
def report(path, output):
    """Generate a professional HTML security report."""
    from secureai.scanners.secrets import SecretsScanner
    from secureai.reporters.html import HTMLReporter

    console.print(Panel(Text("SecureAI — Security Report Generator", style="bold green")))

    # Fixed: Explicitly using the arguments passed into the function
    docker_findings = DockerScanner(path=path).scan()
    secrets_findings = SecretsScanner(path=path).scan()
    all_findings = docker_findings + secrets_findings

    reporter = HTMLReporter(output_dir=output)
    report_path = reporter.generate(all_findings)

    console.print(f"[bold green]✓ Report generated:[/bold green] {report_path}")

# ── SCAN LLM ─────────────────────────────────────────────────────────
@scan.command()
@click.option("--path", default="./", help="Path to scan for OWASP LLM Top 10 issues.", show_default=True)
def llm(path):
    """Scan Python codebase for OWASP LLM Top 10 vulnerabilities."""
    from secureai.scanners.llm_scanner import LLMScanner

    console.print(Panel(Text("SecureAI — OWASP LLM Top 10 Scanner", style="bold magenta"), subtitle=f"Scanning: {path}"))

    scanner = LLMScanner(path=path)
    findings = scanner.scan()

    if not findings:
        console.print("[bold green]✓ No LLM vulnerabilities detected.[/bold green]")
        return

    from secureai.utils.output import display_findings
    display_findings(findings)

# ── SBOM COMMAND ─────────────────────────────────────────────────────
@cli.command()
@click.option("--path", required=True, type=click.Path(exists=True), help="Path to project root.")
@click.option("--format", "fmt", default="cyclonedx-json", type=click.Choice(["cyclonedx-json", "cyclonedx-xml"]), show_default=True)
def sbom(path, fmt):
    """Generate a CycloneDX Software Bill of Materials for a project."""
    import json
    from pathlib import Path

    console.print(Panel(Text("SecureAI — SBOM Generator", style="bold cyan"), subtitle=f"Target: {path} | Format: {fmt}"))

    req_file = Path(path) / "requirements.txt"
    components = []

    if req_file.exists():
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
            else:
                name, version = line, "unknown"
            components.append({"name": name.strip(), "version": version.strip()})

    if not components:
        console.print("[yellow]Warning:[/yellow] No components found in requirements.txt")

    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {"type": "library", "name": c["name"], "version": c["version"]}
            for c in components
        ]
    }

    if fmt == "cyclonedx-json":
        output = json.dumps(bom_data, indent=2)
        console.print(output)
    else:
        lines = ['<?xml version="1.0" ?>', '<bom xmlns="http://cyclonedx.org/schema/bom/1.4">', '  <components>']
        for c in components:
            lines.append(f'    <component type="library"><name>{c["name"]}</name><version>{c["version"]}</version></component>')
        lines += ['  </components>', '</bom>']
        console.print("\n".join(lines))

    console.print(f"\n[bold green]✓ SBOM generated — {len(components)} components.[/bold green]")


if __name__ == "__main__":
    cli()
