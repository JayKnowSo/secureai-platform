"""
SecureAI Platform — AI CVE Analyzer
=====================================
Analyzes CVEs using Claude AI to provide context-aware
security assessments specific to your stack.

Why AI for CVE analysis:
Generic CVE descriptions tell you WHAT is vulnerable.
They don't tell you:
- Is this exploitable in MY specific stack?
- What is the actual blast radius here?
- Is this HIGH CVE actually a LOW risk in my context?

This is exactly the analysis you did manually in Phase 1:
- ecdsa CVE-2024-23342: HIGH but no fix, internal only,
  accepted risk with documentation
- pip CVE-2025-8869: MEDIUM, fixable, fixed immediately

This analyzer automates that thought process using AI.

Phase 1: Returns a mocked but realistic response (free)
Phase 2: Uses real Claude API (ANTHROPIC_API_KEY required)
"""

import os
from secureai.utils.output import console


class CVEAnalyzer:
    """
    Analyzes CVEs using AI to provide context-aware assessments.

    Args:
        stack_path: optional path to requirements.txt
                   provides context about your specific stack
    """

    def __init__(self, stack_path: str = None):
        self.stack_path = stack_path
        self.stack_context = self._load_stack_context()

        # Check if real API key is available
        # If not — use mock response (free development mode)
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.use_mock = not self.api_key

        if self.use_mock:
            console.print(
                "[dim]AI mode: Mock (add ANTHROPIC_API_KEY to .env for real analysis)[/dim]"
            )

    def _load_stack_context(self) -> str:
        """
        Loads requirements.txt to give AI context about your stack.
        The more context the AI has, the more specific its analysis.
        """
        if not self.stack_path:
            # Try to find requirements.txt automatically
            if os.path.exists("requirements.txt"):
                self.stack_path = "requirements.txt"

        if self.stack_path and os.path.exists(self.stack_path):
            with open(self.stack_path, "r") as f:
                return f.read()

        return "Stack context not available"

    def analyze(self, cve_id: str) -> str:
        """
        Analyzes a CVE and returns a formatted security assessment.

        In mock mode: returns realistic example analysis
        In real mode: calls Claude API with full context

        Args:
            cve_id: the CVE identifier (e.g. CVE-2024-23342)

        Returns:
            formatted string with full security analysis
        """
        if self.use_mock:
            return self._mock_analysis(cve_id)
        else:
            return self._real_analysis(cve_id)

    def _mock_analysis(self, cve_id: str) -> str:
        """
        Returns a realistic mock analysis for development.
        Same structure as real API response — swap in one line.
        """
        return f"""
[bold yellow]═══ AI CVE Analysis: {cve_id} ═══[/bold yellow]

[bold]Vulnerability Overview[/bold]
This is a mock analysis for development mode.
Add your ANTHROPIC_API_KEY to .env for real AI analysis.

[bold]Exploitability In Your Stack[/bold]
[yellow]MODERATE[/yellow] — Based on typical Python web application stacks,
this vulnerability requires specific conditions to exploit.

[bold]Blast Radius[/bold]
If exploited, an attacker could potentially:
- Access sensitive data in the affected component
- Escalate privileges within the application context
- Pivot to other services on the same network

[bold]Remediation Path[/bold]
1. Check if a fixed version is available: pip index versions <package>
2. If fixed version exists: pip install --upgrade <package>
3. If no fix: document as accepted risk in an ADR
4. Add to monitoring backlog for upstream patch

[bold]Similar CVEs To Watch[/bold]
- Check related packages in the same dependency chain
- Monitor the NVD feed for packages in your requirements.txt
- Set up automated dependency scanning in your CI/CD pipeline

[bold]Recommended Action[/bold]
[green]DOCUMENT AND MONITOR[/green] — Follow the vulnerability management
lifecycle: Identify → Triage → Decide → Document

[dim]Add ANTHROPIC_API_KEY to .env for real AI-powered analysis
specific to your exact stack and environment.[/dim]
"""

    def _real_analysis(self, cve_id: str) -> str:
        """
        Calls Claude API for real CVE analysis.
        Only runs when ANTHROPIC_API_KEY is set in .env.
        """
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)

            prompt = f"""You are a Cloud Security Engineer analyzing a CVE.

CVE ID: {cve_id}

Stack context (requirements.txt):
{self.stack_context}

Provide a concise security assessment covering:
1. Vulnerability overview — what is it?
2. Exploitability in this specific stack — is it actually exploitable here?
3. Blast radius — what could an attacker do if they exploited it?
4. Remediation path — exact steps to fix or mitigate
5. Similar CVEs to watch — what else should they monitor?
6. Recommended action — CRITICAL/FIX NOW, HIGH/FIX SOON, 
   MEDIUM/PLAN FIX, or LOW/DOCUMENT AND MONITOR

Be specific to the stack provided. Not generic advice.
Format your response clearly with sections."""

            message = client.messages.create(
                model="claude-opus-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as e:
            return f"[red]AI analysis failed: {e}[/red]\nCheck your ANTHROPIC_API_KEY in .env"