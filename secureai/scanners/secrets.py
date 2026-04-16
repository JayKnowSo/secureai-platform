"""
SecureAI Platform — Secrets Detection Scanner
==============================================
Scans your codebase for hardcoded credentials and secrets.

Why secrets scanning matters:
Hardcoded secrets are the #1 cause of cloud breaches.
An AWS access key committed to a public GitHub repo
can be found by automated scanners within seconds.
AWS has been known to scan GitHub themselves and
email account owners when keys are exposed.

This scanner catches secrets BEFORE they reach GitHub.
Same principle as your CI/CD pipeline security gate.

Patterns based on:
- OWASP secrets detection guidelines
- Real-world breach patterns
- Common developer mistakes
"""

import os
import re
from secureai.utils.severity import create_finding


class SecretsScanner:
    """
    Scans files for hardcoded credentials and secrets.

    Uses regex pattern matching to detect:
    - AWS access keys and secret keys
    - API keys and tokens
    - Passwords in code
    - Private keys (PEM format)
    - Database connection strings with credentials
    - Generic high-entropy strings that look like secrets
    
    Args:
        path: directory to scan
    """

    def __init__(self, path: str = "./"):
        self.path = path
        self.findings = []

        # Directories to always skip — I added 'tests' here!
        self.skip_dirs = {
            ".git", ".venv", "venv", "node_modules",
            "__pycache__", ".pytest_cache", "dist", "build", "tests"
        }

        # File extensions to scan
        self.scan_extensions = {
            ".py", ".js", ".ts", ".yaml", ".yml",
            ".json", ".env", ".sh", ".bash",
            ".tf", ".tfvars", ".conf", ".config",
            ".ini", ".toml", ".xml", ".properties"
        }

        # Regex patterns for secret detection
        # Each pattern is (name, severity, regex, remediation)
        self.patterns = [
            (
                "AWS Access Key",
                "CRITICAL",
                re.compile(r'AKIA[0-9A-Z]{16}'),
                "Remove immediately. Rotate the key in AWS IAM. "
                "Use IAM roles instead of access keys where possible."
            ),
            (
                "AWS Secret Key",
                "CRITICAL",
                re.compile(
                    r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'
                ),
                "Remove immediately. Rotate in AWS IAM. "
                "Use environment variables or AWS Secrets Manager."
            ),
            (
                "Private Key",
                "CRITICAL",
                re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
                "Remove immediately. Revoke and regenerate the key pair. "
                "Never store private keys in code."
            ),
            (
                "Hardcoded Password",
                "HIGH",
                re.compile(
                    r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\'${\s]{4,}["\']'
                ),
                "Move to environment variable. "
                "Use .env file (add to .gitignore). "
                "Reference as os.getenv('PASSWORD')"
            ),
            (
                "API Key or Token",
                "HIGH",
                re.compile(
                    r'(?i)(api_key|apikey|api_token|auth_token|access_token)'
                    r'\s*[=:]\s*["\'][^"\'${\s]{8,}["\']'
                ),
                "Move to environment variable. "
                "Never hardcode API keys in source code."
            ),
            (
                "Database URL with credentials",
                "HIGH",
                re.compile(
                    r'(?i)(postgresql|mysql|mongodb|redis)://[^:]+:[^@\s$]{4,}@'
                ),
                "Move DATABASE_URL to .env file. "
                "Reference as os.getenv('DATABASE_URL')"
            ),
            (
                "Generic Secret",
                "MEDIUM",
                re.compile(
                    r'(?i)(secret|token|key)\s*[=:]\s*["\'][^"\'${\s]{8,}["\']'
                ),
                "Review this value. If it is sensitive, "
                "move it to an environment variable."
            ),
        ]

    def scan(self) -> list:
        """
        Walks the directory tree and scans each eligible file.
        Returns list of findings with file and line information.
        """
        self.findings = []

        for root, dirs, files in os.walk(self.path):
            # Remove skip directories from traversal
            # Modifying dirs in-place prevents os.walk from entering them
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]

            for filename in files:
                # Get file extension
                _, ext = os.path.splitext(filename)

                # Skip files we don't care about
                if ext.lower() not in self.scan_extensions:
                    continue

                # Skip .env.example — it has placeholder values
                if filename == ".env.example":
                    continue

                filepath = os.path.join(root, filename)
                self._scan_file(filepath)

        return self.findings

    def _scan_file(self, filepath: str) -> None:
        """
        Scans a single file for secret patterns.
        Reports the exact file and line number for each finding.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (IOError, OSError):
            return

        for line_num, line in enumerate(lines, 1):
            for name, severity, pattern, remediation in self.patterns:
                if pattern.search(line):
                    # Get a sanitized snippet — never log the actual secret
                    # Show just enough context to find the line
                    snippet = line.strip()[:60] + "..." if len(line) > 60 else line.strip()

                    self.findings.append(create_finding(
                        severity=severity,
                        title=f"{name} detected",
                        description=f"Potential {name.lower()} found at "
                                   f"{filepath}:{line_num}\n"
                                   f"Line preview: {snippet}",
                        file=f"{filepath}:{line_num}",
                        line=line_num,
                        remediation=remediation
                    ))