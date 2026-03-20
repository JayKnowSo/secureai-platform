"""
SecureAI Platform — Severity Scoring Utilities
===============================================
Defines severity levels and scoring for security findings.

Severity levels follow industry standard CVSS scoring:
    CRITICAL  = CVSS 9.0-10.0 — immediate action required
    HIGH      = CVSS 7.0-8.9  — urgent, fix soon
    MEDIUM    = CVSS 4.0-6.9  — important, plan fix
    LOW       = CVSS 0.1-3.9  — informational, fix when possible

Why this matters:
Not all vulnerabilities are equal. A CRITICAL CVE with a
public exploit is fundamentally different from a LOW finding
about a missing label. Severity scoring lets engineers
prioritize correctly — same discipline as your Trivy triage.
"""

from enum import Enum


class Severity(Enum):
    """
    Severity levels for security findings.
    Using an Enum prevents typos and enables comparisons.
    Example: Severity.CRITICAL > Severity.HIGH → True
    """
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


# Severity threshold mapping
# Used to filter findings below a certain level
# Example: threshold=HIGH shows CRITICAL and HIGH only
SEVERITY_THRESHOLDS = {
    "CRITICAL": [Severity.CRITICAL],
    "HIGH": [Severity.CRITICAL, Severity.HIGH],
    "MEDIUM": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
    "LOW": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
}


def meets_threshold(severity: str, threshold: str) -> bool:
    """
    Returns True if a finding's severity meets or exceeds the threshold.

    Args:
        severity:  the finding's severity level (CRITICAL/HIGH/MEDIUM/LOW)
        threshold: the minimum level to report (from .env or CLI flag)

    Example:
        meets_threshold("HIGH", "MEDIUM") → True
        meets_threshold("LOW", "HIGH")    → False
    """
    allowed = SEVERITY_THRESHOLDS.get(threshold.upper(), [])
    finding_sev = Severity[severity.upper()]
    return finding_sev in allowed


def create_finding(
    severity: str,
    title: str,
    description: str,
    file: str = "N/A",
    line: int = None,
    remediation: str = "See documentation"
) -> dict:
    """
    Creates a standardized finding dictionary.
    All scanners use this function to ensure consistent output format.

    Args:
        severity:    CRITICAL, HIGH, MEDIUM, or LOW
        title:       short description (shown in table)
        description: full explanation of the issue
        file:        which file contains the issue
        line:        line number in the file (if applicable)
        remediation: exact steps to fix the issue

    Returns:
        dict with all finding fields standardized
    """
    return {
        "severity": severity.upper(),
        "title": title,
        "description": description,
        "file": file,
        "line": line,
        "remediation": remediation
    }