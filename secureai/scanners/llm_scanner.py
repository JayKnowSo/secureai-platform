"""
SecureAI Platform — OWASP LLM Top 10 Scanner
==============================================
Static analysis engine for AI-specific vulnerabilities.

Detects:
  LLM01 — Prompt Injection (unsanitized input in prompts)
  LLM02 — Insecure Output Handling (eval/exec/os.system on LLM output)
  LLM06 — PII in Prompts (SSN, DOB, credit card in prompt construction)
  LLM08 — Excessive Agency (HTTP/file actions driven by LLM output)
"""

import re
from pathlib import Path


# ── Pattern Definitions ───────────────────────────────────────────────────────

# Variables commonly holding user-supplied input
USER_INPUT_VARS = r"(user_input|user_query|user_message|user_data|user_request|user_prompt|request_body|user_text)"

# Variables commonly holding LLM output
LLM_OUTPUT_VARS = r"(result|response|llm_response|ai_response|model_response|llm_output|ai_output|output|answer|completion)"

# PII field names
PII_VARS = r"(ssn|social_security|dob|date_of_birth|credit_card|card_number|passport|patient_name|patient_id|phone_number|email_address)"

# Dangerous sinks for LLM output
EXEC_SINKS  = r"(eval|exec)\s*\("
OS_SINKS    = r"os\.system\s*\("
HTTP_SINKS  = r"requests\.(get|post|put|delete|patch)\s*\("
FILE_SINKS  = r"open\s*\("

SKIP_DIRS = {".venv", "__pycache__", ".git", "node_modules", ".tox"}


# ── Finding Builder ───────────────────────────────────────────────────────────

def _finding(id_, title, severity, description, file_, line, code):
    return {
        "id":          id_,
        "title":       title,
        "severity":    severity,
        "description": description,
        "file":        str(file_),
        "line":        line,
        "code":        code.strip(),
    }


# ── Check Functions ───────────────────────────────────────────────────────────

def _check_llm01(lines, filepath):
    """
    LLM01 — Prompt Injection
    Detects unsanitized user input concatenated into a prompt via
    f-strings or string concatenation.
    """
    findings = []
    # f-string with user input variable inside a prompt-like assignment
    fstring_pattern  = re.compile(
        rf'prompt\s*=\s*f["\'].*\{{{USER_INPUT_VARS}}}', re.IGNORECASE
    )
    # concatenation: prompt = "..." + user_input
    concat_pattern   = re.compile(
        rf'prompt\s*=\s*.+\+\s*{USER_INPUT_VARS}', re.IGNORECASE
    )

    for i, line in enumerate(lines, start=1):
        if fstring_pattern.search(line) or concat_pattern.search(line):
            findings.append(_finding(
                id_="LLM01",
                title="Prompt Injection — Unsanitized User Input",
                severity="HIGH",
                description=(
                    "User-controlled input is injected directly into a prompt. "
                    "Attackers can override system instructions or exfiltrate data. "
                    "Validate and sanitize all user input before including in prompts."
                ),
                file_=filepath,
                line=i,
                code=line,
            ))
    return findings


def _check_llm02(lines, filepath):
    """
    LLM02 — Insecure Output Handling
    Detects LLM output passed directly to eval(), exec(), or os.system().
    """
    findings = []
    # Match: eval(result) / exec(ai_response) / os.system(response)
    exec_pattern = re.compile(
        rf'{EXEC_SINKS[:-2]}\s*\(\s*{LLM_OUTPUT_VARS}\s*\)', re.IGNORECASE
    )
    os_pattern = re.compile(
        rf'os\.system\s*\(\s*{LLM_OUTPUT_VARS}\s*\)', re.IGNORECASE
    )

    for i, line in enumerate(lines, start=1):
        if exec_pattern.search(line) or os_pattern.search(line):
            findings.append(_finding(
                id_="LLM02",
                title="Insecure Output Handling — Dangerous Sink",
                severity="CRITICAL",
                description=(
                    "LLM output is passed directly to eval(), exec(), or os.system(). "
                    "A compromised or manipulated model response can execute arbitrary code. "
                    "Never execute LLM output without strict validation and sandboxing."
                ),
                file_=filepath,
                line=i,
                code=line,
            ))
    return findings


def _check_llm06(lines, filepath):
    """
    LLM06 — PII in Prompts
    Detects PII field names used in prompt construction.
    """
    findings = []
    fstring_pii = re.compile(
        rf'prompt\s*=\s*f["\'].*\{{{PII_VARS}}}', re.IGNORECASE
    )
    concat_pii = re.compile(
        rf'prompt\s*=\s*.+\+\s*str\s*\(\s*{PII_VARS}\s*\)|'
        rf'prompt\s*=\s*.+\+\s*{PII_VARS}',
        re.IGNORECASE
    )

    for i, line in enumerate(lines, start=1):
        if fstring_pii.search(line) or concat_pii.search(line):
            findings.append(_finding(
                id_="LLM06",
                title="PII in Prompt — Sensitive Data Exposure",
                severity="HIGH",
                description=(
                    "Personally Identifiable Information (PII) is included in a prompt "
                    "sent to an external LLM API. This may violate HIPAA, GDPR, or SOC 2. "
                    "Redact or anonymize sensitive fields before including in prompts."
                ),
                file_=filepath,
                line=i,
                code=line,
            ))
    return findings


def _check_llm08(lines, filepath):
    """
    LLM08 — Excessive Agency
    Detects HTTP requests or file operations driven by LLM output.
    """
    findings = []
    http_pattern = re.compile(
        rf'requests\.(get|post|put|delete|patch)\s*\(\s*{LLM_OUTPUT_VARS}',
        re.IGNORECASE
    )
    file_pattern = re.compile(
        rf'open\s*\(\s*{LLM_OUTPUT_VARS}\b',
        re.IGNORECASE
    )

    for i, line in enumerate(lines, start=1):
        if http_pattern.search(line) or file_pattern.search(line):
            findings.append(_finding(
                id_="LLM08",
                title="Excessive Agency — LLM-Driven Action",
                severity="CRITICAL",
                description=(
                    "An HTTP request or file operation is triggered using LLM output "
                    "as the target. A manipulated model response can cause data exfiltration, "
                    "SSRF, or unauthorized file access. Always validate LLM output "
                    "before using it to drive system actions."
                ),
                file_=filepath,
                line=i,
                code=line,
            ))
    return findings


# ── Scanner Class ─────────────────────────────────────────────────────────────

class LLMScanner:
    """
    OWASP LLM Top 10 static analysis scanner.
    Scans Python files for AI-specific security vulnerabilities.
    """

    def __init__(self, path: str = "./"):
        self.path = Path(path)

    def scan(self) -> list[dict]:
        findings = []
        for pyfile in self._python_files():
            try:
                lines = pyfile.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:  # nosec B112 — skip unreadable files, continue scanning remainder
                continue

            findings.extend(_check_llm01(lines, pyfile))
            findings.extend(_check_llm02(lines, pyfile))
            findings.extend(_check_llm06(lines, pyfile))
            findings.extend(_check_llm08(lines, pyfile))

        return findings

    def _python_files(self):
        """Yield all .py files, skipping ignored directories."""
        for pyfile in self.path.rglob("*.py"):
            if not any(skip in pyfile.parts for skip in SKIP_DIRS):
                yield pyfile
