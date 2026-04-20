# ADR-004: OWASP LLM Top 10 Static Analysis Scanner

**Date:** 2026-04-20
**Status:** Accepted

## Context

SecureAI Platform audits security infrastructure. As AI-powered applications become
common attack surfaces, the tool needed to detect AI-specific vulnerabilities defined
by the OWASP LLM Top 10 — a framework for the most critical risks in LLM-integrated systems.

No existing open-source CLI tool combined Docker/secrets scanning with LLM-specific
static analysis in a single auditing platform.

## Decision

Implement a static analysis engine (`llm_scanner.py`) that scans Python codebases for
four high-priority OWASP LLM Top 10 vulnerabilities using regex pattern matching:

- **LLM01 — Prompt Injection:** Detects unsanitized user input concatenated into prompts
  via f-strings or string concatenation.
- **LLM02 — Insecure Output Handling:** Detects LLM output passed to `eval()`, `exec()`,
  or `os.system()` — arbitrary code execution risk.
- **LLM06 — PII in Prompts:** Detects PII field names (SSN, DOB, credit card, etc.)
  included in prompt construction — HIPAA/GDPR exposure risk.
- **LLM08 — Excessive Agency:** Detects HTTP requests or file operations driven directly
  by LLM output — SSRF and unauthorized action risk.

Pattern matching operates on variable name conventions rather than runtime analysis,
enabling zero-dependency static scanning with no API calls required.

## Rationale

**Static analysis chosen over runtime analysis** because it requires no execution
environment, no mocking, and produces zero false positives from legitimate LLM calls
that happen to use dangerous patterns at runtime.

**Regex over AST parsing** for speed of implementation and zero additional dependencies.
The tradeoff is reduced precision on complex expressions — acceptable for v0.2.0 scope.

**Word boundary matching** added to `open()` detection after `output_path` triggered
a false positive due to `output` appearing in `LLM_OUTPUT_VARS`. TDD caught this
immediately — the fix was a `\b` boundary assertion.

## Consequences

- 16 new tests, all passing — zero false positives on clean code, accurate detection
  on all four vulnerability classes
- Total test suite: 28 passing
- `secureai scan llm --path ./` available as CLI command
- Scanner skips `.venv`, `__pycache__`, `.git`, `node_modules` to prevent false positives
  from third-party libraries
- Self-scanning CI pipeline now detects LLM vulnerabilities in SecureAI itself on every push
