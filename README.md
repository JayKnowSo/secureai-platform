# SecureAI Platform

![CI](https://github.com/JayKnowSo/secureai-platform/actions/workflows/security.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-28%20passing-brightgreen)
![OWASP LLM](https://img.shields.io/badge/OWASP%20LLM-Top%2010%20Coverage-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

AI-powered cloud security auditing platform. Combines static infrastructure scanning with Claude AI analysis to surface exploitability — not just vulnerability lists.

---

## Threat Coverage

| OWASP LLM Risk | ID | Control |
|---|---|---|
| Prompt Injection | LLM01 | Pattern detection on user-controlled input reaching model context |
| Insecure Output Handling | LLM02 | Output validation — detects unsanitized model responses piped to shell/eval |
| Sensitive Information Disclosure | LLM06 | PII regex scan on prompts before model submission |
| Excessive Agency | LLM08 | Detects autonomous action patterns without human-in-the-loop gates |

---

## Security Scanners

| Scanner | Target | Detections |
|---|---|---|
| Docker | Dockerfile + compose | Root execution, missing digest pins, exposed ports, hardcoded secrets, missing resource limits |
| Secrets | Full codebase | API keys, AWS credentials, private keys, database connection strings |
| CVE Analysis | Any CVE ID | Exploitability against your stack, blast radius, AI-generated remediation path |
| OWASP LLM | LLM application code | LLM01, LLM02, LLM06, LLM08 — static pattern analysis |

---

## Architecture

```
secureai/
├── cli.py
├── scanners/
│   ├── docker.py          # Dockerfile + compose static analysis
│   └── secrets.py         # Secrets detection engine
├── analyzers/
│   └── cve.py             # AI CVE analysis via Claude API
├── reporters/
│   └── html.py            # HTML report generator
└── utils/
    ├── severity.py        # CVSS-aligned severity scoring
    └── output.py          # Terminal output formatting
```

---

## Usage

```
secureai scan docker --path ./
secureai scan secrets --path ./
secureai analyze cve CVE-2024-23342
secureai report --output reports/
```

---

## Stack

Python 3.11 · Claude API (claude-sonnet) · Click · Pytest · Gitleaks · Semgrep

---

## Test Suite

28 tests — TDD-first. Word boundary assertions enforce false-positive prevention on output path detection (LLM02).

```
pytest tests/ -v
```

---

## Decisions

- [ADR-001 — CLI Architecture](docs/adr/ADR-001-cli-architecture.md)
- [ADR-002 — AI Integration Approach](docs/adr/ADR-002-ai-integration.md)
- [ADR-003 — Secrets Detection Patterns](docs/adr/ADR-003-secrets-detection.md)
- [ADR-004 — OWASP LLM Top 10 Implementation](docs/adr/ADR-004-owasp-llm-coverage.md)

---

## Roadmap

- [x] Docker infrastructure scanner
- [x] Secrets detection engine
- [x] AI CVE analysis
- [x] OWASP LLM Top 10 scanner (LLM01, LLM02, LLM06, LLM08)
- [ ] AWS infrastructure auditor
- [ ] SBOM generation via Syft CycloneDX
- [ ] Real-time CVE monitoring
- [ ] Security dashboard

## License

MIT
