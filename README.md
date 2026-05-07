# SecureAI Platform

![CI](https://github.com/JayKnowSo/secureai-platform/actions/workflows/security.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-28%20passing-brightgreen)
![OWASP LLM](https://img.shields.io/badge/OWASP%20LLM-Top%2010%20Coverage-blue)
![License](https://img.shields.io/badge/license-MIT-blue)


A command-line security auditing platform combining static infrastructure scanning with AI-powered vulnerability analysis. Built for engineers who need context-aware findings — not just a list of what broke.

## What Makes This Different

Most scanners surface vulnerabilities. SecureAI surfaces exploitability — analyzing each finding against your specific stack and returning prioritized, actionable remediation paths via Claude AI.

## Security Coverage

| Scanner | Target | Detections |
|---|---|---|
| Docker | Dockerfile + compose | Root execution, digest pinning, exposed ports, hardcoded secrets, missing resource limits |
| Secrets | Full codebase | API keys, AWS credentials, private keys, database strings |
| CVE Analysis | Any CVE ID | Exploitability in your stack, blast radius, remediation path |
| OWASP LLM Top 10 | LLM application code | LLM01 prompt injection, LLM02 insecure output, LLM06 PII exposure, LLM08 excessive agency |

## Commands

```bash
secureai scan docker --path ./
secureai scan secrets --path ./
secureai analyze cve CVE-2024-23342
secureai report --output reports/
```

## Architecture

```
secureai/
├── cli.py              # CLI entry point
├── scanners/
│   ├── docker.py       # Dockerfile + compose scanner
│   └── secrets.py      # Secrets detection engine
├── analyzers/
│   └── cve.py          # AI CVE analysis via Claude API
├── reporters/
│   └── html.py         # HTML report generator
└── utils/
    ├── severity.py     # CVSS-aligned severity scoring
    └── output.py       # Terminal output formatting
```

## Setup

```bash
git clone https://github.com/JayKnowSo/secureai-platform.git
cd secureai-platform
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Test Suite

```bash
pytest tests/ -v  # 28 tests — all passing
```

## Architecture Decisions

| ADR | Decision |
|---|---|
| [ADR-001](docs/adr/ADR-001-cli-architecture.md) | CLI framework selection |
| [ADR-002](docs/adr/ADR-002-ai-integration.md) | AI integration approach |
| [ADR-003](docs/adr/ADR-003-secrets-detection.md) | Secrets detection patterns |
| [ADR-004](docs/adr/ADR-004-owasp-llm-coverage.md) | OWASP LLM Top 10 implementation |

## Roadmap

- [x] Docker infrastructure scanner
- [x] Secrets detection engine
- [x] AI CVE analysis
- [x] OWASP LLM Top 10 scanner
- [ ] AWS infrastructure auditor
- [ ] Real-time CVE monitoring
- [ ] Security dashboard

## License

MIT
