# SecureAI Platform

> AI-powered cloud security auditing platform for engineers 
> who want to find vulnerabilities before attackers do.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## What It Does

SecureAI Platform is a command-line security auditing tool 
that combines automated infrastructure scanning with 
AI-powered vulnerability analysis.

**The problem it solves:**
Most security tools tell you WHAT is vulnerable.
SecureAI tells you WHY it matters in YOUR specific context
and EXACTLY what to do about it.

---

## Commands

### Scan Docker Infrastructure
```bash
secureai scan docker --path ./
```
Analyzes your Dockerfile and docker-compose.yml for:
- Hardcoded credentials
- Privileged containers
- Missing health checks
- Non-root user violations
- Exposed sensitive ports
- Missing resource limits
- Floating image tags (no digest pinning)

### Scan For Secrets
```bash
secureai scan secrets --path ./
```
Detects hardcoded credentials across your entire codebase:
- API keys and tokens
- Passwords and secrets
- AWS access keys
- Private keys and certificates
- Database connection strings

### AI CVE Analysis
```bash
secureai analyze cve CVE-2024-23342
```
AI analyzes the CVE in the context of your stack:
- Is this exploitable in your environment?
- What is the blast radius?
- What is the remediation path?
- What similar CVEs should you watch?

### Generate Security Report
```bash
secureai report --output reports/
```
Generates a professional HTML security report:
- Executive summary
- All findings by severity
- AI-generated remediation recommendations
- CVSS-style severity scoring

---

## Installation
```bash
# Clone the repository
git clone https://github.com/JayKnowSo/secureai-platform.git
cd secureai-platform

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
```

---

## Quick Start
```bash
# Scan your Docker setup
secureai scan docker --path ./

# Scan for hardcoded secrets
secureai scan secrets --path ./

# Analyze a specific CVE
secureai analyze cve CVE-2024-23342

# Generate full security report
secureai report
```

---

## Architecture
```
secureai/
├── cli.py              # CLI entry point — all commands defined here
├── scanners/
│   ├── docker.py       # Dockerfile + compose scanner
│   └── secrets.py      # Secrets detection engine
├── analyzers/
│   └── cve.py          # AI CVE analysis — Claude API
├── reporters/
│   └── html.py         # HTML report generator
└── utils/
    ├── severity.py     # Severity scoring and thresholds
    └── output.py       # Rich terminal formatting
```

---

## Security Decisions

All architecture decisions are documented in `docs/adr/`:

- [ADR-001](docs/adr/ADR-001-cli-architecture.md) — CLI framework selection
- [ADR-002](docs/adr/ADR-002-ai-integration.md) — AI integration approach
- [ADR-003](docs/adr/ADR-003-secrets-detection.md) — Secrets detection patterns

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full platform vision.

**Phase 1 (Current):** Core scanner + AI CVE analysis  
**Phase 2 (Planned):** AWS infrastructure auditor  
**Phase 3 (Planned):** Real-time CVE monitoring  
**Phase 4 (Planned):** Security dashboard  
**Phase 5 (Planned):** Enterprise multi-account support  

---

## Author

**Jemel Padilla**  
Cloud Security Engineer | DevSecOps  
Bronx born. Orlando built.  

[LinkedIn](https://linkedin.com/in/jemelpadilla) | 
[GitHub](https://github.com/JayKnowSo)

---

## License

MIT License — see [LICENSE](LICENSE) for details.