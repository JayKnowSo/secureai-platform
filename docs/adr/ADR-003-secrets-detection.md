# ADR-003: Secrets Detection — Pattern-Based Approach

**Date:** 2026-03-20
**Status:** Accepted
**Author:** Jemel Padilla

## Context

SecureAI Platform needs to detect hardcoded credentials
across a codebase before they reach GitHub.

Two approaches were considered:

1. Pattern-based detection using regex
2. Entropy-based detection using Shannon entropy scoring

## Decision

Use pattern-based regex detection as the primary approach.

## Rationale

**Pattern-based detection:**
- Catches known credential formats with high precision
- Low false positive rate — patterns are specific
- Fast — no complex scoring calculations
- Readable — patterns document what they detect
- Industry standard — used by truffleHog, detect-secrets,
  GitGuardian, and GitHub's own secret scanning

**Entropy-based detection:**
- Catches unknown high-entropy strings
- High false positive rate — flags random-looking strings
- Slower — requires scoring every string in every file
- Harder to explain to non-security engineers

**Why pattern-based wins for this use case:**
The most dangerous secrets — AWS keys, API tokens,
private keys, database URLs — all have known formats.
Pattern matching catches 95% of real-world exposures
with near-zero false positives.

Entropy detection is complementary — not a replacement.
It is planned for Phase 2 as an additional layer.

## Patterns Implemented

| Pattern | Severity | Rationale |
|---------|----------|-----------|
| AWS Access Key (AKIA...) | CRITICAL | Full account compromise |
| AWS Secret Key | CRITICAL | Full account compromise |
| Private Key (PEM) | CRITICAL | Cryptographic key exposure |
| Hardcoded Password | HIGH | Credential theft |
| API Key or Token | HIGH | Service account compromise |
| Database URL with creds | HIGH | Data breach vector |
| Generic Secret | MEDIUM | Requires human review |

## Files Always Skipped

- .env.example — placeholder values by design
- .venv/ — third-party library test keys
- node_modules/ — third-party code
- .git/ — git metadata

## Consequences

**Positive:**
- High precision — low false positive rate
- Fast execution — milliseconds per file
- Self-documenting — patterns explain what they detect
- Proven approach — same method as enterprise tools
- 12 tests proving detection accuracy

**Negative:**
- Cannot detect novel/custom secret formats
- Requires pattern updates as new services emerge
- Does not catch high-entropy random strings

## Action Items

- [ ] Phase 2: add entropy scoring as secondary layer
- [ ] Quarterly: review and update patterns for new services
- [ ] Future: add .secureai-ignore file for false positive suppression

## Security Relevance

Secrets in code are the #1 cause of cloud breaches.
An AWS access key committed to a public GitHub repo
can be found by automated scanners within seconds.
This scanner catches secrets before they reach GitHub —
the same shift-left principle as the CI/CD security gate
in the FastAPI project.

## Career Relevance

Secrets scanning is a core DevSecOps capability.
Understanding why pattern-based detection is preferred
over entropy-based detection demonstrates security
engineering depth — not just tool usage.
