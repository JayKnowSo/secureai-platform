# ADR-002: AI Integration Approach — Mock First, Real API Second

**Date:** 2026-03-20
**Status:** Accepted
**Author:** Jemel Padilla

## Context

SecureAI Platform includes an AI CVE analysis feature
that provides context-aware security assessments.

Two implementation approaches were considered:

1. Build directly against Claude API from day one
2. Build mock-first, swap in real API when ready

The AI feature requires:
- An Anthropic API key (costs money per request)
- Network access to api.anthropic.com
- Graceful degradation when key is unavailable

## Decision

Implement mock-first with a clean swap path to real API.

The CVEAnalyzer class checks for ANTHROPIC_API_KEY:
- If present: uses real Claude API
- If absent: returns realistic mock response

The interface is identical in both modes.
Swapping from mock to real requires zero code changes —
just adding the API key to .env.

## Rationale

**Development cost:**
Building against the real API during development means
every test run costs money. Mock-first means zero cost
during development and CI/CD pipeline runs.

**Portability:**
Anyone cloning the repo can run the full tool immediately
without needing an API key. Lowers the barrier to entry
for contributors and portfolio reviewers.

**Production ready:**
The mock response demonstrates the exact output format
the real API produces. It is not a placeholder —
it is a realistic example of the analysis output.

**Single responsibility:**
The analyzer class handles both modes cleanly.
No if/else scattered throughout the codebase.
One class, one decision point, clean interface.

## Consequences

**Positive:**
- Zero cost during development
- Full functionality without API key
- CI/CD pipeline runs free
- Anyone can clone and run immediately
- Clean upgrade path to real AI

**Negative:**
- Mock responses are not personalized to actual CVE data
- Requires documentation to explain mock vs real mode

## Action Items

- [ ] Add ANTHROPIC_API_KEY to .env when ready
- [ ] Test real API responses against mock format
- [ ] Phase 3: add NVD API for real CVE data context

## Security Relevance

API keys are secrets. The mock-first approach ensures
the tool never fails or exposes errors due to missing
credentials. The ANTHROPIC_API_KEY follows the same
.env discipline established in the FastAPI project —
never hardcoded, always environment variable.

## Career Relevance

Mock-first development is a professional pattern used
in enterprise software. It demonstrates:
- Cost awareness
- Test-driven thinking
- Clean interface design
- Production readiness mindset
