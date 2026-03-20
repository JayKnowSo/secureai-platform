# SecureAI Platform — Roadmap

> From CLI tool to enterprise AI security platform.
> Every phase ships something real and deployable.

---

## Phase 1 — Core Scanner + AI CVE Analysis
**Status: In Progress**  
**Timeline: Week 1**

- [x] Project structure and CLI framework
- [x] Docker + compose security scanner
- [x] Secrets detection engine
- [x] AI CVE analysis (Claude API)
- [x] HTML security report generator
- [x] Full test suite
- [x] ADRs documenting all decisions

---

## Phase 2 — AWS Infrastructure Auditor
**Status: Planned**  
**Timeline: Month 2**

- [ ] IAM policy over-privilege detection
- [ ] S3 public access scanner
- [ ] Security group rule auditor
- [ ] CloudTrail compliance checker
- [ ] AWS Well-Architected Framework alignment
- [ ] Multi-region support

---

## Phase 3 — Real-Time CVE Monitoring
**Status: Planned**  
**Timeline: Month 3**

- [ ] NVD API integration
- [ ] Dependency watching from requirements.txt
- [ ] Automatic alert on new CVEs hitting your stack
- [ ] AI immediate impact assessment per alert
- [ ] Email and Slack notification support

---

## Phase 4 — Security Dashboard
**Status: Planned**  
**Timeline: Month 4**

- [ ] FastAPI backend
- [ ] Real-time security posture visualization
- [ ] CVE trend over time
- [ ] Open findings by severity
- [ ] Remediation progress tracking
- [ ] AWS compliance score
- [ ] Pipeline security history
- [ ] Deployed to AWS — live URL

---

## Phase 5 — Enterprise Platform
**Status: Planned**  
**Timeline: Month 5+**

- [ ] Multi-account AWS support
- [ ] Team collaboration features
- [ ] Executive and engineer report variants
- [ ] CI/CD pipeline integration as a service
- [ ] Compliance frameworks — SOC2, PCI-DSS, HIPAA
- [ ] Slack and Teams integration
- [ ] API for third-party integrations

---

## The Vision

> Most security tools tell you WHAT is vulnerable.
> SecureAI tells you WHY it matters in YOUR context
> and EXACTLY what to do about it.
>
> Built by a Cloud Security Engineer
> who got tired of generic security advice.