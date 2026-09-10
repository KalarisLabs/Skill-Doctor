# Security Policy

Skill Doctor is a security scanner for AI agent skill files. We treat the security of this scanner, its analysis engines, and its supply chain with the highest priority.

## Reporting a Vulnerability

**DO NOT file public GitHub issues for security vulnerabilities, zero-days, or exploit payloads.**

If you discover a vulnerability in Skill Doctor, please report it privately:

1. **GitHub Security Advisory**: Submit a private report via [GitHub Security Advisories](https://github.com/KalarisLabs/Skill-Doctor/security/advisories/new).
2. **Direct Email**: If GitHub Advisories are unavailable, email **`security@kalarislabs.com`** with:
   - A clear description of the issue
   - Reproduction steps or proof of concept
   - Impact assessment
   - Your name and affiliation for disclosure credits (optional)

### Policy & Responsible Disclosure
- We acknowledge reports within **48 hours**.
- We aim to provide a remediation patch within **14 days** of confirmation.
- We request that you observe coordinated disclosure: please do not publicly discuss or publish details of the vulnerability until a patch has been released.

## Handling of Malicious Samples

Skill Doctor contains rules and detectors for 11 threat classes (SDTM-v1). 

- **Do NOT open issues or PRs containing active malware, live command-and-control URLs, or unredacted credentials.**
- To contribute detection rules or test fixtures, refer to [CONTRIBUTING.md](CONTRIBUTING.md). Attack test fixtures must follow the synthetic test fixture conventions and be quarantined in `tests/fixtures/attack/` using harmless mock endpoints.
