<p align="center">
  <img src="public/skill%20doctor%20banner.png" alt="Skill Doctor — Multi-Layer Security for AI Agent Skill Files" width="100%" />
</p>

<h1 align="center">Skill Doctor</h1>

<p align="center">
  <strong>Multi-layer security platform for AI agent skill files.</strong><br/>
  Detect malicious, deceptive, or vulnerable skills before they reach your agent runtime.
</p>

<p align="center">
  <a href="https://github.com/KalarisLabs/Skill-Doctor/actions"><img src="https://img.shields.io/github/actions/workflow/status/KalarisLabs/Skill-Doctor/ci.yml?style=flat-square&label=CI" alt="CI Status" /></a>
  <a href="https://pypi.org/project/skill-doctor/"><img src="https://img.shields.io/pypi/v/skill-doctor?style=flat-square&color=blue" alt="PyPI Version" /></a>
  <a href="https://github.com/KalarisLabs/Skill-Doctor/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-green?style=flat-square" alt="License" /></a>
  <a href="https://skilldoctor.kalarislabs.com"><img src="https://img.shields.io/badge/web-skilldoctor.kalarislabs.com-blueviolet?style=flat-square" alt="Website" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> · <a href="#how-it-works">How It Works</a> · <a href="#threat-detection">Threat Detection</a> · <a href="#cli-reference">CLI Reference</a> · <a href="#development">Development</a> · <a href="#roadmap">Roadmap</a>
</p>

---

**Skill Doctor** is Kalaris Labs' first open-source infrastructure project — a security scanner purpose-built for the emerging attack surface of AI agent skill files (`SKILL.md`, `.clauderules`, `AGENTS.md`, MCP server configs).

> **Why this matters:** Skill files execute with the full trust context of your AI agent — access to tools, file systems, APIs, and downstream agents. A single compromised skill can exfiltrate credentials, inject backdoors, or escalate privileges across your entire agent ecosystem.

---

## Quick Start

### Install via pip

```bash
pip install skill-doctor
```

### Scan a skill

```bash
# Scan a local skill directory
skill-doctor scan ./my-skill/

# Scan a single file
skill-doctor scan SKILL.md

# Scan a zip archive
skill-doctor scan skill-bundle.zip

# Scan from a URL
skill-doctor scan https://example.com/skills/agents.md

# Fail on HIGH severity findings (CI/CD gating)
skill-doctor scan ./skills/ --fail-on HIGH
```

### Web Interface

Use [skilldoctor.kalarislabs.com](https://skilldoctor.kalarislabs.com) for drag-and-drop scanning with zero installation — or deploy your own instance.

---

## How It Works

Skill Doctor runs a multi-layer analysis pipeline. Each layer is independent — the system degrades gracefully if a layer is unavailable.

| Layer | Engine | What It Does | Speed |
|-------|--------|-------------|-------|
| **Layer 1** | YARA-X + Python AST + Entropy + Unicode | Pattern matching, taint analysis, encoded payload detection | < 500ms |
| **Layer 2** | Groq LLM (Llama 3.3 70B) | Intent mismatch, hidden instruction extraction, tool scope audit | 3–8s |
| **Layer 3** | E2B Firecracker microVM | Runtime behavior observation in sandboxed agent environment | 15–60s |
| **Layer 4** | Community Threat DB | Hash-based lookup against known-malicious skill fingerprints | < 50ms |

### Architecture

Built on a **Cloudflare-first** edge infrastructure:

- **Web UI** — Cloudflare Pages (Next.js)
- **API Gateway** — Cloudflare Workers (Hono.js)
- **Database** — Cloudflare D1 (SQLite at edge)
- **Cache** — Cloudflare KV (scan result caching)
- **Queue** — Cloudflare Queues (async scan jobs)
- **Storage** — Cloudflare R2 (report storage)
- **Scanner** — fly.io (Python FastAPI)
- **LLM** — Groq API (via Cloudflare AI Gateway)
- **Sandbox** — E2B (Firecracker microVM)

---

## Threat Detection

Skill Doctor detects **10 attack classes** synthesized from the OWASP Agentic Skills Top 10, OWASP MCP Top 10, and real-world campaigns:

| ID | Attack Class | Examples |
|----|-------------|----------|
| **SD-01** | Prompt Injection | Direct override, ASCII smuggling, encoded payloads |
| **SD-02** | Command Injection | `subprocess.run(shell=True)`, `eval()`, `exec()`, `pickle.loads()` |
| **SD-03** | Data Exfiltration | `~/.aws/credentials`, `$GITHUB_TOKEN`, HTTP callbacks |
| **SD-04** | Privilege Escalation | Tool scope violations, cross-agent impersonation |
| **SD-05** | Supply Chain Tampering | Hash mismatch, `.pyc` cache poisoning, typosquatting |
| **SD-06** | SSRF via Tool Parameters | Unvalidated URL parameters in tool descriptions |
| **SD-07** | Tool Poisoning | Shadow tool registration, schema manipulation |
| **SD-08** | Persistent Backdoors | Writes to `CLAUDE.md`, `.cursor/rules`, cron jobs |
| **SD-09** | Context Window Flooding | Oversized outputs crowding security-relevant context |
| **SD-10** | Obfuscation & Evasion | Homoglyphs, multi-layer encoding, logic bombs |

---

## CLI Reference

```bash
# Core scanning
skill-doctor scan ./path/                     # Scan directory
skill-doctor scan skill.zip                   # Scan archive
skill-doctor scan skill.md                    # Scan single file
skill-doctor scan https://example.com/s.md    # Scan from URL
skill-doctor scan-all ./skills/               # Recursive scan

# Output formats
--output sarif|json|html|pdf                  # Report format
--fail-on CRITICAL|HIGH|MEDIUM|LOW            # CI/CD exit code

# Layer control
--no-llm                                      # Skip LLM semantic pass
--no-sandbox                                  # Skip E2B sandbox

# Rule packs
--rule-pack core,supply_chain                 # Select rule packs

# Utilities
skill-doctor diff v1/ v2/                    # Diff scan two versions
skill-doctor mcp                              # Run as MCP server
skill-doctor rules                            # List loaded rule packs
skill-doctor version                          # Print version
```

---

## Test Results

Scan of the [Kane CLI browser automation skill](https://testmuai.com/kane-cli/agents.md) using the Skill Doctor `master` branch:

```
SKILL DOCTOR v0.1.0
by Kalaris Labs

[TARGET] https://testmuai.com/kane-cli/agents.md
[NORMALIZE] Normalizing bundle...
[HASH] Bundle hash: 3335ef7aacedf6bf...
[THREAT DB] Checking threat database...
[STATIC] Running static analysis...
[STATIC] Found 0 static findings
[LLM] Running LLM semantic analysis...
   Found 0 semantic findings
[SANDBOX] Behavioral sandbox deferred to Week 2
[TIME] Scanning completed in 1.20s

============================================================
SCAN RESULTS
============================================================
Risk Level: SAFE
Risk Score: 0.0 / 10.0
Layers Run: static, semantic
Duration: 1.20s

[SUMMARY] 0 findings total:

[SAFE] No findings detected. Skill appears safe.
```

---

## Development

### Prerequisites

```bash
# Install tools
brew install uv node docker      # macOS
# Or: scoop install uv nodejs docker   # Windows

# API keys (free tiers are sufficient)
# Groq:  https://console.groq.com
# E2B:   https://e2b.dev
# Clerk: https://clerk.com
```

### Local Development

```bash
# Clone
git clone https://github.com/KalarisLabs/Skill-Doctor.git
cd Skill-Doctor

# Install dependencies
uv sync --all-extras

# Run CLI locally
uv run python -m skill_doctor.cli scan ./test-skill/

# Start FastAPI backend
uv run uvicorn skill_doctor.api.main:app --reload

# Start Next.js web UI
cd web && npm install && npm run dev
```

### Running Tests

```bash
# Run all tests
uv run python -m pytest tests/ -v

# Run a specific test file
uv run python -m pytest tests/test_scanner.py -v
```

---

## Deployment

### Cloudflare Infrastructure

```bash
npm install -g wrangler && wrangler login

# Create resources
wrangler kv:namespace create "SCAN_CACHE"
wrangler d1 create skill-doctor-db
wrangler r2 bucket create skill-doctor-reports
wrangler queues create scan-jobs

# Deploy
cd packages/worker && wrangler deploy
cd packages/web && npm run build && wrangler pages deploy ./out --project-name=skill-doctor
```

### fly.io Scanner Service

```bash
cd packages/scanner
fly auth login
fly apps create skill-doctor-scanner
fly secrets set GROQ_API_KEY=xxx E2B_API_KEY=xxx
fly deploy
```

---

## Current Status

Skill Doctor is in **Alpha** (`v0.1.0`). The following layers are operational:

| Layer | Status |
|-------|--------|
| Layer 1 — Static Analysis (YARA-X + AST + Entropy + Unicode) | ✅ Live |
| Layer 2 — LLM Semantic Analysis (Groq) | ✅ Live |
| Layer 3 — Behavioral Sandbox (E2B) | 🚧 Week 2 |
| Layer 4 — Community Threat Database | 🚧 Stub (local only) |
| CLI | ✅ Live |
| Web UI | 🚧 In development |
| API Gateway | 🚧 In development |

---

## Roadmap

- [ ] E2B behavioral sandbox (Layer 3)
- [ ] Registry gate API for skill registries
- [ ] Cryptographic skill provenance (Ed25519 signing)
- [ ] Scientific Pack for research environments
- [ ] EU AI Act compliance module
- [ ] MCP server mode for runtime gating

---

## Contributing

We welcome contributions! Key areas:

- Additional YARA rules for new attack patterns
- Support for more skill file formats
- Performance optimizations
- Documentation improvements
- Bug fixes

Please see `CONTRIBUTING.md` for guidelines.

---

## Acknowledgments

- **Cisco AI Defense** — Skill Scanner (Apache 2.0) — YARA rule inspiration
- **NVIDIA** — SkillSpector (MIT) — AST analysis patterns
- **OWASP** — Agentic Skills Top 10 and MCP Top 10 — Threat taxonomy
- **Cloudflare** — Edge infrastructure platform
- **Groq** — Fast LLM inference
- **E2B** — Behavioral sandboxing

---

## License

**GNU Affero General Public License v3 (AGPL v3)**

If you run Skill Doctor as a network service or modify it, you must release your modifications under AGPL v3. For commercial licenses without open-sourcing requirements, contact: [sayan@kalarislabs.com](mailto:sayan@kalarislabs.com)

## Trademark

"Skill Doctor" and "Skill Doctor by Kalaris Labs" are trademarks of Kalaris Labs. Forks may use the code under AGPL v3 but must:

- Clearly state "Based on Skill Doctor by Kalaris Labs"
- Not use the "Skill Doctor" name without a trademark license

---

<p align="center">
  <strong>Skill Doctor</strong> · Securing the AI skill ecosystem, one file at a time.<br/>
  <a href="https://github.com/KalarisLabs/Skill-Doctor">GitHub</a> · <a href="mailto:sayan@kalarislabs.com">Email</a> · <a href="https://skilldoctor.kalarislabs.com">Website</a>
</p>
