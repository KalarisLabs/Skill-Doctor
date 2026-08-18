# Skill Doctor 🩺

![Skill Doctor Banner](public/skill%20doctor%20banner.png)

A multi-layer security platform for AI agent skill files. Detects malicious, deceptive, or vulnerable skill files before they are loaded by agent runtimes.

**Skill Doctor is Kalaris Labs' first open-source infrastructure project.**

## What It Does

Skill Doctor scans AI agent skill files (SKILL.md, .clauderules, AGENTS.md, MCP server configs) for security vulnerabilities through a multi-layer analysis pipeline:

- **Layer 1 - Static Analysis**: YARA-X pattern matching + Python AST taint analysis + entropy/Unicode scanning
- **Layer 2 - Semantic Analysis**: Groq LLM (Llama 3.3 70B) for intent mismatch and hidden instruction detection  
- **Layer 3 - Behavioral Sandbox**: E2B Firecracker microVM to observe runtime behavior (deferred to Week 2)
- **Layer 4 - Threat Intelligence**: Community threat database with hash-based caching

## Quick Start

### CLI Installation

```bash
pip install skill-doctor
```

### Basic Usage

```bash
# Scan a skill directory
skill-doctor scan ./my-skill/

# Scan a zip file
skill-doctor scan skill.zip

# Scan from Git URL
skill-doctor scan github.com/user/repo

# Fail on HIGH severity findings (for CI/CD)
skill-doctor scan ./skills/ --fail-on HIGH
```

### Web Interface

Deploy your own instance or use [scan.skilldoctor.dev](https://scan.skilldoctor.dev) (coming soon) for drag-and-drop scanning with zero installation.

## Architecture

**Cloudflare-first infrastructure:**
- **Web UI**: Cloudflare Pages (Next.js)
- **API Gateway**: Cloudflare Workers (Hono.js)
- **Database**: Cloudflare D1 (SQLite at edge)
- **Cache**: Cloudflare KV (scan result caching)
- **Queues**: Cloudflare Queues (async scan jobs)
- **Storage**: Cloudflare R2 (report storage)
- **Scanner Service**: fly.io (Python FastAPI)
- **LLM**: Groq API (via Cloudflare AI Gateway)
- **Sandbox**: E2B (Firecracker microVM)

## Threat Detection

Skill Doctor detects 10 attack classes from the OWASP Agentic Skills Top 10 and OWASP MCP Top 10:

- **SD-01**: Prompt Injection (direct, indirect, ASCII smuggling, encoded)
- **SD-02**: Command Injection via Companion Scripts
- **SD-03**: Data Exfiltration (env vars, sensitive paths, context dumps)
- **SD-04**: Privilege Escalation (tool scope violations)
- **SD-05**: Supply Chain Tampering (hash mismatch, .pyc poisoning)
- **SD-06**: SSRF via Tool Parameters
- **SD-07**: Tool Poisoning (shadow tool registration)
- **SD-08**: Persistent Backdoors (auto-loaded file writes)
- **SD-09**: Context Window Flooding
- **SD-10**: Obfuscation and Evasion (homoglyphs, encoding, logic bombs)

## CLI Reference

```bash
# Scan commands
skill-doctor scan ./path/           # Scan directory
skill-doctor scan skill.zip         # Scan zip
skill-doctor scan skill.md          # Scan single file
skill-doctor scan github.com/user/repo  # Scan from Git URL

# Options
--output sarif|json|html|pdf        # Output format
--fail-on CRITICAL|HIGH|MEDIUM|LOW  # Exit code on findings
--no-llm                            # Skip LLM pass (static only)
--no-sandbox                        # Skip E2B sandbox
--rule-pack core,supply_chain       # Select rule packs

# Other commands
skill-doctor scan-all ./skills/     # Scan all skills in directory tree
skill-doctor diff v1/ v2/          # Diff scan two versions
skill-doctor mcp                    # Run as MCP server
skill-doctor rules                  # List loaded rule packs
skill-doctor version                # Print version
```

## Development

### Prerequisites

```bash
# Install tools
brew install uv node docker

# Get API keys (free tiers sufficient)
# Groq: https://console.groq.com
# E2B: https://e2b.dev
# Clerk: https://clerk.com
```

### Local Development

```bash
# Clone repository
git clone https://github.com/KalarisLabs/Skill-Doctor.git
cd Skill-Doctor

# Install Python dependencies
uv sync

# Run CLI locally
uv run python -m skill_doctor.cli scan ./test-skill/

# Start FastAPI backend
uv run uvicorn skill_doctor.api.main:app --reload

# Start Next.js web UI
cd web
npm install
npm run dev
```

### Running Tests

```bash
# Install test dependencies
uv sync --dev

# Run all tests
uv run pytest tests/ -v

# Run specific test
uv run pytest tests/test_scanner.py -v
```

## Deployment

### Cloudflare Infrastructure

```bash
# Install wrangler
npm install -g wrangler
wrangler login

# Create resources
wrangler kv:namespace create "SCAN_CACHE"
wrangler d1 create skill-doctor-db
wrangler r2 bucket create skill-doctor-reports
wrangler queues create scan-jobs

# Deploy Worker
cd packages/worker
wrangler deploy

# Deploy web UI
cd packages/web
npm run build
wrangler pages deploy ./out --project-name=skill-doctor
```

### fly.io Scanner Service

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Deploy scanner
cd packages/scanner
fly auth login
fly apps create skill-doctor-scanner
fly secrets set GROQ_API_KEY=xxx E2B_API_KEY=xxx
fly deploy
```

## Test Results

We recently scanned the Kane CLI browser automation skill (`https://testmuai.com/kane-cli/agents.md`) using the Skill Doctor master branch. The scanner successfully normalized the URL bundle and completed the analysis in 1.20s with 0 findings, verifying that the skill is safe.

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

## License

**GNU Affero General Public License v3 (AGPL v3)**

This is a strong copyleft license. If you run Skill Doctor as a network service or modify it, you must release your modifications under AGPL v3.

For commercial licenses without open-sourcing requirements, contact: sayan@kalarislabs.com

## Trademark

"Skill Doctor" and "Skill Doctor by Kalaris Labs" are trademarks of Kalaris Labs.

Forks may use the code under AGPL v3 but must:
- Clearly state "Based on Skill Doctor by Kalaris Labs"
- Not use the "Skill Doctor" name without a trademark license

## Contributing

We welcome contributions! Please see `CONTRIBUTING.md` for guidelines.

Key areas for contribution:
- Additional YARA rules for new attack patterns
- Support for more skill file formats
- Performance optimizations
- Documentation improvements
- Bug fixes

## Roadmap

- [ ] Week 2: E2B behavioral sandbox (Layer 3)
- [ ] Registry gate API for skill registries
- [ ] Cryptographic skill provenance (Ed25519 signing)
- [ ] Scientific Pack for research environments
- [ ] EU AI Act compliance module
- [ ] MCP server mode for runtime gating

## Acknowledgments

- **Cisco AI Defense**: Skill Scanner (Apache 2.0) - YARA rule inspiration
- **NVIDIA**: SkillSpector (MIT) - AST analysis patterns
- **OWASP**: Agentic Skills Top 10 and MCP Top 10 - Threat taxonomy
- **Cloudflare**: Edge infrastructure platform
- **Groq**: Fast LLM inference
- **E2B**: Behavioral sandboxing

## Contact

- **GitHub**: https://github.com/KalarisLabs/Skill-Doctor
- **Email**: sayan@kalarislabs.com
- **Website**: https://kalarislabs.com

---

Skill Doctor · Securing the AI skill ecosystem, one file at a time.
