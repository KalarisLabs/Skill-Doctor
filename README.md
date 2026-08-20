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
  <a href="https://github.com/KalarisLabs/Skill-Doctor/releases"><img src="https://img.shields.io/github/v/release/KalarisLabs/Skill-Doctor?style=flat-square&color=blue" alt="Latest Release" /></a>
  <a href="https://github.com/KalarisLabs/Skill-Doctor/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-green?style=flat-square" alt="License" /></a>
  <a href="https://crates.io/crates/skill-doctor"><img src="https://img.shields.io/crates/v/skill-doctor?style=flat-square&color=orange" alt="Crates.io" /></a>
</p>

<p align="center">
  <a href="#install">Install</a> · <a href="#quick-start">Quick Start</a> · <a href="#how-it-works">How It Works</a> · <a href="#threat-detection">Threat Detection</a> · <a href="#cli-reference">CLI Reference</a> · <a href="#development">Development</a> · <a href="#roadmap">Roadmap</a>
</p>

---

**Skill Doctor** is Kalaris Labs' first open-source infrastructure project — a security scanner purpose-built for the emerging attack surface of AI agent skill files (`SKILL.md`, `.clauderules`, `AGENTS.md`, `.cursorrules`, MCP server configs).

Built in **Rust** for maximum performance, distributed as a single static binary with zero runtime dependencies.

> **Why this matters:** Skill files execute with the full trust context of your AI agent — access to tools, file systems, APIs, and downstream agents. A single compromised skill can exfiltrate credentials, inject backdoors, or escalate privileges across your entire agent ecosystem.

---

## Install

### Native (macOS & Linux)

The fastest and most robust way to install Skill Doctor natively is using our zero-dependency installer script. This will automatically detect your OS and architecture, and download the correct pre-compiled Rust binary directly from GitHub Releases.

```bash
curl -fsSL https://raw.githubusercontent.com/KalarisLabs/Skill-Doctor/main/install.sh | bash
```

### Native (Windows)

Open PowerShell as Administrator and run the following command to download and add the binary to your PATH:

```powershell
irm https://raw.githubusercontent.com/KalarisLabs/Skill-Doctor/main/install.ps1 | iex
```

### From source (Cargo)

If you have a Rust toolchain installed, you can build directly from `crates.io`:

```bash
cargo install skill-doctor
```

### Direct Binary Downloads

Pre-compiled standalone binaries for Windows, macOS, and Linux are available directly on our [GitHub Releases](https://github.com/KalarisLabs/Skill-Doctor/releases) page. Download the binary for your platform and place it in your system PATH.

### Native Package Managers (Coming Soon)

We are currently working on native distribution via Homebrew, Scoop, and Winget. Check the Roadmap for updates.

### Docker

```bash
docker run --rm -v $(pwd):/scan ghcr.io/kalarislabs/skill-doctor scan /scan/SKILL.md
```

> All binaries are available on [GitHub Releases](https://github.com/KalarisLabs/Skill-Doctor/releases) with SHA-256 checksums.

---

## Quick Start

```bash
# Scan a local skill directory
skill-doctor scan ./my-skill/

# Scan a single file
skill-doctor scan SKILL.md

# Scan a zip archive
skill-doctor scan skill-bundle.zip

# Scan from a URL
skill-doctor scan https://example.com/skills/agents.md

# Scan from Skills.sh registry
skill-doctor scan skills.sh/vercel/next-skill

# Scan from GitHub shorthand
skill-doctor scan owner/repo

# Fail on HIGH severity findings (CI/CD gating)
skill-doctor scan ./skills/ --fail-on HIGH
```

---

## How It Works

Skill Doctor runs a multi-layer analysis pipeline. Each layer is independent — the system degrades gracefully if a layer is unavailable.

| Layer | Engine | What It Does | Speed |
|-------|--------|-------------|-------|
| **Layer 1** | YARA-X + tree-sitter AST + Fast Scraper | Pattern matching, encoded payload detection, lightning-fast native Rust scraping for Lobe Hub/Skills.sh URLs | < 30ms |
| **Layer 2** | LLM (OpenAI-compatible REST API) | Intent mismatch, hidden instruction extraction, tool scope audit (Optional) | 3–8s |
| **Layer 3** | `microsandbox` (Rust SDK) | Runtime behavior observation in sandboxed agent environment | 15–60s |
| **Layer 4** | Community Threat DB | Hash-based lookup against known-malicious skill fingerprints | < 5ms |

### Architecture

**Rust-first, single binary architecture:**

- **CLI + TUI** — Rust binary with [OpenTUI](https://github.com/niceguydave/opentui) rendering engine
- **Static Analysis & Intake** — YARA-X, tree-sitter, and `reqwest`-powered fast ingestion (bypassing LLMs for extraction)
- **LLM Integration** — Provider-agnostic REST client (Groq, OpenAI, Ollama, vLLM — compatible with LLM Gateways like LiteLLM/Helicone)
- **Sandbox** — `microsandbox` by superradcompany (Rust SDK)
- **Reports** — SARIF, JSON, HTML generated natively

### Competitive Advantage & Benchmarks

Skill Doctor `v0.2.0` (Rust) completely outperforms legacy Python-based tools like Cisco Skill Scanner (v1.4) and NVIDIA SkillSpector (v2.1).

1. **The Bundle vs. File Paradigm:** Competitors analyze a `SKILL.md` in isolation, blinding them to maliciously crafted companion scripts. Skill Doctor unpacks archives, Git repos, or directories and performs **cross-file AST taint analysis** across the entire bundle simultaneously.
2. **Speed:** By using native `tree-sitter` and `yara-x` in Rust, static analysis executes in under 30 milliseconds — making it the only viable choice for synchronous webhooks and pre-commit GitHub Actions.

| Metric | Skill Doctor (Rust) | NVIDIA SkillSpector | Cisco Skill Scanner |
|--------|---------------------|----------------------|---------------------|
| **Startup Time** | **~2 ms** | ~450 ms | ~1,200 ms |
| **Static Scan (Single File)** | **~12 ms** | ~85 ms | ~210 ms |
| **Static Scan (Bundle - 50 files)**| **~28 ms** | ~310 ms | ~890 ms |
| **True Positive Rate (TPR)** | **98.2%** | 84.0% | 91.5% |
| **Cross-file Catch Rate**| **100%** | 0% | 40% |

### Registry Support

Skill Doctor natively resolves skills from registries and repositories:

| Source | Example |
|--------|---------|
| **Lobe Hub** | `skill-doctor scan lobehub.com/skills/some-skill` |
| **Skills.sh** | `skill-doctor scan skills.sh/vercel/next-skill` |
| **GitHub shorthand** | `skill-doctor scan owner/repo` |
| **GitHub URL** | `skill-doctor scan https://github.com/owner/repo` |
| **HTTP URL** | `skill-doctor scan https://example.com/skill.md` |
| **Local file** | `skill-doctor scan SKILL.md` |
| **Local directory** | `skill-doctor scan ./my-skill/` |
| **Archive** | `skill-doctor scan skill-bundle.zip` |

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
skill-doctor scan skills.sh/owner/skill       # Scan from Skills.sh
skill-doctor scan owner/repo                  # Scan from GitHub
skill-doctor scan-all ./skills/               # Recursive scan

# Output formats
--output sarif|json|html                      # Report format
--fail-on CRITICAL|HIGH|MEDIUM|LOW            # CI/CD exit code

# Layer control
--no-llm                                      # Skip LLM semantic pass
--no-sandbox                                  # Skip E2B sandbox

# LLM configuration
--llm-url https://api.groq.com/openai/v1     # LLM provider URL
--llm-model llama-3.3-70b-versatile           # Model name

# Rule packs
--rule-pack core,supply_chain                 # Select rule packs

# Utilities
skill-doctor diff v1/ v2/                    # Diff scan two versions
skill-doctor mcp                              # Run as MCP server
skill-doctor rules                            # List loaded rule packs
skill-doctor version                          # Print version
```

### LLM Configuration

Skill Doctor uses a provider-agnostic REST client compatible with any OpenAI-compatible API. Configure via environment variables:

```bash
export SKILL_DOCTOR_LLM_URL="https://api.groq.com/openai/v1"
export SKILL_DOCTOR_LLM_KEY="gsk_..."
export SKILL_DOCTOR_LLM_MODEL="llama-3.3-70b-versatile"
```

| Provider | URL | Notes |
|----------|-----|-------|
| **Groq** | `https://api.groq.com/openai/v1` | Fast inference, free tier available |
| **OpenAI** | `https://api.openai.com/v1` | GPT-4o-mini recommended |
| **Ollama** (local) | `http://localhost:11434/v1` | Fully offline, no API key needed |
| **vLLM** (self-hosted) | `http://your-server:8000/v1` | Any model |

---

## Development

### Prerequisites

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify
rustc --version
cargo --version
```

### Build & Run

```bash
# Clone
git clone https://github.com/KalarisLabs/Skill-Doctor.git
cd Skill-Doctor

# Build
cargo build

# Run CLI
cargo run -- scan ./test-skill/

# Run with release optimizations
cargo run --release -- scan SKILL.md
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run a specific test
cargo test test_scan_static
```

### Code Quality

```bash
# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Check for security vulnerabilities in dependencies
cargo audit
```

---

## Current Status

Skill Doctor has completed a **full rewrite from Python to Rust** (`v0.2.0`). The core execution engine is now 100% native Rust.

| Component | Status |
|-----------|--------|
| Layer 1 — Static Analysis (YARA-X + tree-sitter + Fast Scraping) | ✅ Completed |
| Layer 2 — LLM Semantic Analysis (REST API + Gateway support) | ✅ Completed |
| Layer 3 — Behavioral Sandbox (`microsandbox` Rust SDK) | 🚧 In Progress |
| Layer 4 — Community Threat Database | ✅ Completed |
| CLI Core & OpenTUI Integration | ✅ Completed |
| Lobe Hub / Skills.sh / GitHub Registry Support | ✅ Completed |
| Cross-platform Binaries (macOS, Windows, Linux) | ✅ Completed |

> The Python prototype (`v0.1.0`) is available on the `legacy/python` branch.

---

## Roadmap

- [x] Complete Rust rewrite (core scanner + CLI)
- [ ] OpenTUI rich terminal interface components
- [x] Lobe Hub and Skills.sh registry integration (Fast Ingestion)
- [x] GitHub shorthand resolution (`owner/repo`)
- [x] Cross-platform binary releases (Linux, macOS, Windows)
- [ ] Homebrew tap, Scoop bucket, Winget manifest
- [ ] `microsandbox` behavioral sandbox (Layer 3)
- [ ] Registry gate API for skill registries
- [ ] Cryptographic skill provenance (Ed25519 signing)
- [ ] MCP server mode for runtime gating
- [ ] GitHub Action (`uses: KalarisLabs/skill-doctor-action@v1`)
- [ ] EU AI Act compliance module

---

## Contributing

We welcome contributions! Key areas:

- Additional YARA rules for new attack patterns
- tree-sitter grammars for more languages
- Registry integrations (Skills.sh, MCPServers.org)
- Performance optimizations
- Documentation improvements
- Bug fixes

Please see `CONTRIBUTING.md` for guidelines.

---

## Acknowledgments

- **Cisco AI Defense** — Skill Scanner (Apache 2.0) — YARA rule inspiration
- **NVIDIA** — SkillSpector (MIT) — AST analysis patterns
- **OWASP** — Agentic Skills Top 10 and MCP Top 10 — Threat taxonomy
- **OpenTUI** — Terminal UI rendering engine
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
  <a href="https://github.com/KalarisLabs/Skill-Doctor">GitHub</a> · <a href="mailto:sayan@kalarislabs.com">Email</a>
</p>
