# Migration: Python → Rust

> Complete rewrite of Skill Doctor from Python to Rust.
> This document tracks architecture decisions, crate mappings, and migration progress.

---

## Why Rust

| Factor | Impact |
|--------|--------|
| **YARA-X is Rust-native** | Zero FFI overhead. The Python prototype called YARA-X through bindings — in Rust it's a direct `yara-x` crate dependency. |
| **tree-sitter is Rust-native** | AST parsing for Python/JS/TS files uses `tree-sitter` natively. No bindings layer. |
| **Single static binary** | One `skill-doctor` binary per platform. No runtime dependencies. ~5-10MB. |
| **OpenTUI support** | `opentui_rust` crate provides the terminal UI rendering engine. |
| **Memory safety** | Security tooling written in a memory-safe compiled language carries more credibility. |
| **Performance** | Layer 1 static analysis drops from ~500ms (Python) to ~10-30ms (Rust). |

---

## Crate Mapping

Maps every Python dependency to its Rust equivalent.

### Core Scanner

| Python | Rust Crate | Notes |
|--------|-----------|-------|
| `yara-x` (Python bindings) | `yara-x` | Native. Same library, no bindings. |
| `tree-sitter` + `tree-sitter-python` | `tree-sitter`, `tree-sitter-python` | Native. Add `tree-sitter-javascript`, `tree-sitter-typescript` for JS/TS skill scripts. |
| `ast` (Python stdlib) | `tree-sitter` | Python's `ast` module only parses Python. tree-sitter handles all languages. |
| `re` (Python stdlib) | `regex` | More performant, Unicode-aware regex engine. |
| `hashlib` (Python stdlib) | `sha2` | SHA-256 computation. |
| `zipfile` / `tarfile` | `zip`, `tar`, `flate2` | Archive handling with zip-slip protection. |
| `httpx` | `reqwest` | HTTP client for URL downloads and LLM REST API calls. |
| `pydantic` | `serde` + `serde_json` | Serialization/deserialization. |

### CLI & TUI

| Python | Rust Crate | Notes |
|--------|-----------|-------|
| `click` | `clap` (derive) | CLI argument parsing. Industry standard. |
| `rich` (unused in code) | `opentui_rust` | Terminal UI rendering engine — replaces basic `print()` output. |
| N/A | `indicatif` | Progress bars (fallback for non-TUI mode, piped output). |
| N/A | `console` | Terminal color/style for non-TUI fallback. |

### LLM Integration

| Python | Rust Crate | Notes |
|--------|-----------|-------|
| `groq` (SDK) | `reqwest` + `serde_json` | **No Groq SDK in Rust.** Call the Groq REST API directly. Also enables easy provider switching (OpenAI, Anthropic, Ollama — all OpenAI-compatible REST). |

### API Server (future)

| Python | Rust Crate | Notes |
|--------|-----------|-------|
| `fastapi` + `uvicorn` | `axum` + `tokio` | Async HTTP server. Used for API gateway and web backend. |

### Testing

| Python | Rust Crate | Notes |
|--------|-----------|-------|
| `pytest` | Built-in `#[test]` + `assert!` | Rust has first-class testing. |
| `pytest-asyncio` | `tokio::test` | Async test support. |

---

## Architecture Mapping

### Directory Structure (Rust)

```
skill-doctor/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── crates/
│   ├── cli/                      # Binary crate — CLI entry point + OpenTUI
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           # clap CLI, dispatches to commands
│   │       ├── commands/
│   │       │   ├── scan.rs       # skill-doctor scan
│   │       │   ├── scan_all.rs   # skill-doctor scan-all
│   │       │   ├── diff.rs       # skill-doctor diff
│   │       │   ├── mcp.rs        # skill-doctor mcp
│   │       │   └── rules.rs      # skill-doctor rules
│   │       └── tui/
│   │           ├── mod.rs        # OpenTUI integration
│   │           ├── scan_view.rs  # Live scan progress UI
│   │           └── results.rs    # Findings display
│   │
│   ├── core/                     # Library crate — all scanning logic
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── models.rs         # Finding, ScanResult (serde)
│   │       ├── intake.rs         # Bundle normalization
│   │       ├── layer1_static.rs  # YARA-X + tree-sitter + entropy + unicode
│   │       ├── layer2_semantic.rs # LLM REST API calls
│   │       ├── layer3_sandbox.rs # E2B sandbox integration
│   │       ├── layer4_threat.rs  # Threat DB lookup
│   │       ├── scorer.rs         # Risk scoring
│   │       └── registries/
│   │           ├── skills_sh.rs  # Skills.sh registry resolver
│   │           └── github.rs     # GitHub shorthand resolver
│   │
│   └── report/                   # Report generation crate
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── json.rs           # JSON report
│           ├── sarif.rs          # SARIF 2.1 output
│           └── html.rs           # HTML report
│
├── rules/                        # YARA rule files (unchanged)
│   └── core/
│       ├── sd01_prompt_injection.yar
│       ├── sd02_command_injection.yar
│       └── ...
│
├── tests/                        # Integration tests
│   ├── fixtures/                 # Test skill files
│   └── integration/
│
├── README.md
├── MIGRATION.md                  # This file
├── LICENSE
└── .github/
    └── workflows/
        ├── ci.yml                # cargo test + clippy + fmt
        └── release.yml           # Cross-compile + GitHub Releases
```

### Module-by-Module Migration Map

| Python Module | Rust Module | Key Changes |
|--------------|------------|-------------|
| `skill_doctor/scanner/intake.py` | `crates/core/src/intake.rs` | Add Skills.sh resolver, GitHub shorthand. Use `reqwest` for downloads. |
| `skill_doctor/scanner/layer1_static.py` | `crates/core/src/layer1_static.rs` | YARA-X native. tree-sitter native. Entropy via `sha2`/math. |
| `skill_doctor/scanner/layer2_semantic.py` | `crates/core/src/layer2_semantic.rs` | Direct REST API to Groq/OpenAI/Ollama. No SDK dependency. |
| `skill_doctor/scanner/layer4_threat_db.py` | `crates/core/src/layer4_threat.rs` | Same SQLite-based local DB, use `rusqlite`. |
| `skill_doctor/scanner/scorer.py` | `crates/core/src/scorer.rs` | Direct port. |
| `skill_doctor/models.py` | `crates/core/src/models.rs` | Pydantic → serde derive macros. |
| `skill_doctor/cli.py` | `crates/cli/src/main.rs` | Click → Clap derive. Add OpenTUI rendering. |
| `skill_doctor/report/*.py` | `crates/report/src/*.rs` | Direct port. |

---

## LLM Strategy — Direct REST API

Instead of depending on vendor SDKs (Groq SDK, OpenAI SDK), all LLM calls go through a single `LlmClient` that speaks the OpenAI-compatible chat completions REST API.

```rust
// crates/core/src/llm_client.rs

pub struct LlmClient {
    http: reqwest::Client,
    base_url: String,      // e.g., "https://api.groq.com/openai/v1"
    api_key: String,
    model: String,         // e.g., "llama-3.3-70b-versatile"
}

impl LlmClient {
    /// Works with Groq, OpenAI, Anthropic (via proxy), Ollama, vLLM, etc.
    pub async fn chat(&self, messages: Vec<Message>) -> Result<String> {
        let resp = self.http
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&ChatRequest { model: &self.model, messages })
            .send()
            .await?;
        // parse response...
    }
}
```

**Supported providers via config:**

| Provider | `base_url` | `model` |
|----------|-----------|---------|
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Ollama (local) | `http://localhost:11434/v1` | `llama3.2` |
| vLLM (self-hosted) | `http://your-server:8000/v1` | Any model |

Configuration via environment variables:
```bash
export SKILL_DOCTOR_LLM_URL="https://api.groq.com/openai/v1"
export SKILL_DOCTOR_LLM_KEY="gsk_..."
export SKILL_DOCTOR_LLM_MODEL="llama-3.3-70b-versatile"
```

---

## OpenTUI Integration

The CLI uses OpenTUI for rich terminal rendering when running interactively, and falls back to plain text when output is piped.

### Scan Progress View

```
┌─────────────────────────────────────────────────────────┐
│  SKILL DOCTOR v0.2.0                    ◉ SCANNING...  │
├─────────────────────────────────────────────────────────┤
│  Target: skills.sh/vercel/next-skill                   │
│  Hash:   3335ef7aacedf6bf...                           │
│                                                         │
│  Layer 1 ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ DONE  (28ms, 3 hits)   │
│  Layer 2 ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░ 60%   (LLM reasoning)  │
│  Layer 3 ░░░░░░░░░░░░░░░░░░░░ QUEUED                  │
│  Layer 4 ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ DONE  (5ms, 0 hits)    │
│                                                         │
│  ┌─── Findings (3) ──────────────────────────────────┐ │
│  │ CRITICAL  SD-02  Command Injection   script.py:42 │ │
│  │ HIGH      SD-03  Data Exfiltration   SKILL.md:17  │ │
│  │ MEDIUM    SD-10  Obfuscation         utils.py:89  │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  Risk: DANGEROUS (8.7/10)       Duration: 4.21s        │
└─────────────────────────────────────────────────────────┘
```

### Non-interactive fallback

When piped (`skill-doctor scan ./skill/ | jq`), output falls back to plain text or structured JSON — no TUI rendering.

---

## Registry Support — Skills.sh & GitHub

### Skills.sh Resolution

```bash
# All of these resolve to the same skill:
skill-doctor scan skills.sh/vercel/next-skill
skill-doctor scan vercel/next-skill              # shorthand (checks Skills.sh first, then GitHub)
```

Resolution flow:
1. Query `https://skills.sh/api/skills/<owner>/<repo>` for metadata
2. Download skill bundle (SKILL.md + companion files) from the returned source URL
3. Normalize into bundle directory
4. Run scan pipeline

### GitHub Resolution

```bash
skill-doctor scan github:KalarisLabs/some-skill
skill-doctor scan https://github.com/owner/repo
```

Resolution flow:
1. Construct raw content URL from GitHub API
2. Download SKILL.md and any companion files referenced
3. Normalize and scan

---

## Build & Release Pipeline

### Cross-compilation targets

| Target | OS | Arch | Binary Name |
|--------|-----|------|-------------|
| `x86_64-unknown-linux-gnu` | Linux | x86_64 | `skill-doctor-linux-amd64` |
| `aarch64-unknown-linux-gnu` | Linux | ARM64 | `skill-doctor-linux-arm64` |
| `x86_64-apple-darwin` | macOS | Intel | `skill-doctor-darwin-amd64` |
| `aarch64-apple-darwin` | macOS | Apple Silicon | `skill-doctor-darwin-arm64` |
| `x86_64-pc-windows-msvc` | Windows | x86_64 | `skill-doctor-windows-amd64.exe` |

### GitHub Actions Release Workflow

On tag push (`v*`):
1. `cargo test` on all platforms
2. Cross-compile binaries via `cross`
3. Compute SHA-256 checksums
4. Create GitHub Release with binaries + checksums
5. Update Homebrew tap formula
6. Update Scoop manifest

### YARA Rules Embedding

YARA `.yar` rule files are embedded into the binary at compile time using `include_str!()` or the `rust-embed` crate. No external rule files needed at runtime.

---

## Migration Checklist

### Phase 1 — Core Library (`crates/core`)
- [ ] `models.rs` — Finding, ScanResult with serde derives
- [ ] `intake.rs` — Bundle normalization (local files, dirs, archives, URLs)
- [ ] `intake.rs` — Skills.sh registry resolver
- [ ] `intake.rs` — GitHub shorthand resolver
- [ ] `layer1_static.rs` — YARA-X native scanning
- [ ] `layer1_static.rs` — tree-sitter AST analysis
- [ ] `layer1_static.rs` — Entropy analysis
- [ ] `layer1_static.rs` — Unicode analysis
- [ ] `layer2_semantic.rs` — LLM REST client (provider-agnostic)
- [ ] `layer4_threat.rs` — Local threat DB (rusqlite)
- [ ] `scorer.rs` — Risk scoring engine

### Phase 2 — CLI + TUI (`crates/cli`)
- [ ] `main.rs` — Clap CLI with all commands
- [ ] `commands/scan.rs` — Scan command
- [ ] `commands/scan_all.rs` — Recursive scan
- [ ] `commands/diff.rs` — Diff scan
- [ ] `commands/mcp.rs` — MCP server mode
- [ ] `tui/scan_view.rs` — OpenTUI scan progress
- [ ] `tui/results.rs` — OpenTUI results display

### Phase 3 — Reports (`crates/report`)
- [ ] `json.rs` — JSON report
- [ ] `sarif.rs` — SARIF 2.1 output
- [ ] `html.rs` — HTML report

### Phase 4 — Release Engineering
- [ ] GitHub Actions CI (test + clippy + fmt)
- [ ] GitHub Actions Release (cross-compile + checksums)
- [ ] Homebrew tap (`KalarisLabs/homebrew-tap`)
- [ ] Scoop manifest
- [ ] Winget manifest
- [ ] Install script (shell + PowerShell)

### Phase 5 — Cleanup
- [ ] Archive Python source to `legacy/python/` branch
- [ ] Remove `pyproject.toml`, `uv.lock`, `.venv/`
- [ ] Update all documentation

---

## References

- [YARA-X Rust crate](https://crates.io/crates/yara-x)
- [tree-sitter Rust crate](https://crates.io/crates/tree-sitter)
- [OpenTUI Rust crate](https://crates.io/crates/opentui_rust)
- [Clap CLI framework](https://crates.io/crates/clap)
- [reqwest HTTP client](https://crates.io/crates/reqwest)
- [Groq REST API docs](https://console.groq.com/docs/api-reference)
