<p align="center">
  <img src="public/skill-doctor-banner.webp" alt="Skill Doctor security scanner for AI agent skill files" width="100%" />
</p>

# Skill Doctor

Deterministic static security analysis for AI agent skill files (SKILL.md bundles, archives), offline by default.

[![CI](https://github.com/KalarisLabs/Skill-Doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/KalarisLabs/Skill-Doctor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93.0-blue.svg)](Cargo.toml)
[![crates.io](https://img.shields.io/crates/v/skill-doctor)](https://crates.io/crates/skill-doctor)
[![npm](https://img.shields.io/npm/v/%40security.kalarislabs%2Fskill-doctor)](https://www.npmjs.com/package/@security.kalarislabs/skill-doctor)
[![npm](https://img.shields.io/npm/dm/%40security.kalarislabs%2Fskill-doctor)](https://www.npmjs.com/package/@security.kalarislabs/skill-doctor)
[![crates.io](https://img.shields.io/crates/d/skill-doctor)](https://crates.io/crates/skill-doctor)
[![GitHub release](https://img.shields.io/github/v/release/KalarisLabs/Skill-Doctor)](https://github.com/KalarisLabs/Skill-Doctor/releases)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/KalarisLabs/Skill-Doctor)
![GitHub Org Views](https://github-view-counter.vercel.app/api?username=KalarisLabs)

[Docs](docs/RELEASE.md) · [Getting started](#getting-started) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Discussions](https://github.com/KalarisLabs/Skill-Doctor/discussions)

## Why this exists

Skill files are natural-language instructions that agents execute with real tool access, installed from untrusted sources, and nothing statically analyses them before they run. The threat model includes prompt injection, credential exfiltration, privilege escalation, supply-chain and obfuscation tricks inside Markdown and frontmatter.

## Getting Started

### npx (zero installation)
```bash
npx @security.kalarislabs/skill-doctor scan ./examples/hello-skill
```

### npm global install
```bash
npm install -g @security.kalarislabs/skill-doctor
skill-doctor scan ./examples/hello-skill
```

### cargo install (crates.io)
```bash
cargo install skill-doctor --locked --features mcp
skill-doctor scan ./examples/hello-skill
```

### Prebuilt binary download
Download the platform archive from the [v0.1.0 GitHub release](https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.1.0).

### Build from source
Requires Rust 1.93.0+ (MSRV):

```bash
git clone https://github.com/KalarisLabs/Skill-Doctor && cd Skill-Doctor
cargo install --path crates/skill-doctor-cli --locked --features mcp
skill-doctor scan ./examples/hello-skill
```

**Notes:**
- `--features mcp` is required for `skill-doctor mcp`; the published crate has `default = []`, so a plain `cargo install skill-doctor` ships without the MCP server.
- `SKILL_DOCTOR_SKIP_DOWNLOAD=1` skips the npm postinstall binary download for source builds.
- macOS: `xattr -d com.apple.quarantine skill-doctor`; binaries are not Apple-notarized.
- Requires Node >= 18 for the npm path; Requires Rust 1.93.0+ (MSRV) to build.

### Your first scan
```bash
skill-doctor scan ./examples/hello-skill
```

Exit codes: `0` = clean · `1` = usage or internal error · `2` = findings at or above `--fail-on` · `3` = structural coverage below `--fail-under-coverage`

Exit code `1` is NOT "findings found" — it denotes a usage error or internal scanner failure.

## What it detects

| ID | Name | Description | Detection layer |
|----|------|-------------|-----------------|
| SD-01 | Prompt Injection | Direct, indirect, ASCII smuggling, and encoded prompt injections | L1 Unicode & Shannon Entropy; L2 semantic opt-in |
| SD-02 | Command Injection | Unsanitized execution in companion scripts (`eval`, `exec`, `system`) | L1 Lexical Source-to-Sink Taint; L3-lite sandbox opt-in |
| SD-03 | Data Exfiltration | Covert extraction of environment variables and sensitive file paths | L1 Secret Patterns; L3-lite sandbox opt-in |
| SD-04 | Privilege Escalation | Undeclared capabilities exceeding frontmatter permission declarations | L1 Capability Differ (declared vs observed operations) |
| SD-05 | Supply-Chain Tampering | Checksum mismatches, bytecode cache pollution, typosquatting | L1 Package Hook Patterns; L4 intel opt-in |
| SD-06 | SSRF | Outbound requests to cloud metadata services or internal networks | L1 Metadata & Loopback Address Patterns; L2 semantic opt-in |
| SD-07 | Tool Poisoning | Cross-skill tool name shadowing and parameter collisions | L1 Cross-Skill Namespace Collision Checks; L2 semantic opt-in |
| SD-08 | Persistent Backdoor | Auto-loaded context hooks (.clauderules, startup persistence) | L1 Context File Rule Patterns; L3-lite sandbox opt-in |
| SD-09 | Context-Window Flooding | Instruction washing and denial-of-service token floods | L1 Token Count & Repetition Detection; L3-lite sandbox opt-in |
| SD-10 | Obfuscation & Evasion | UTS #39 confusables, bidi Trojan Source, deferred logic bombs | L1 Unicode Engine; L3-lite sandbox opt-in |
| SD-11 | Scanner-Mediated Injection | Attacks attempting to exploit or hijack the host scanner/agent | skill-doctor-neutralize Fencing + Additive Invariant |

The v0.1.0 suite ships 14 curated fixtures (6 attack covering SD-01/02/03/04/10, 3 benign, 4 benchmark, 1 example); remaining classes are rule-only and not yet fixture-covered. See [issue tracking corpus growth](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3Acorpus).

## Usage

### Scan a single skill
```bash
skill-doctor scan ./examples/hello-skill
```

### Scan a directory of skills
```bash
skill-doctor scan-all . --exclude "node_modules/*" --exclude "target/*"
```

### Compare against a baseline
```bash
skill-doctor diff ./examples/hello-skill --baseline report.json
```

### CI gate
```bash
skill-doctor gate ./examples/hello-skill --fail-on HIGH --fail-under-coverage 0.8
```

### Watch for changes
```bash
skill-doctor watch ./examples/hello-skill
```

### MCP server
```bash
skill-doctor mcp
```

### Flags

| Flag | Description |
|------|-------------|
| `--fail-on` | Minimum severity to trigger exit code 2 (default: high) |
| `--fail-under-coverage` | Minimum structural coverage ratio to trigger exit code 3 |
| `--output` | Output format: text, json, sarif |
| `--deterministic` | Byte-identical output (sorted maps, pinned timestamps) |
| `--offline` | Zero network calls, zero LLM (default behavior) |
| `--sandbox` | Run L3-lite behavioral process harness (opt-in feature) |
| `--intel` | Query L4 community threat intelligence feed (opt-in feature) |
| `--tui` | Launch interactive full-screen dashboard (opt-in feature) |
| `--color` | Output colorization (auto, always, never) |
| `--quiet` | Suppress informational headers and non-essential progress output |

**Guarantees:**
- Offline by default with zero mandatory network calls
- `--deterministic` produces byte-identical output (enforced by the `determinism` CI job, which hashes two runs)

## Use it in CI

### GitHub Action
```yaml
- name: Run Skill Doctor
  id: scan
  uses: KalarisLabs/Skill-Doctor@v0.1.0
  with:
    path: .
    mode: scan-all
    fail-on: HIGH
    fail-under-coverage: 0.8
    output: sarif
    sarif-file: skill-doctor.sarif

- name: Upload SARIF report
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skill-doctor.sarif
```

**Current limitation:** The action verifies the downloaded asset against `SHA256SUMS.txt` but performs no cosign verification (trust-on-first-use). See [issue #41](https://github.com/KalarisLabs/Skill-Doctor/issues/41).

### Raw CLI in CI
```bash
skill-doctor scan-all . \
  --output sarif \
  --fail-on HIGH \
  --fail-under-coverage 0.8 \
  --deterministic \
  --offline
```

## Verify what you downloaded

### Verify checksum signature with Cosign
```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/KalarisLabs/Skill-Doctor/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

### Verify binary digest
```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

### Inspect CycloneDX SBOM
```bash
jq -r '.components[] | "\(.name) \(.version) (\(.licenses[0].license.id // "unknown"))"' skill-doctor.cdx.json
```

## Performance

| Metric | Pre-registered target | Measured (with platform + provenance) |
|--------|---------------------|--------------------------------------|
| Binary footprint (musl, stripped, `--features mcp`) | ~12 MB target (**MISSED**: YARA-X embeds Wasmtime/Cranelift ~14 MiB; < 20 MiB ceiling) | **16,934,512 bytes** (16.15 MiB, `x86_64-unknown-linux-musl`, CI-measured) |
| Binary footprint (MSVC, stripped, `--features mcp`) | < 20 MiB ceiling | **17,936,896 bytes** (17.11 MiB, `x86_64-pc-windows-msvc`, not CI-verified) |
| Peak RSS | < 40 MiB | **14.67 MiB** (local measurement, `x86_64-pc-windows-msvc`, not CI-verified) |
| Scan throughput | ≥ 2,000 skills/min (warm cache off) | **660 skills/s** (~39,600 skills/min) (local measurement, `x86_64-pc-windows-msvc`, not CI-verified) |
| Median cold scan latency | sub-150 ms (pre-registered target) | Not measured in CI |

## Documentation

- [docs/RELEASE.md](docs/RELEASE.md) — Release & publication playbook
- [DEPENDENCIES.md](DEPENDENCIES.md) — Every package we use and why
- [TESTING.md](TESTING.md) — Test strategy, CI gates, and branch protection
- [docs/PAPER-RECONCILIATION.md](docs/PAPER-RECONCILIATION.md) — Whitepaper implementation mapping
- [CHANGELOG.md](CHANGELOG.md) — Version history

There is no hosted docs site at this time. All documentation is in-repo.

## Community — who Skill Doctor is for

Skill Doctor is for:
- Teams shipping agent skills/plugins who need security validation before deployment
- Registry and marketplace operators screening submissions for malicious patterns
- Security engineers adding a CI gate to prevent skill-based attacks
- Researchers studying skill-file attack patterns and detection techniques

See [ADOPTERS.md](ADOPTERS.md) for organizations that have publicly adopted Skill Doctor.

Join the conversation:
- [GitHub Discussions](https://github.com/KalarisLabs/Skill-Doctor/discussions) — Announcements, Q&A, rule proposals, show and tell
- [Issue tracker](https://github.com/KalarisLabs/Skill-Doctor/issues) — Bug reports and feature requests

## Contributing

### 10-minute dev setup
```bash
git clone https://github.com/KalarisLabs/Skill-Doctor && cd Skill-Doctor
rustup toolchain install stable
cargo build --release --features mcp
SD_L3_REQUIRE_INTERPRETER=1 cargo test --workspace --all-features --locked
```

### Rule contribution contract
Every new detection rule ships with:
- An attack fixture demonstrating the threat
- A benign fixture demonstrating no false positive
- A determinism-safe snapshot

### MSRV policy
1.93.0, empirically bisected. Raising it is a breaking change.

### Required status checks for PRs
- version-sync
- check-gate
- msrv-check
- lint-and-unit
- supply-chain
- determinism
- os-cli (Ubuntu/macOS/Windows)
- dogfood-self-scan
- docs-smoke
- packaging-gate

### PR checklist bans
- No `--no-run` compile output presented as a test pass
- No `echo`-printed measurements
- Every number labelled target vs measurement with platform

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines. Good first issues are tagged with [`good first issue`](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). See the [v0.1.1 milestone](https://github.com/KalarisLabs/Skill-Doctor/milestone/1) for planned work.

## Security

- Report privately via [GitHub Security Advisories](https://github.com/KalarisLabs/Skill-Doctor/security/advisories) — never in public issues.
- Security contact: security@kalarislabs.com (see [SECURITY.md](SECURITY.md))

### Supported versions
| Version | Support status |
|---------|----------------|
| 0.1.x   | Supported      |

### Version history note
crates.io versions 0.2.0 / 0.2.2 / 0.2.3 are yanked pre-release prototypes that must not be used. 0.1.0 is the first supported release.

See the [verification section](#verify-what-you-downloaded) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Requires Rust 1.93.0+ (MSRV).

## Sponsors

Documentation platform: [Mintlify](https://mintlify.com)

## Contributors

Lead author: [Sayan Chowdhury](https://github.com/sayanchowdhury) (Kalaris Labs)

## Support this project

How to support this project:
- Star the repository
- File rule false positives/negatives as issues
- Contribute attack and benign fixtures
- Contribute code, documentation, or tests

Organizations interested in sponsorship should contact us via [GitHub Discussions](https://github.com/KalarisLabs/Skill-Doctor/discussions). Sponsors receive a credit line in this section.

## Acknowledgements

Skill Doctor depends on these upstream projects:
- [YARA-X](https://github.com/VirusTotal/yara-x) — Pattern matching engine
- [Wasmtime/Cranelift](https://github.com/bytecodealliance/wasmtime) — WebAssembly runtime and compiler
- [rmcp](https://github.com/ShowMeYourFlowHub/rmcp) — Model Context Protocol implementation
- [clap](https://github.com/clap-rs/clap) — Command-line argument parsing
- [rayon](https://github.com/rayon-rs/rayon) — Data parallelism

## Download statistics

- [npm downloads](https://npm-stat.com/charts.html?package=%40security.kalarislabs%2Fskill-doctor)
- [crates.io downloads](https://crates.io/crates/skill-doctor)

## Limitations & roadmap

### Current limitations
- 14 fixtures and no external-corpus evaluation
- L2 semantic requires an LLM endpoint and is opt-in
- L3-lite sandbox requirements and platform caveats
- Action TOFU (trust-on-first-use)
- No Apple notarization
- 6 supported target triples
- Footprint dominated by YARA-X/Wasmtime

### Roadmap
- [Expand fixture coverage across all 11 SDTM-v1 classes](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3Acorpus)
- [Add Cosign verification to GitHub Action](https://github.com/KalarisLabs/Skill-Doctor/issues/41)
- [External corpus evaluation on public skill repositories](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3Aevaluation)
- [Reduce binary footprint via conditional compilation](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3Aperformance)
- [Apple notarization for macOS binaries](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3Aplatform)
- [Additional target triples](https://github.com/KalarisLabs/Skill-Doctor/issues?q=is%3Aissue+is%3Aopen+label%3Aplatform)

See the [v0.1.1 milestone](https://github.com/KalarisLabs/Skill-Doctor/milestone/1) for detailed planning.