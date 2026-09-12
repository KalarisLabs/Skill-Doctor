# DEPENDENCIES.md — every package we use and why

All versions are indicative and pinned for real in `Cargo.lock`. Rust edition 2021, toolchain pinned
in `rust-toolchain.toml`. The product ships as one static binary; nothing here implies a runtime
interpreter. Prefer pure-Rust crates so the static (musl) build stays clean.

## Analysis engines (core)

| Crate | Purpose | Layer |
|-------|---------|-------|
| `yara-x` | Pure-Rust YARA engine; rule packs for SD-01–SD-11. Compiled once at build time with minimal features (`default-features = false, features = ["constant-folding"]`) to drop binary format and crypto modules. | L1 pattern |
| `tree-sitter` + `tree-sitter-bash`, `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-json`, `tree-sitter-md` | Parse companion scripts & manifests (incl. malformed) for taint analysis. | L1 taint |
| `unicode-security` | UTS #39 confusables / mixed-script / skeleton normalization. | L1 unicode, neutralize |
| `unicode-normalization` | NFC/NFKC normalization; zero-width & bidi handling. | L1 unicode, neutralize |
| `memchr` / `bstr` | Fast byte scanning over memory-mapped buffers. | L1 |
| `regex` | Bounded, backtracking-free pattern checks (frontmatter, IDs). | L1 |
| `base64`, `hex` | Recursive decode of encoded payloads (then rescan). | L1 entropy |

## Intake, hashing, IO (L0)

| Crate | Purpose |
|-------|---------|
| `memmap2` | Memory-map files; no heap copy of hostile input. |
| `sha2` | Canonical SHA-256 bundle digest (cache + threat intel key). |
| `blake3` | Fast content hashing for the in-process cache tier. |
| `walkdir`, `ignore` | Directory traversal honoring ignore files. |
| `zip`, `tar`, `flate2` | Accept ZIP / tar.gz skill bundles. |
| `sled` *(or `redb`)* | Embedded KV cache (digest → findings) for warm re-scans. |
| `growable-bloom-filter` | In-process "definitely not seen" tier. |

## Concurrency & error handling

| Crate | Purpose |
|-------|---------|
| `rayon` | Work-stealing fan-out across files and engines. |
| `tokio` | Async runtime — **only** in `skill-doctor-mcp` and the optional network layer. |
| `anyhow` | Error boundary at the CLI. |
| `thiserror` | Typed errors in libraries. |
| `once_cell` | Lazily-initialized embedded rulesets/tables. |

## CLI, reporting, UX (`skill-doctor-cli`)

| Crate | Purpose |
|-------|---------|
| `clap` (derive) | Argument parsing / subcommands. |
| `serde`, `serde_json` | JSON report model. |
| `serde-sarif` | SARIF 2.1.0 output for GitHub Code Scanning. |
| `is-terminal` | Detect TTY; default to plain text through a pipe. |
| `anstream` + `owo-colors` | Colored diagnostics only when attached to a terminal. |
| `ratatui` + `crossterm` | Opt-in TUI (feature `tui`, never default). |
| `codespan-reporting` | Compiler-grade underlined byte-span diagnostics. |

## Semantic delegation (`skill-doctor-mcp`)

| Crate | Purpose |
|-------|---------|
| `rmcp` | Official Rust Model Context Protocol SDK (server, stdio/HTTP transports). |
| `schemars` | JSON Schema for the `skill_doctor_scan` tool + schema-constrained verdict. |
| `serde`, `serde_json`, `tokio` | Transport + envelope/verdict (I)O. |
| `rand` | Per-scan nonce generation (verdict must echo it). |

## Behavioral sandbox (`skill-doctor-sandbox`, feature `sandbox`)

| Crate | Purpose |
|-------|---------|
| `nix` | Low-level process/namespace controls for monitoring. |
| `serde`, `serde_json` | Behavior trace records. |

Note: L3 is currently implemented as a process harness with environment isolation and differential replay, not as a microVM. Future versions may integrate microVM isolation.

## Threat intel & provenance (opt-in / release)

| Crate | Purpose |
|-------|---------|
| `reqwest` (rustls) | L4 threat-intel fetch (digests/summaries only), feature-gated, opt-in. |
| `sigstore` | Verify/produce signed release artifacts + attestation. |
| `cargo-auditable` (build) | Embed dependency list for advisory scanning. |

## Rules build (`skill-doctor-rules`)

| Crate | Purpose |
|-------|---------|
| `yara-x` | Compile `rules/*.yar` in `build.rs` and serialize into the binary. |
| `serde_yaml` | Parse rule-pack metadata / SDTM-v1 mapping. |

## Dev / CI / bench (not shipped in the binary)

| Tool | Purpose |
|------|---------|
| `criterion` | Micro-benchmarks. |
| `insta` | Snapshot tests for reports (locks determinism). |
| `proptest` | Property tests (e.g. additive-only invariant, digest stability). |
| `cargo-nextest` | Faster test runner in CI. |
| `cargo-deny` | License + advisory + duplicate-dependency gate. |
| `cargo-dist` | Build/sign/publish the multi-platform binaries. |

## Distribution packages (outside crates.io)

| Channel | Artifact |
|---------|----------|
| npm `@kalarislabs/skill-doctor` | Thin installer that fetches the prebuilt static binary (no Node at scan time). |
| Homebrew tap `kalarislabs/tap` | `skill-doctor` formula. |
| winget / Scoop | Windows binaries. |
| GitHub Action `kalarislabs/skill-doctor-action` | CI gate wrapper around `scan-all`. |

> Rule of thumb: any dependency added here must keep the static musl build green and must not pull
> in a C toolchain requirement that breaks single-binary distribution. Run `cargo deny check` and
> `cargo build --target x86_64-unknown-linux-musl` before merging a new dependency.
