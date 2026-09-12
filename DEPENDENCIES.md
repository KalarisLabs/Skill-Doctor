# DEPENDENCIES.md — Every Package We Use and Why

This document details the complete, verified dependency graph for Skill Doctor `v0.1.0`. All versions are pinned in `Cargo.lock` with Rust edition 2021 and MSRV `1.93.0`.

Skill Doctor compiles to a single, standalone static binary with zero external runtime interpreters and zero mandatory network calls.

---

## 1. Shipped in Default Binary

These crates form the core static analysis engine and CLI, linked into the primary distribution binary.

### Core Analysis & Hashing (`skill-doctor-core`, `skill-doctor-neutralize`, `skill-doctor-rules`)

| Crate | Version | Purpose |
|-------|---------|---------|
| `yara-x` | `1.20.0` | Pure-Rust YARA compiler & VM executing SD-01 through SD-11 threat rules. Configured with `default-features = false, features = ["constant-folding"]` to exclude native binary/crypto modules. **Note on footprint**: `yara-x` compiles rules into WebAssembly bytecode and executes them via embedded `wasmtime` 45.0.3 using the Cranelift JIT compiler; this Cranelift/wasmtime subsystem accounts for ~14 MB of the stripped binary. |
| `unicode-security` | `0.1.2` | UTS #39 confusables, mixed-script detection, and ASCII skeleton generation for Trojan Source and homoglyph detection (SD-10 / SD-11). |
| `unicode-normalization`| `0.1.25`| NFC / NFKC canonical decomposition and zero-width character detection. |
| `regex` | `1.13.1` | Linear-time, backtracking-free regular expression matching for frontmatter parsing and rule matching. |
| `memchr` | `2.8.3` | SIMD-accelerated byte-level substring searching. |
| `base64` | `0.23.1` | Multi-pass recursive decode of obfuscated payloads (Base64 standard & URL-safe) for hidden threat scanning. |
| `hex` | `0.4.3` | Hexadecimal payload decoding and digest formatting. |
| `sha2` | `0.11.0` | Canonical cryptographic SHA-256 digesting of files and skill bundles. |
| `rayon` | `1.12.0` | Work-stealing parallel multi-threaded file and bundle traversal. |
| `zip` | `8.6.0` | Native intake and in-memory extraction of `.zip` skill archives. |
| `tar` | `0.4.46` | Native intake of `.tar` skill bundles. |
| `flate2` | `1.1.10`| Gzip decompression for `.tar.gz` and `.tgz` archives. |
| `walkdir` | `2.5.0` | Recursive directory traversal with cycle detection. |
| `serde` | `1.0.229`| Serialization framework with derive macros. |
| `serde_json` | `1.0.151`| Deterministic JSON and SARIF report generation. |
| `serde_yaml` | `0.9.34`| YAML frontmatter parsing for `SKILL.md` capability manifests. |
| `thiserror` | `2.0.20`| Ergonomic, strongly typed error models across internal crate boundaries. |

### CLI, Terminal UX & Filesystem Watcher (`skill-doctor-cli`)

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | `4.6.6` | Command-line argument parsing with derive macros. |
| `anstream` | `1.0.0` | Terminal stream colorizer honoring `NO_COLOR` and ANSI capability. |
| `anstyle` | `1.0.14`| Zero-dependency ANSI style definitions for terminal diagnostics. |
| `is-terminal` | `0.4.17`| TTY detection to default to uncolored output when piped or running in CI. |
| `indicatif` | `0.18.6`| Terminal progress bars for multi-skill batch scanning. |
| `notify` | `8.2.0` | Cross-platform filesystem watcher for `skill-doctor watch`. |
| `anyhow` | `1.0.104`| Top-level application error handling with backtraces. |

---

## 2. Feature-Gated Modules (Opt-In)

These crates are activated via Cargo features and compiled into specialized configurations.

### Model Context Protocol Server (`--features mcp`, `skill-doctor-mcp`)
Included in official prebuilt release binaries to enable `skill-doctor mcp`.

| Crate | Version | Purpose |
|-------|---------|---------|
| `rmcp` | `3.2.0` | Official Rust SDK for the Model Context Protocol (stdio transport, JSON-RPC 2.0). |
| `tokio` | `1.53.1`| Async runtime (`rt`, `macros`, `io-std`) driving the MCP event loop. |
| `uuid` | `1.26.1`| Cryptographically secure single-use session nonces preventing prompt replay attacks. |

### Behavioral Sandbox Harness (`--features sandbox`, `skill-doctor-sandbox`)
Opt-in L3 dynamic analysis harness providing process tree monitoring and environment isolation.

| Crate | Version | Purpose | Platform |
|-------|---------|---------|----------|
| `windows-sys`| `0.61.2`| Windows Job Objects, process containment, and token manipulation. | Windows only |
| `libc` | `0.2` | Process groups (`setpgid`), file descriptor management, and resource limits. | Unix only |
| `tempfile` | `3.27.0`| Ephemeral isolated scratch filesystems for child execution. | All |
| `uuid` | `1.26.1`| Unique sandbox session identifiers. | All |

### Optional Terminal UI (`--features tui`)

| Crate | Version | Purpose |
|-------|---------|---------|
| `ratatui` | `0.30.2`| Opt-in interactive terminal dashboard. |
| `crossterm`| `0.29.0`| Cross-platform terminal control and raw mode. |

---

## 3. Development & CI Dependencies (Not Shipped in Binary)

| Crate / Tool | Version | Purpose |
|--------------|---------|---------|
| `criterion` | `0.8.2` | Statistical micro-benchmarks for L0 intake and L1 analysis engines. |
| `tempfile` | `3.27.0`| Test fixture isolation in unit and integration test suites. |
| `cargo-deny` | `v2.0.11`| Automated supply-chain gate (licenses, bans, RUSTSEC advisories). |
| `gitleaks` | `v8.24.0`| Pre-commit and CI secrets scanner. |
| `semgrep` | `v1` | Architectural invariant enforcement (no unauthorized crate imports). |

---

## 4. Packaging & Platform Summary

| Target Triple | OS / Environment | Binary Format | Linkage |
|---------------|------------------|---------------|---------|
| `x86_64-unknown-linux-musl` | Linux x64 | ELF | 100% Statically linked (musl libc) |
| `aarch64-unknown-linux-musl`| Linux ARM64 | ELF | 100% Statically linked (musl libc) |
| `x86_64-apple-darwin` | macOS x64 (Intel)| Mach-O | Dynamically links `libSystem` |
| `aarch64-apple-darwin` | macOS ARM64 (Apple Silicon) | Mach-O | Dynamically links `libSystem` |
| `x86_64-pc-windows-msvc` | Windows x64 | PE32+ (exe) | Statically links MSVC CRT (`/MT`) |
