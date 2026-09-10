---
name: rust-workspace
description: Cargo workspace layout, crate boundaries, and dependency policy for Skill Doctor. Use when creating crates, editing Cargo.toml, adding modules, moving types, or adding a dependency.
---

# Rust workspace

## Boundaries

- `skill-doctor`: binary only. clap + report printers. No YARA, no taint, no MCP protocol.
- `skill-doctor-core`: engines + scoring. No clap. No `tokio`.
- `skill-doctor-rules`: `build.rs` embeds compiled YARA. Scan path never compiles rules.
- `skill-doctor-neutralize`: pure functions. No filesystem, no network.
- `skill-doctor-mcp`: `tokio` allowed. Depends on core + neutralize.
- `skill-doctor-sandbox`: feature-gated. Only `unsafe` crate.

## Dependency rules

1. Versions live in root `[workspace.dependencies]`. Member crates use `{ workspace = true }`.
2. Adding a crate requires updating `DEPENDENCIES.md` in the same change.
3. `anyhow` only in the binary. Libraries use `thiserror`.
4. Default features of `skill-doctor` must **not** enable `sandbox`, `tui`, or network.
5. After any Cargo.toml edit: `cargo metadata --locked` (or generate lockfile once) must succeed.
6. Forbidden on the default path: Python/PyO3, Node, OpenAI/Anthropic SDKs, scan-time YARA compile.

## Module layout inside core

```
src/l0/  intake, digest, cache
src/l1/  pattern, taint, entropy, unicode, capability
src/l4/  intel (feature)
src/l5/  merge, coverage, report types
src/taxonomy.rs   SD-01…SD-11 only unless the whitepaper adds a class
```

Do not collapse crates to “make it simpler.” The boundaries exist so L1 stays a library other tools can embed.
