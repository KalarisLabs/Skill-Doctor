---
name: rust-idioms
description: Everyday Rust engineering for Skill Doctor — errors, ownership, clippy, APIs, iterators. Use when writing or reviewing Rust that is not specifically about perf, unsafe, or YARA.
---

# Rust idioms

## Errors

- Libraries: `thiserror` enums. No `unwrap` / `expect` on recoverable paths.
- Binary: `anyhow` at `main` only. Map to exit codes in one place.
- Do not `panic` in L1 because a skill file is malformed. Malformed input is a finding or a skipped file with coverage reduced.

## Ownership

- Hot path: borrow (`&[u8]`, `&str`, `&Path`). Own only when storing in a `Finding`.
- Do not `clone()` to satisfy the borrow checker if a lifetime or `Arc` would do. Clippy `clone_on_copy` / needless clones must stay clean.
- `PathBuf` walks: collect sorted `Vec<PathBuf>` once, then iterate. Do not `read_dir` twice.

## APIs

- Public core API is small: `scan_bundle(&[u8] | &Path) -> Result<Report>`.
- Rule IDs and SD class IDs are `&'static str` or newtypes, not free-form `String` invented at runtime.
- Prefer `enum Severity { Low, Medium, High, Critical }` over strings.

## Clippy / fmt

- `cargo fmt --all` is not optional.
- `clippy --all-targets -- -D warnings` is the style guide. Do not fight clippy with `#[allow]` unless the allow cites an invariant.
- `unsafe` is not an idiom. Load `unsafe-sandbox` instead.

## Concurrency

- L1 fan-out: `rayon`. No `tokio` in core.
- MCP / optional L4: `tokio`.
- Shared state: `std::sync` / `arc_swap` / `OnceLock`. Do not add a new runtime.
