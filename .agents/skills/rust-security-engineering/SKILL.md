---
name: rust-security-engineering
description: Specialist for Rust security engineering (YARA-X, Tree-sitter, AST parsing).
---

# Rust Security Engineering

Use this skill when modifying the core Rust engine (`crates/core`, `crates/cli`, `crates/report`).

## Architectural Domain
The Rust engine acts as the canonical security scanner for the Skill Doctor platform. It is responsible for fast, native analysis of files.

## Best Practices
- **YARA-X & Tree-sitter:** Prioritize memory safety and fast parsing. Always use robust AST querying.
- **Async Execution:** Use `tokio` for I/O bound tasks, but ensure compute-heavy static analysis runs on `spawn_blocking`.
- **Error Handling:** Use `anyhow` for application-level errors and `thiserror` for library-level errors. Ensure no raw panics are exposed.
- **Portability:** Ensure the engine can be compiled as a standalone CLI or wrapped for network execution. Do not mock security functions.
