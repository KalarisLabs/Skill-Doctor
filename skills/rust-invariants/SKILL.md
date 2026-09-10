---
name: rust-invariants
description: Nine non-negotiable Skill Doctor product invariants. Use when changing scan defaults, scoring, features, networking, LLM/MCP paths, CLI flags, or anything that could weaken determinism or additive-only behavior.
---

# Invariants — stop and redesign if a change breaks one

1. **Rust-only product runtime.** npm is a binary installer. Node never scans.
2. **No mandatory LLM.** Default is `--offline --deterministic`. L1 needs zero network, zero key.
3. **Additive-only.** L2 may add findings or raise confidence. L2 may never delete or downgrade L1.
4. **Determinism.** Two `--deterministic` runs → identical JSON/SARIF bytes (sorted maps, pinned time, sorted walks).
5. **Rules compiled at build time** in `skill-doctor-rules`. Never per scan.
6. **SD-11.** Any bytes sent to any model pass through `skill-doctor-neutralize` first.
7. **Secrets.** Emit environment *key names* only, never values.
8. **CLI-first.** TUI is feature `tui` plus an explicit flag. Never default.
9. **Four frozen contributions.** Do not invent SD-12 or a fifth claim.

## Tests that must exist

- `cargo tree -e features -p skill-doctor` has no LLM crate on default features.
- Table test: L1 CRITICAL survives an L2 verdict of "benign".
- Two deterministic JSON reports, equal SHA-256.
- Neutralize is not a no-op on bidi / zero-width / homoglyph fixtures.

## CI grep (keep in ci.yml)

Fail the job if default-path sources match `openai|anthropic|OPENAI_API_KEY|ANTHROPIC_API_KEY`.
