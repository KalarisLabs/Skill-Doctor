---
name: rust-testing
description: How to write Skill Doctor tests — unit, integration, CLI, fixtures, determinism, additive-only. Use when adding tests, fixtures, snapshots, or changing cargo test layout.
---

# Testing

Canonical policy: `TESTING.md`. Do not invent a second harness.

## Placement

| Kind | Where |
|------|--------|
| Unit | `#[cfg(test)]` next to the code |
| Integration | `crates/<name>/tests/` |
| CLI / exit codes | `tests/cli/` against the compiled binary |
| Fixtures | `tests/fixtures/{benign,attack,hard_negative,evasion}/` |
| Real malware | `tests/fixtures/real_malware/`, `#[ignore]`, `REAL_MALWARE=1` |

## Detector PR checklist (all four)

1. Engine or YARA rule  
2. Positive fixture (must fire)  
3. Hard-negative (must not fire)  
4. Test asserting both

## Always-on property tests

- **Determinism:** two scans, equal SHA-256 of JSON.
- **Additive-only:** L1 CRITICAL + L2 "benign" → CRITICAL remains.
- **Offline:** `--offline` makes zero network syscalls (at least: no `reqwest` constructed).
- **Malformed skill:** does not panic.

## Forbidden

- Network in unit tests.
- `thread::sleep` for sandbox.
- Snapshots with timestamps or absolute paths.
- Live secrets. Use canaries like `AKIA_TEST_CANARY`.
- Speed assertions in the every-commit suite (see `rust-perf`).
