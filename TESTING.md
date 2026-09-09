# TESTING.md — test strategy and CI gates

## Every-commit CI (`ci.yml`)

Every push to `main` and every pull request runs the following **required** gates:

| Step | Command | Purpose |
|------|---------|---------|
| Format | `cargo fmt --all --check` | Code style consistency |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | Lint gate, zero warnings |
| Test | `cargo test --workspace --locked` | All unit + integration tests |
| Supply-chain | `cargo deny check` | License, advisory, duplicate deps |
| Secrets scan | `gitleaks detect --source .` | No committed secrets |
| CLI smoke (Linux) | `./target/release/skill-doctor scan tests/fixtures/benign --fail-on HIGH --offline --deterministic` | Binary works, exit 0 |
| CLI smoke (Windows) | Same command via `.\target\release\skill-doctor.exe` | Cross-platform |
| CLI smoke (macOS) | Same command | Cross-platform |

## What is NOT on every-commit

- TestMu, mutation testing — not used.
- musl static build — release pipeline only, not every commit.
- crates.io publish — manual release step, never automated on commit.
- npm publish — release pipeline only.
- Real malware corpus — access-gated, never in fork CI.

## Reproducibility gate

After the build step, the CI runs two `--deterministic --output json` scans of the same tree
and asserts byte-identical output (via `diff` or SHA-256 comparison). This ensures:

- Sorted directory walk
- Pinned timestamps
- Deterministic iteration over unordered collections
- Stable serialization

## Test categories

### Unit tests (`#[cfg(test)]` in each module)
- Taxonomy serialization round-trips
- Finding/Report serde round-trips
- L0 digest stability
- L1 engine detection on fixture snippets
- Additive-only invariant (L2 cannot remove L1 findings)
- Scorer boundary conditions

### Integration tests (`tests/`)
- `scan` of `tests/fixtures/benign` → exit 0
- `scan` of `tests/fixtures/attack/SD-02` → exit 2 (when L1 pattern engine is live)
- Determinism: two identical scans produce identical SHA-256
- `--help` / `--version` output smoke tests

### Property tests (`proptest`)
- Additive-only invariant holds for arbitrary finding sets
- Digest is stable regardless of file visit order

## Local pre-push (`scripts/prepublish-check.sh --fast`)

Runs: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`.
With `--full`: additionally runs `cargo deny check` and the CLI smoke test.

## Fixture conventions

- `tests/fixtures/benign/` — clean skills that must pass all scans.
- `tests/fixtures/attack/SD-XX/` — one directory per threat class with a triggering skill.
- Never commit real malware to the default test path.
