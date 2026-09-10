# TESTING.md — test strategy and CI gates

## Every-commit CI (`ci.yml`)

Every push to `main` and every pull request runs the following **required** gates:

| Gate | Command / Action | Purpose |
|------|------------------|---------|
| Quality code | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --locked` | Code formatting, zero warnings, and unit/integration correctness |
| Architectural invariants | Grep check for forbidden LLM API keys / direct model dependencies | Ensure SD-11 and offline invariants hold |
| Security audit | `gitleaks detect`, `skill-doctor scan-all . --output sarif --fail-on HIGH` | Secrets audit, self-scan dogfood gate, SARIF upload |
| Security audit dependency | `cargo audit`, `cargo deny check`, `npm audit` | RustSec advisory audit, license/bans/sources policy, npm wrapper audit |
| Security advisories tests | `cargo deny check advisories`, `cargo test --test security_advisories_test` | Vulnerability advisory tests and supply-chain (SD-05) rule verification |
| Dependency test coverage | `cargo tarpaulin --workspace` | Workspace and dependency test coverage reporting and artifacts |
| Reproducibility | Two `--deterministic --output json` scans compared via SHA-256 | Bit-identical output determinism verification |
| Cross-platform smoke | CLI scan of benign (exit 0) and attack SD-02 (exit 2) on Ubuntu, macOS, Windows | Cross-platform binary verification |
| Performance smoke | `cargo bench --workspace -- --test` | Benchmark verification smoke test |

## Specialized CI Pipelines

| Pipeline | Workflow | Triggers | Purpose |
|----------|----------|----------|---------|
| **TEST mulambda E2E** | `.github/workflows/testmu.yml` | label `e2e`, nightly (`02:00 UTC`), `main`, `workflow_dispatch` | Comprehensive end-to-end testing matrix across OSs, fixture suites, SARIF schema, baseline diff, npm wrapper, and LambdaTest/TestMu Kane cloud integration with `LT_USERNAME`/`LT_ACCESS_KEY` |
| **Performance benchmarks** | `.github/workflows/bench.yml` | label `bench`, nightly (`03:00 UTC`), tags `v*`, `workflow_dispatch` | Criterion micro-benchmarks, §7.3 throughput (≥2,000 skills/min), and peak RSS (<40 MB) metrics reporting |


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
