---
name: ci-cd
description: GitHub Actions, required checks, TestMu, OS matrix, and merge gates for Skill Doctor. Use when editing workflows, adding CI jobs, deciding what runs on every commit, or wiring crates/npm publish.
---

# CI/CD

Canonical policy: `TESTING.md`. Workflows must match it. If you change a required check, update `TESTING.md` in the same PR.

## Every commit / every PR (required, must stay fast)

Job names (branch protection should match these strings):

- `lint-and-unit` — fmt, clippy `-D warnings`, `cargo test --workspace --locked`, invariant grep
- `os-cli (ubuntu-latest)` / `(macos-latest)` / `(windows-latest)` — build CLI, `--help`, `version`, later: benign exit 0 and SD-02 exit 2
- `supply-chain` — `cargo deny`, gitleaks

Keep this path under ~8 minutes on cache hit. Use `Swatinem/rust-cache`. OS matrix `fail-fast: false`.

**Do not put on this path:** TestMu Kane, competitor benches, musl cross, `cargo publish`, `npm publish`, coverage fail gates during bootstrap.

## Not every commit

| Workflow | Trigger | Why |
|----------|---------|-----|
| `testmu.yml` | label `e2e`, nightly, `main`, `workflow_dispatch` | Kane/LambdaTest is slow, billed, AI-flaky |
| `bench.yml` | nightly + tags | Docker competitor pulls |
| `release.yml` | tags `v*` only | musl, SBOM, Sigstore, crates.io, npm |

## How an agent should add CI

1. New *product* behavior → add a unit/CLI test first. CI already runs `cargo test`.
2. New *tooling* (deny, gitleaks, a matrix OS) → add a job in `ci.yml` only if it belongs on every commit.
3. New *expensive* check → new workflow, non-required, document in `TESTING.md`.
4. Never store tokens in YAML. Use existing secrets: `NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, `LT_USERNAME`, `LT_ACCESS_KEY`.
5. Pin action versions; prefer SHA once v2 is tagged.
6. Do not add a fourth review bot. CodeRabbit / Greptile / Intelligence AI are PR comments, not required checks.

## Local commands agents must run before claiming CI will pass

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
./scripts/prepublish-check.sh --fast
```

`--full` is the pre-tag gate (deny + publish dry-run). Never `cargo publish` / `npm publish` from a feature branch.

## Coverage

llvm-cov / tarpaulin is informational until a baseline exists. Do not `-D` fail PRs on coverage % during bootstrap.
