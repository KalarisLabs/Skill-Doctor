# Contributing to Skill Doctor

Thank you for contributing to Skill Doctor! We welcome contributions that make the scanner faster, more accurate, and more robust.

Please read [AGENTS.md](AGENTS.md) and [CONTEXT.md](CONTEXT.md) before writing code, and review [TESTING.md](TESTING.md) before opening a pull request.

---

## 10-Minute Developer Setup

Skill Doctor requires Rust 1.93.0+ and standard build tools:

```bash
# 1. Clone repository
git clone https://github.com/KalarisLabs/Skill-Doctor.git
cd Skill-Doctor

# 2. Verify toolchain (pinned in rust-toolchain.toml)
rustup show

# 3. Build workspace release binary with MCP support
cargo build --release --locked --features mcp

# 4. Run test suite across all features
cargo test --workspace --all-features --locked

# 5. Execute quick smoke test against public fixture
cargo run -p skill-doctor --locked --features mcp -- scan ./examples/hello-skill
```

---

## Minimum Supported Rust Version (MSRV) Policy

The project MSRV is **Rust 1.93.0**:
- Pinned in `rust-toolchain.toml` and specified in `Cargo.toml` (`rust-version = "1.93.0"`).
- The MSRV is strictly enforced on every PR by the `msrv-check` CI gate.
- Why 1.93.0? This version was bisected as the minimum compiler providing standard library APIs and YARA-X compilation features while guaranteeing stability across Ubuntu, macOS, and Windows build environments.
- Any change to MSRV requires an explicit RFC and must be synchronized across `Cargo.toml`, `rust-toolchain.toml`, `README.md`, and CI workflows.

---

## Required Status Checks (12 CI Gates)

Every pull request must pass all 12 required status checks before merge:

1. `check-gate`: Cargo check across all workspace crates and target configurations.
2. `msrv-check`: Compilation verified under Rust 1.93.0.
3. `lint-and-unit`: Formatting (`cargo fmt --check`), clippy (`-D warnings`), and full unit tests.
4. `supply-chain`: Dependency audit and license compliance via `cargo-deny` and `gitleaks`.
5. `determinism`: Dual-run report hashing proving byte-identical outputs (`--deterministic`).
6. `os-cli (ubuntu-latest)`: Native CLI binary execution and scan verification on Ubuntu.
7. `os-cli (macos-latest)`: Native CLI binary execution and scan verification on macOS.
8. `os-cli (windows-latest)`: Native CLI binary execution and scan verification on Windows.
9. `dogfood-self-scan`: Skill Doctor scanning its own repository with zero critical findings.
10. `docs-smoke`: Link validation and command consistency verification across documentation.
11. `packaging-gate`: Crate packaging and dry-run validation for published artifacts.
12. `version-sync`: Synchronized versioning between `Cargo.toml`, `package.json`, `action.yml`, `CHANGELOG.md`, and `README.md`.

---

## How to Add a YARA Rule End-to-End

Detector contributions must adhere to the 11 frozen threat classes in `SDTM-v1`. Adding a new rule requires four artifacts:

```
Rule File (.yar) ───► Positive Fixture (attack/) ───► Hard-Negative Fixture (benign/) ───► Automated Test
```

1. **Rule Definition**: Add rule in `rules/` (e.g. `rules/sd_02_cmd_injection.yar`). Rules are compiled at build time by `crates/skill-doctor-rules/build.rs` into serialized bytecode. Never parse raw rules at scan time.
2. **Positive Fixture**: Add a minimal, defanged synthetic attack skill in `tests/fixtures/attack/SD-XX/<sample-name>/` (e.g. `SKILL.md` or companion script) that reliably triggers the rule.
3. **Hard-Negative Fixture**: Add a clean, benign skill in `tests/fixtures/benign/<sample-name>/` that exercises similar words, tokens, or script patterns without triggering a false positive.
4. **Automated Test**: Add an integration test in `crates/skill-doctor-core/tests/` asserting that:
   - The attack fixture fails with exit code 2 and reports the exact `rule_id`.
   - The benign fixture passes with exit code 0.
   - Outputs under `--deterministic` remain byte-identical across consecutive executions.

---

## Corpus Safety Policy

Skill Doctor is a security scanner, but the public repository must remain safe for all environments:
- **No live malware**: Zero live malware, exploit payloads, or weaponized command-and-control scripts may ever be committed.
- **Defanged samples**: Malicious samples must use benign commands (`echo`, `calc`, `whoami`), mock domains (`example.com`, `localhost`), and synthetic canary credentials (`AKIA_CANARY_*`).
- **Secret values**: Tests and fixtures must never include real tokens, credentials, or private keys. Reports and logs must only emit secret key names (`AWS_SECRET_ACCESS_KEY`), never secret values.

---

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New scanner features or detectors.
- `fix:` Bug fixes, false-positive reductions, or parser corrections.
- `chore:` Maintenance, dependency updates, build tooling.
- `docs:` Documentation improvements and clarifications.
- `test:` Test fixtures, unit tests, or benchmarking harnesses.
- `ci:` GitHub Actions and CI workflow modifications.

---

## Review & Merge Expectations

- Every PR requires review from repository maintainers (see `.github/CODEOWNERS`).
- The additive-only invariant is non-negotiable: L2/L3/L4 layers can never delete or downgrade an L1 deterministic finding.
- PRs must strictly adhere to the checklist in `.github/PULL_REQUEST_TEMPLATE.md`.
