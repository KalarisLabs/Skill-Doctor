# TESTING.md — Test Strategy, CI Gates & Branch Protection

This document outlines the testing strategy, CI quality gates, and branch protection requirements for Skill Doctor.

---

## 1. Required on Every Commit / Every PR (Must be Green to Merge)

These are the non-negotiable gates that keep `npx`, `cargo install`, and the GitHub Action trustworthy. All checks are kept under ~8 minutes using `Swatinem/rust-cache@v2`, and run with matrix `fail-fast: false` so a Windows issue does not hide a macOS issue.

| Job Name | What it Proves | Why it is Non-Negotiable |
|---|---|---|
| **`lint-and-unit`** (`fmt`) | `cargo fmt --all --check` | Contributors and coding agents cannot bikeshed code style. |
| **`lint-and-unit`** (`clippy`) | `cargo clippy --workspace --all-targets -- -D warnings` | The real Rust review bot; enforces zero warnings across all crates. |
| **`lint-and-unit`** (`tests`) | `cargo test --workspace --locked` | Unit + integration + CLI tests pass. `--locked` ensures CI matches `Cargo.lock`. |
| **`lint-and-unit`** (`invariants`) | Default features have no OpenAI / Anthropic SDK | Keeps the "no mandatory LLM / pure offline" invariant true in CI, not just in README. |
| **`os-cli`** (Ubuntu / macOS / Windows) | `--help`, `--version`, scan benign → `0`, scan SD-02 → `2` (`--offline --deterministic`) | Adoption is "does the CLI work on my laptop." |
| **`determinism`** | Two JSON/SARIF runs produce identical SHA-256 | Core product claim. Without this, CI users will not trust `--fail-on`. |
| **`lint-and-unit`** (`additive-only`) | L1 CRITICAL survives an L2 "benign" | SD-11 invariant; one regression and the scanner is unsafe. |
| **dogfood-self-scan** | `skill-doctor scan-all . --exclude tests/fixtures/attack --exclude tests/fixtures/evasion --exclude sd-bench/corpora --fail-on HIGH --offline` | Scans all first-party skills and benign fixtures (excluding deliberate malware attack corpora); must exit 0, and asserts attack fixture SD-02 exits 2. |
| **`supply-chain`** | `cargo deny check` + `gitleaks` | Prevents supply-chain attacks, license violations, and committed credentials. |

### What is NOT on this Path
Do not put on this path: TestMu Kane, competitor benches, musl cross-compile, `cargo publish`, `npm publish`, or coverage percentage-fails. Those killed v1 and they do not help a first-time adopter.

---

## 2. Required on Every PR, but Not a Merge Blocker During Bootstrap

- **Coverage (`cargo-tarpaulin` / `llvm-cov`)**: Upload the coverage report. Fail on % only after a verified baseline is established.
- **AI Reviewers (CodeRabbit / Greptile / Intelligence AI)**: Comments, not required checks. Security findings from Greptile require human review.

---

## 3. Required Before Anyone Can Adopt (Release Tags `v*` Only)

This is what makes crates.io, npm, and GitHub Releases safe, not just green:
1. All required checks green on that release commit SHA.
2. musl `linux-amd64` binary actually runs `scan --offline` on the benign fixture (proves "one binary, zero deps").
3. SHA-256 checksums published next to every released binary asset.
4. SBOM (`cargo cyclonedx`) + Sigstore cryptographic attestation.
5. `cargo publish --dry-run` in crate dependency order, followed by `npm pack` checksum verification.
6. `CHANGELOG.md` entry documenting changes for the tag.
7. Optional but strong: GitHub Code Scanning ingestion of SARIF from `skill-doctor gate` on this repository.

---

## 4. Nightly Benchmarks (Not Per-Commit)

- **`sd-bench`**: Runs against pinned competitors (Cisco AI Defense, NVIDIA SkillSpector), recording target vs measured throughput in `sd-bench/RESULTS.md`.
- Does not fail PRs on the 2,000 skills/min or 40 MB peak memory metrics until the complete corpus harness is populated.

---

## 5. Open-Source Repository Hygiene Files

The repository enforces the presence of standard open-source files:
- [x] `LICENSE`: Apache-2.0
- [x] `SECURITY.md`: Private vulnerability reporting instructions (no dropping malware in public issues)
- [x] `CONTRIBUTING.md`: Points to `TESTING.md` and enforces the four-item detector PR requirement
- [x] `.github/CODEOWNERS`: Global repository owners
- [x] `.github/dependabot.yml`: Automated dependency updates for Cargo, GitHub Actions, and npm
- [x] `deny.toml`: Supply-chain policy configuration
- [x] Issue Templates: `bug_report.yml`, `feature_request.yml`, and `config.yml`

---

## 6. GitHub Branch Protection Configuration

Configure branch protection on `main` with the following **Required Status Checks**:

```text
lint-and-unit
os-cli (ubuntu-latest)
os-cli (macos-latest)
os-cli (windows-latest)
supply-chain
dogfood-self-scan
determinism
docs-smoke
```

*Admin bypass should be disabled to ensure all merged code meets these quality criteria.*
