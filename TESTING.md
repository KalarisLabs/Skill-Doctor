# TESTING.md — Test Strategy, CI Gates & Branch Protection

This document outlines the testing strategy, CI quality gates, and branch protection requirements for Skill Doctor.

---

## 1. Required on Every Commit / Every PR (Must be Green to Merge)

These are the non-negotiable gates that keep `npx`, `cargo install`, and the GitHub Action trustworthy. All checks are kept under ~8 minutes using `Swatinem/rust-cache@v2`, and run with matrix `fail-fast: false` so a Windows issue does not hide a macOS issue.

| Job Name | What it Proves | Why it is Non-Negotiable |
|---|---|---|
| **`check-gate`** | `cargo check --workspace --all-targets --locked` | Fast compilation baseline before running heavier jobs. |
| **`msrv-check`** | `cargo +1.93.0 check --workspace --all-targets --locked` | Enforces MSRV floor (1.93.0) and guarantees pinned toolchain compatibility. |
| **`version-sync`** | Consistency across `Cargo.toml`, `package.json`, `CHANGELOG.md`, `README.md`, `action.yml`, and `DEPENDENCIES.md` | Eliminates version drift and prevents phantom dependencies. |
| **`lint-and-unit`** | `cargo fmt`, `clippy`, unit + integration tests, invariant checks | Enforces zero warnings, code style, and architectural invariants. |
| **`supply-chain`** | `cargo deny check` + `gitleaks` + `semgrep` | Prevents supply-chain attacks, license violations, and committed credentials. |
| **`determinism`** | Two JSON/SARIF runs produce identical SHA-256 | Core product claim. Guarantees bit-reproducible scan output. |
| **`docs-smoke`** | Smoke tests all README install, CLI, and quickstart commands | Prevents documentation drift and broken copy-paste commands. |
| **`packaging-gate`** | Validates npm wrapper, tarball packaging, offline skip flag, and binary execution | Ensures released npm packages and archives install cleanly with zero stray files. |
| **`dogfood-self-scan`** | `skill-doctor scan-all .` self-scan (exit 0) and SD-02 detection (exit 2) | Proves the tool scans real repos cleanly while detecting actual attacks. |
| **`os-cli`** (Ubuntu / macOS / Windows) | `--help`, `--version`, scan benign → `0`, scan SD-02 → `2` (`--offline --deterministic`) | Validates prebuilt CLI binary execution across all 3 major platforms. |

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

Branch protection on `main` is configured and enforced via the GitHub API with the following **12 Required Status Checks**:

```text
check-gate
msrv-check
version-sync
lint-and-unit
supply-chain
determinism
docs-smoke
packaging-gate
dogfood-self-scan
os-cli (ubuntu-latest)
os-cli (macos-latest)
os-cli (windows-latest)
```

*Strict branch protection is active: branches must be up to date before merging, and all 12 checks must pass.*

---

## 7. Local Test Execution on Windows (Application Control / AppLocker)

When developing on Windows environments where unverified/unsigned test binaries in `target\debug\deps\*.exe` are blocked by Windows Application Control or AppLocker (error `4551`), run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-windows.ps1
```

This helper compiles test targets (`cargo test --no-run`), automatically signs generated test executables and DLLs using `signtool.exe` with a developer certificate, and executes the complete test suite (87+ tests across all workspace crates and integration suites).

