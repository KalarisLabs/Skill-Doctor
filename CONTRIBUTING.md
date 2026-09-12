# Contributing to Skill Doctor

Thank you for contributing to Skill Doctor! We welcome contributions that make the scanner faster, more accurate, and more robust.

Please read [AGENTS.md](AGENTS.md) and [CONTEXT.md](CONTEXT.md) before writing code, and review [TESTING.md](TESTING.md) before opening a pull request.

---

## The Four-Item Detector Pull Request

Every pull request adding or modifying a threat detector (SD-01 through SD-11) **must ship with all four items**:

1. **A Rule**: An embedded YARA-X or static engine rule registered in `rules/` and mapped to its SDTM-v1 class in `skill-doctor-core::taxonomy`.
2. **A Positive Fixture**: A synthetic skill file in `tests/fixtures/attack/SD-XX/` that triggers the finding.
3. **A Hard-Negative Fixture**: A clean, benign skill file (e.g. in `tests/fixtures/benign/` or companion sample) that exercises similar syntax but does **not** trigger a finding.
4. **An Automated Test**: A Rust test in `tests/` or in the engine module verifying that the positive fixture fails, the hard-negative fixture passes, and findings are deterministic.

---

## Non-Negotiable Invariants

PRs that violate any of these invariants will be rejected by automated CI:

- **Rust Only**: The core scanner runtime is pure Rust. No Python, no Node, no shell interpreter required to scan.
- **No Mandatory LLM**: The default scan path (`--offline --deterministic`) requires zero network, zero API keys, and zero cloud accounts.
- **Additive-Only Invariant**: Probabilistic/L2 layers may add findings or raise confidence, but can **never** suppress, downgrade, or remove a deterministic L1 finding.
- **Determinism**: In `--deterministic` mode, running `skill-doctor` twice on identical inputs must produce byte-identical SHA-256 output.
- **No Secret Values**: Never persist raw API keys or secret tokens in findings, evidence, or logs.

---

## Local Pre-Push Checklist

Before opening a PR, run the local pre-publish check:

```bash
# Fast check (fmt + clippy + test)
./scripts/prepublish-check.sh --fast

# Or run commands directly:
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Every PR must pass all 12 required status checks across platforms (including check-gate, msrv-check, version-sync, packaging-gate, and os-cli on Ubuntu, macOS, and Windows). See [TESTING.md](TESTING.md) §6 for the complete required checks set.

