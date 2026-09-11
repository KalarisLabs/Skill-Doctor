## Description
<!-- Provide a brief description of the changes introduced by this pull request. -->

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New threat detector or rule enhancement (SDTM-v1 class)
- [ ] Performance optimization (throughput / RSS / binary size)
- [ ] Documentation update
- [ ] Other (please describe):

---

## Four-Item Detector Checklist (Required if modifying/adding detectors)
If this PR adds or modifies a threat detector (SD-01 through SD-11), verify that all four items are included:
- [ ] **1. Rule**: Rule file in `rules/` (e.g. `rules/sd_0X_*.yar`) or static engine pattern registered to an SDTM-v1 threat class in `taxonomy.rs`.
- [ ] **2. Positive Fixture**: Synthetic malicious skill in `tests/fixtures/attack/SD-XX/` that triggers the finding.
- [ ] **3. Hard-Negative Fixture**: Clean/benign skill that exercises similar syntax but does NOT trigger a finding (zero false positives).
- [ ] **4. Automated Test**: Test in `crates/skill-doctor-core/tests/` verifying positive fixture triggers failure and hard-negative passes.

---

## Invariant Verification Checklist
- [ ] **Invariant 1 (Pure Rust)**: Zero Python/Node/shell required on product scan runtime.
- [ ] **Invariant 2 (Offline & Deterministic)**: Default scan path requires zero network and zero LLMs.
- [ ] **Invariant 3 (Additive-Only)**: L2/L3/L4 never suppress or downgrade L1 findings.
- [ ] **Invariant 4 (Determinism)**: Consecutive scans produce bit-identical reports.
- [ ] **Invariant 5 (Build-time Compilation)**: Rules compiled in `build.rs`, zero scan-time compilation.
- [ ] **Invariant 6 (Neutralization)**: No unneutralized input passed to models.
- [ ] **Invariant 7 (No Secret Values)**: Only secret key names, never raw values in reports.
- [ ] **Invariant 8 (CLI First)**: Default binary is lean and standalone.
- [ ] **Invariant 9 (Scope Limit)**: SDTM-v1 stays bounded at exactly 11 classes (SD-01 through SD-11).

---

## Pre-Push Verification
- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
