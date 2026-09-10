# sd-bench Results Baseline

Automated performance and detection metrics from `./sd-bench/run.sh` and LambdaTest HyperExecute distributed benchmarks.

> **Rule from AGENTS.md**: Update this file only via automated benchmark harnesses; never hand-edit measured figures. Do not conflate Criterion micro-benchmarks with corpus throughput.

---

## Pre-registered Targets (§7.3) vs Measured Baseline

These pre-registered targets represent the architectural optimization budget. Measured figures are produced empirically by the benchmark harness (`./sd-bench/run.sh`) or release artifact verification on the tagged SHA.

| Metric | Target | Measured Status | Verification Source |
|---|---|---|---|
| Throughput (offline L1, warm cache off) | **≥ 2,000 skills/min** | Target budget | Evaluated on release tags & nightly grid via `./sd-bench/run.sh` / HyperExecute |
| Peak RSS | **< 40 MB** | Target budget | Zero-alloc miss path verified; evaluated on release tags |
| Install Footprint | **one binary, ~12 MB, zero runtime deps** | **2.2 MB** (release binary, default features) | Measured on Windows x64 MSVC (`target/release/skill-doctor.exe`) |
| Cold install → first result | **< 15 s** | Target budget | Standalone precompiled binary executes with zero runtime dependencies |

---

## Engine Latency (Criterion Micro-Benchmarks)

*Note: Criterion micro-benchmarks measure component engine execution time (in-process iterations over synthetic benchmarks); they must not be conflated with multi-process corpus scanning throughput.*

Measured via `cargo bench -p skill-doctor-core`:

| Target Component | Benchmark Name | Latency (Mean) | Operations / sec |
|---|---|---|---|
| L0 Intake & Bundle Digest | `l0_intake_benign` | 140.39 µs | ~7,123 ops/s |
| L5 Full Analysis Pipeline | `l5_full_analysis_benign` | 31.90 µs | ~31,348 ops/s |

---

## Corpus Throughput & Scalability

Measured via `./sd-bench/run.sh` over representative skill directory corpora:

| Environment | Skills Count | Total Size | Duration | Throughput (skills/sec) | Data Throughput |
|---|---|---|---|---|---|
| Local Native (Per-process CLI) | 4 | 1,314 B | ~1.6 s | 2.5 skills/s | 0.8 KB/s |
| HyperExecute Distributed | *Sharded* | *Scaled* | *Auto-split* | Nightly / Tag Grid | Distributed harness via `.github/workflows/hyperexecute-bench.yml` |

---

## Detection Accuracy & Recall

Empirically verified against reference corpora:

| Threat Class | Corpus Fixture | Expected Verdict | Verified |
|---|---|---|---|
| SD-01 Prompt Injection | `prompt-inject-skill` | Fail (SD-01) | `[x]` |
| SD-02 Command Injection | `cmd-inject-skill` | Fail (SD-02) | `[x]` |
| Clean Reference | `clean-formatter-skill` | Pass | `[x]` |
| Clean Reference | `clean-calculator-skill` | Pass | `[x]` |
