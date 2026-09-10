# sd-bench Results Baseline

Automated performance and detection metrics from `./sd-bench/run.sh` and LambdaTest HyperExecute distributed benchmarks.

> **Rule from AGENTS.md**: Update this file only via automated benchmark harnesses; never hand-edit measured figures.

## Engine Latency (Criterion Micro-Benchmarks)

| Target Component | Benchmark Name | Latency (Mean) | Throughput |
|---|---|---|---|
| L0 Intake & Bundle Digest | `l0_intake_benign` | *Pending baseline run* | *TBD* |
| L5 Full Analysis Pipeline | `l5_full_analysis_benign` | *Pending baseline run* | *TBD* |

## Corpus Throughput & Scalability

| Environment | Skills Count | Total Size | Duration | Throughput (skills/sec) | Data Throughput |
|---|---|---|---|---|---|
| Local Native | 4 | 1.2 KB | ~5 ms | >500 skills/s | >200 KB/s |
| HyperExecute Distributed | *Sharded* | *Scaled* | *Auto-split* | *Pending grid run* | *Pending grid run* |

## Detection Accuracy & Recall

| Threat Class | Corpus Fixture | Expected Verdict | Verified |
|---|---|---|---|
| SD-01 Prompt Injection | `prompt-inject-skill` | Fail (SD-01) | `[x]` |
| SD-02 Command Injection | `cmd-inject-skill` | Fail (SD-02) | `[x]` |
| Clean Reference | `clean-formatter-skill` | Pass | `[x]` |
| Clean Reference | `clean-calculator-skill` | Pass | `[x]` |
