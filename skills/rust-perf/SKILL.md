---
name: rust-perf
description: Rust performance and memory optimization for Skill Doctor L1. Use when making scans faster, reducing RSS or binary size, adding rayon/mmap, writing benchmarks, or discussing the §7.3 targets (2000 skills/min, 40MB, 12MB binary, 15s cold).
---

# Rust performance

Load this before optimizing. Do **not** sacrifice invariants (determinism, additive-only, no mandatory LLM) for speed.

## Pre-registered targets (§7.3) — not measured results

Treat these as the optimization budget. Write them into benches as `assert` ceilings once harness exists. Until then, design so they are reachable. Never publish a number as measured unless `sd-bench/RESULTS.md` was produced by the harness on a tagged release.

| Metric | Target |
|--------|--------|
| Throughput (offline L1, warm cache off) | **≥ 2,000 skills/min** |
| Peak RSS | **< 40 MB** |
| Install | **one binary, ~12 MB, zero runtime deps** |
| Cold install → first result | **< 15 s** |

Parity with Cisco/NVIDIA on synthetic TPR is the detection claim; **adoption** is this table. Competitors cannot move install footprint without leaving Python.

## What to optimize (in order)

1. **Do not compile YARA at scan time.** `build.rs` once. Scan = match.
2. **mmap** skill files with `memmap2` when size > ~64 KiB. Keep small files on the stack/heap.
3. **Zero extra alloc on the miss path.** A clean skill should not build a `Vec<Finding>` of zeros then throw it away — return empty slice / `SmallVec`.
4. **Rayon over files and engines**, not over lines inside one 2 KB SKILL.md.
5. **Sorted walk once.** Determinism and perf: `ignore`/`walkdir` → collect → `sort` → process.
6. **Canonical digest** over sorted `(path, content)` pairs; hash streaming, not a giant concatenated `String`.
7. **No tokio, no async, no reqwest** on the default path. Async startup cost kills cold-install.
8. **Binary size:** default features slim. `LTO=thin` in release profile. `strip = true`. Avoid `tokio`+`reqwest`+`openssl` in the default binary (use rustls only if L4 is on). Target ~12 MB **stripped musl**.
9. **RSS:** do not hold every file's bytes after L1 on that file finishes. Drop mmaps per file. Global caches are digest → findings, bounded.
10. **Ruleset** is embedded bytes, not a temp directory of `.yar` files at runtime.

## Forbidden “optimizations”

- Skipping Unicode/SD-11 work on the L2 path to go faster (L2 is optional; L1 unicode still runs).
- Unordered `HashMap` iteration in reports (breaks determinism). Use `BTreeMap` or sort before serialize.
- `parallel` + unsynchronized `Vec::push`.
- Adding an LLM “to filter false positives” on the hot path.
- `cargo build --release` numbers copied into the paper. Paper values stay **targets** until RESULTS.md.

## How to measure

```bash
cargo build -p skill-doctor --release
/usr/bin/time -v ./target/release/skill-doctor scan-all ./tests/fixtures --offline --deterministic
# RSS = Maximum resident set size
# Throughput = fixtures / wall time * 60
```

Prefer `criterion` or a fixed `benches/` once the scan path exists. Pin fixture counts. Do not use `std::time` in unit tests as a pass/fail speed gate (too noisy on CI). Put performance gates in `sd-bench` or a dedicated `perf.yml` nightly job, not in the every-commit clippy job.

## Release profile (root Cargo.toml)

```toml
[profile.release]
lto = "thin"
codegen-units = 1
opt-level = 3
strip = true
panic = "abort"   # binary only; libraries stay unwind if tests need it
```

Use `panic = "abort"` only on the binary package via `[profile.release.package.skill-doctor]` if tests need unwind.

## Mental model

Cold install < 15 s means: static musl binary on PATH, no `pip`, no model pull, no rule compile, first `scan` of a small skill is dominated by process start + mmap + YARA match. If you add a runtime that downloads models or compiles rules, you have missed the target on purpose.
