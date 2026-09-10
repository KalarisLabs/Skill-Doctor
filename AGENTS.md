# AGENTS.md — working agreement for coding agents in this repository

This file governs any AI coding agent (Claude Code, Cursor, Codex CLI, Gemini CLI, etc.) operating
in this repo. Read `CONTEXT.md` before writing code. Read `DEPENDENCIES.md` before adding a crate.

## What this project is

Skill Doctor is a **Rust** security scanner for AI agent skill files. The product is a single
statically linked binary whose **deterministic L1 layer is the shippable core**. Everything else is
elective and must degrade to reduced coverage, never to an error.

## Skills — load before acting

Each folder under `skills/` is an Agent Skill (`SKILL.md`). Load the matching one instead of improvising. If two apply, load both.

| Skill | Load when |
|-------|-----------|
| `skills/project-context` | start of a session, architecture, where code lives |
| `skills/rust-workspace` | crates, Cargo.toml, deps |
| `skills/rust-invariants` | defaults, scoring, LLM/MCP, features |
| `skills/rust-idioms` | everyday Rust: errors, ownership, clippy |
| `skills/rust-perf` | speed, RSS, binary size, rayon/mmap, §7.3 targets |
| `skills/rust-testing` | tests, fixtures, determinism |
| `skills/ci-cd` | GitHub Actions, required checks, TestMu, OS matrix |
| `skills/yara-rules` | detectors, YARA-X, SDTM IDs |
| `skills/neutralize-sd11` | L2, MCP, envelopes |
| `skills/cli-sarif` | clap, exit codes, SARIF |
| `skills/release-publish` | crates.io, npm, tags |
| `skills/review-bots` | CodeRabbit / Greptile / Intelligence AI |
| `skills/unsafe-sandbox` | `unsafe`, L3 process harness |

## Non-negotiable invariants (do not violate; PRs that break these are rejected)

1. **Rust only.** No Python, no Node, no shell interpreter in the product runtime. (npm is only a
   binary installer; Node is never required to scan.)
2. **No mandatory LLM.** L1 must run with zero network, zero key, zero account. Semantic analysis
   (L2) is *host-delegated* and optional.
3. **Additive-only invariant.** A probabilistic/L2 verdict may add findings or raise confidence.
   It may **never** remove, downgrade, or suppress a deterministic L1 finding. This is enforced in
   `skill-doctor-core::scoring` and covered by a dedicated test; do not weaken it.
4. **Determinism.** In `--deterministic` mode, output is byte-identical across runs: pin timestamps,
   directory walk order, and iteration order over unordered collections (sort before serialize).
5. **Rules compiled at build time.** YARA-X rules are compiled once in `skill-doctor-rules`'
   `build.rs` and embedded in the binary. Never compile rules per invocation.
6. **SD-11 safety.** Any content sent to any model MUST pass through `skill-doctor-neutralize`
   first. No code path may hand raw skill content to an LLM.
7. **Secrets.** Never store secret *values* — only environment key *names* — in findings, reports,
   or logs.
8. **CLI-first.** Plain scrolling text is the default output. The TUI is behind the `tui` feature
   and is never the default.
9. **Exactly the four contributions** described in the whitepaper. Do not invent scope.

## Build / test / lint commands

```bash
cargo build --release                     # build the binary
cargo test --workspace                    # all tests except access-gated real_malware
cargo clippy --workspace -- -D warnings    # lint gate (must be clean)
cargo fmt --all --check                    # formatting gate
cargo run -p skill-doctor-cli -- scan ./examples/hello-skill
cargo build --release --features sandbox   # include L3 behavioral process harness
./sd-bench/run.sh --pinned                  # reproduce the benchmark against pinned competitors
```

Before opening a PR, all of the following must pass: `cargo fmt --check`, `cargo clippy -D
warnings`, `cargo test --workspace`, and **the binary must pass its own scan** (`skill-doctor
scan-all . --fail-on HIGH`).

## Where things live

- New detector? Add the engine in `skill-doctor-core/src/l1/`, a YARA-X rule in `rules/`, and a
  fixture in `corpora/`. Register the SDTM-v1 class in `skill-doctor-core/src/taxonomy.rs`.
- New threat class (SD-12+)? Update `taxonomy.rs`, `rules/`, Appendix A mapping, and add fixtures.
- MCP tool/schema change? `skill-doctor-mcp/src/` — keep the `skill_doctor_scan` tool schema stable.
- Output format change? `skill-doctor-cli/src/report/` (text, json, sarif). Rule IDs are stable and
  human-assigned; never renumber existing IDs (baselines and suppression lists depend on them).

## Conventions

- Errors: `thiserror` in libraries, `anyhow` only at the CLI boundary.
- Concurrency: `rayon` for the file/engine fan-out; `tokio` only inside `skill-doctor-mcp` and the
  optional network layer.
- No `unsafe` outside `skill-doctor-sandbox`; if unavoidable elsewhere, justify it in a
  `// SAFETY:` comment and gate it behind review.
- Every new capability that can be absent must report reduced **structural coverage**, not fail.

## Commit / PR expectations

- Conventional Commits (`feat:`, `fix:`, `perf:`, `docs:`, `test:`, `bench:`).
- Every detector PR ships with: a rule, a positive fixture, a hard-negative fixture, and a test.
- Update `sd-bench/RESULTS.md` only via the harness; never hand-edit measured numbers.
