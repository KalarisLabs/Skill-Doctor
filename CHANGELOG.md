# Changelog

All notable changes to Skill Doctor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-10

### Added
- Initial release of Skill Doctor (v0.1.0)
- L0 intake layer with directory, ZIP, tar.gz, and single file support
- L1 deterministic static analysis engines:
  - Pattern engine with regex-based detection for SD-01 through SD-11
  - Unicode engine for zero-width, bidi, and confusable detection
  - Entropy engine with Shannon entropy and recursive decode
  - Taint engine for companion script dataflow analysis
  - Capability differ for SD-04 privilege escalation detection
- L5 scoring, coverage computation, and report generation
- CLI with scan, scan-all, diff, watch, and gate commands
- Text, JSON, and SARIF 2.1.0 output formats
- Deterministic mode for byte-identical reproducible results
- Offline mode for zero-network operation
- Structural coverage reporting (evaluable classes / 11 SDTM-v1 total)
- Exit codes: 0 (clean), 1 (error), 2 (findings), 3 (coverage below threshold)
- skill-doctor-neutralize crate for SD-11 scanner-mediated injection protection
- skill-doctor-mcp crate for Model Context Protocol server (host-delegated L2)
- skill-doctor-sandbox crate for L3 behavioral process harness (feature-gated)
- skill-doctor-rules crate for YARA-X rule compilation (build-time embedded)
- CI gates: check-gate, msrv-check, lint-and-unit, supply-chain, determinism, os-cli (Ubuntu/macOS/Windows), dogfood-self-scan, docs-smoke, packaging-gate
- License: Apache-2.0

### Security
- SD-11 protection: all content reaching models passes through skill-doctor-neutralize
- Additive-only invariant: L2/L3/L4 cannot remove, downgrade, or reclassify L1 findings
- Secret protection: only key names (not values) appear in findings, reports, and logs
- Canary credential system in L3 sandbox for behavioral leak detection
- Process tree isolation in L3 sandbox via Windows Job Objects and Unix process groups

### Performance
- Pre-registered targets:
  - Throughput: ≥ 2,000 skills/min (offline L1, warm cache off)
  - Peak RSS: < 40 MB
  - Binary footprint: < 20 MB ceiling
  - Cold install → first result: < 15 s
- Empirical measurements (v0.1.0):
  - Peak RSS: 14.66 MB (15,020 KB) (local measurement, x86_64-pc-windows-msvc, not CI-verified)
  - Throughput: 660 skills/s (~39,600 skills/min) (local measurement, x86_64-pc-windows-msvc, not CI-verified)
  - Binary footprint (stripped with MCP): 16.2 MB (Linux musl), 17.9 MB (Windows PE)

### Documentation
- AGENTS.md: working agreement for coding agents
- CONTEXT.md: architecture and threat model context
- DEPENDENCIES.md: every package we use and why
- TESTING.md: test strategy, CI gates, and branch protection
- SECURITY.md: private vulnerability reporting path
- CONTRIBUTING.md: contribution guidelines and four-item detector PR requirement

[0.1.0]: https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.1.0
