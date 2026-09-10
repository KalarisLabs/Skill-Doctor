---
name: project-context
description: Skill Doctor product and architecture context. Use at the start of a session, when deciding where code lives, when the user asks how the scanner works, or before any non-trivial change.
---

# Project context

Read `AGENTS.md` then `CONTEXT.md` if they exist. This skill is the short form.

## Product

Skill Doctor is a **Rust CLI** that scans AI agent skill files. The shippable core is **deterministic L1**. L2 (host-delegated semantics), L3 (sandbox), and L4 (intel) are optional and must degrade to **reduced coverage**, never a crash or a dropped L1 finding.

Repo: `KalarisLabs/Skill-Doctor`. Do not create a new GitHub repository.

## Pipeline

```
input → L0 intake/digest/cache
     → L1 static engines          THE PRODUCT
     → L2 host-delegated MCP      optional, additive-only
     → L3 process harness + replay        feature sandbox
     → L4 threat intel            network opt-in
     → L5 score / coverage / report
```

Default CLI: L0+L1+L5 with `--offline --deterministic`.

## Crate map

| Crate | Owns |
|-------|------|
| `skill-doctor` | clap, printers, exit codes |
| `skill-doctor-core` | L0/L1/L4/L5, taxonomy, scoring |
| `skill-doctor-rules` | `build.rs` compiles `rules/` |
| `skill-doctor-neutralize` | SD-11 envelope, no I/O |
| `skill-doctor-mcp` | host-delegated MCP |
| `skill-doctor-sandbox` | L3, only crate that may use `unsafe` |

## SDTM-v1 — do not renumber

SD-01 prompt injection · SD-02 command injection · SD-03 exfil · SD-04 scope (capability differ, no model) · SD-05 supply chain · SD-06 SSRF · SD-07 tool poisoning · SD-08 backdoors · SD-09 flooding · SD-10 obfuscation · SD-11 scanner-mediated injection.

## Exit codes (stable)

`0` clean · `1` usage/internal · `2` findings ≥ `--fail-on` · `3` coverage under threshold.

## Build order if the tree is still a stub

1. CLI `--help` / `version` / `scan` stub  
2. L0 digest  
3. rules crate + one YARA rule per class  
4. L1 engines  
5. L5 reports + exit codes  
6. additive-only scorer + neutralize  
7. fixtures + determinism test  
8. MCP  
9. CI matching `TESTING.md`  
10. release last

Load `rust-invariants` before changing defaults. Load `ci-cd` before touching workflows. Load `rust-perf` before optimizing.
