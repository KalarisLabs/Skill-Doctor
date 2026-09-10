---
name: yara-rules
description: Author and compile YARA-X rules for SDTM-v1. Use when adding or changing detectors, rules/*.yar, rule IDs, or taxonomy mappings.
---

# YARA-X rules

- One file per class under `rules/core/sdXX_*.yar`. Extra packs: supply-chain, obfuscation, MCP.
- IDs are stable and human-assigned. Never renumber. Baselines and suppressions depend on this.
- `skill-doctor-rules/build.rs` compiles the tree **once**. Scan path only matches.
- Every rule `meta`: `class`, `severity`, `description`.
- SD-02 companion-script taint is **tree-sitter**, not a regex for `eval(`.
- SD-04 is capability-set differ, not YARA. Do not fake it with a pattern.
- New class SD-12+ is a whitepaper change. Do not add it in a drive-by PR.
- Detector PR: rule + positive fixture + hard-negative + test.
