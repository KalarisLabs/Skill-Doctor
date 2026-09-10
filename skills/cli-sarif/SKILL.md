---
name: cli-sarif
description: Skill Doctor CLI UX, flags, exit codes, text/JSON/SARIF reports. Use when changing clap, printers, GitHub Action inputs, or CI gate flags.
---

# CLI and reports

Binary: `skill-doctor`. Subcommands: `scan`, `scan-all`, `diff`, `gate`, `version`.
Default output: plain scrolling text. TUI only with feature `tui` **and** `--tui`.

| Exit | Meaning |
|------|---------|
| 0 | clean, or findings below `--fail-on` |
| 1 | usage / internal error |
| 2 | findings ≥ `--fail-on` |
| 3 | coverage < `--fail-under-coverage` |

CI `gate` defaults `--fail-on HIGH`. Interactive `scan` does not fail by default.
`--offline --deterministic` together must not touch the network.
SARIF 2.1.0. Rule IDs = taxonomy IDs. Stable for GitHub code scanning.
