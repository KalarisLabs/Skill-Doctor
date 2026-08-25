---
name: threatdb-engineering
description: Specialist for ThreatDB canonical source files and schema compilation.
---

# ThreatDB Engineering

Use this skill when managing `threat-db/` entries and compilation scripts.

## Architectural Domain
ThreatDB is a Git-backed, YAML-structured canonical source of threat intelligence.

## Best Practices
- **YAML Source of Truth:** All edits to threat signatures must occur in `threat-db/data/threats/*.yaml`.
- **Schema Validation:** Ensure YARA/AST indicators map correctly to the defined schemas.
- **Compilation:** Run the compilation scripts to generate the `threats.json` used by D1 / R2.
