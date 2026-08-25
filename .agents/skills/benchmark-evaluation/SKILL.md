---
name: benchmark-evaluation
description: Specialist for SD-B-001/SD-B-002 evaluation datasets.
---

# Benchmark Evaluation

Use this skill when managing benchmarks (`web/src/pages/benchmarks.astro`, `tests/`).

## Architectural Domain
Skill Doctor maintains independent datasets to test engine efficacy against overfitting.

## Best Practices
- **Separation of Concerns:** Never mix ThreatDB signatures directly with Benchmark datasets.
- **Coverage:** Ensure benchmarks cover both Static (SD-B-001) and Semantic (SD-B-002) evasion techniques.
