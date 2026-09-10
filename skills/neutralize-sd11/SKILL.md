---
name: neutralize-sd11
description: SD-11 scanner-mediated injection — neutralize untrusted skill bytes before any model; additive-only scoring. Use when touching L2, MCP, prompts, envelopes, or scoring merge.
---

# SD-11

If the scanner forwards skill text to a model, the scanner is the injection surface.

1. Strip bidi / zero-width / tag chars; record removals as findings.
2. NFKC + UTS #39 skeleton; homoglyphs are findings, not silent folds.
3. Remaining text goes in a fenced untrusted envelope. No raw skill in the model prompt.
4. Host returns schema-constrained JSON only.
5. Merge: L2 may add or raise. L2 may not delete or downgrade L1.
6. If neutralize fails: do not call the model; reduce L2 coverage.

No vendor LLM SDK on the default CLI path. Product L2 is MCP `mode=host`.
