---
name: review-bots
description: How to work with CodeRabbit, Greptile, and Intelligence AI on Skill Doctor PRs. Use when a review bot comments or when deciding if a bot finding blocks merge.
---

# Review bots

- **CodeRabbit** — summaries + line comments
- **Greptile** — security-oriented (caught a live Composio credential and fail-on bugs before). Security findings are blocking until disproven.
- **Intelligence AI** — extra pass. Same blocking vs nit rule.

Not CI. Green bot ≠ merge. Red CI ≠ override with a bot emoji.

Fix or refute security/correctness/invariant breaks with a test. Style nits that contradict rustfmt/clippy: clippy wins. Secrets: rotate at vendor, purge git, add gitleaks — do not only delete the line. Do not add a fourth bot. Do not commit bot tokens.
