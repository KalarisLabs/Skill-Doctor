---
name: unsafe-sandbox
description: Rules for unsafe Rust and the L3 microVM sandbox. Use when adding unsafe blocks, FFI, sandbox features, differential replay, or canary credentials.
---

# Unsafe and sandbox

- `unsafe` only in `skill-doctor-sandbox`.
- Every block has `// SAFETY:` naming the invariant.
- Default binary does not enable `sandbox`. Missing L3 → coverage reduction, not a crash.
- Canaries are fake host-injected values, never production secrets.
- Differential replay: vary clock / hostname / CI env; divergence is a finding.
- No Firecracker daemon on the default path.
- Sandbox tests: `#[cfg(feature = "sandbox")]`. Do not fail Windows required CI because L3 is absent.
