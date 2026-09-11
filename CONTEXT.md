# CONTEXT.md — architecture & threat-model context

Everything an engineer or coding agent needs to understand the system before contributing.
The authoritative narrative is the whitepaper; this file is the engineering-facing distillation.

## 1. Problem in one paragraph

AI agent runtimes load skill files at execution time and grant them the agent's full trust context
(tools, filesystem, credentials, downstream agents). The skill population is heading from tens of
thousands toward an estimated 3–5 million, which guarantees a standing subpopulation of deliberately
weaponized skills. Existing scanners (Cisco AI Defense, NVIDIA SkillSpector) are competent but
unadopted because of three frictions: a Python **runtime dependency**, an LLM **credential
dependency**, and **nondeterministic** verdicts. Skill Doctor removes all three.

## 2. Design theses (the "why")

- **Friction is the primary adversary.** A scanner becomes infrastructure when marginal cost → 0.
- **Deterministic substitution.** Replace model calls with computation wherever possible
  (capability set-diff for SD-04, recursive entropy decode, Unicode skeleton normalization,
  differential replay for logic bombs).
- **The deterministic layer is the product; semantics are additive.**
- **Coverage is reported, not assumed.** Every scan prints how many SDTM-v1 classes were
  structurally evaluable.

## 3. SDTM-v1 threat taxonomy (11 classes)

| ID | Class | Primary detection |
|----|-------|-------------------|
| SD-01 | Prompt Injection (direct/indirect/ASCII-smuggle/encoded) | L1 Unicode + entropy; L2 |
| SD-02 | Command Injection via companion scripts | L1 tree-sitter taint |
| SD-03 | Data Exfiltration (env/secret paths/context dump/covert) | L1; L3 |
| SD-04 | Privilege Escalation / Scope Violation | L1 **capability differ** |
| SD-05 | Supply-Chain Tampering (checksum, bytecode-cache, typosquat) | L1; L4 |
| SD-06 | SSRF via tool parameters | L1; L2 |
| SD-07 | Tool Poisoning (name collision) | L1 cross-skill; L2 |
| SD-08 | Persistent Backdoors (auto-loaded context files) | L1; L3 |
| SD-09 | Context-Window Flooding | L1; L3 |
| SD-10 | Obfuscation & Evasion (homoglyph, deferred payload, logic bomb) | L1; L3 differential replay |
| **SD-11** | **Scanner-Mediated Injection (new)** | `skill-doctor-neutralize` + additive-only invariant |

SD-11 is the class this project introduces: the scanner itself becomes an injection vector when it
feeds untrusted skill content to a model. Mitigated by architecture, not by prompt.

## 4. Layered architecture and crate map

```
input -> [L0 intake/normalize/digest/cache] (skill-doctor-core::l0)
      -> [L1 static engines]                 (skill-doctor-core::l1)  <- rules from skill-doctor-rules
      -> [L2 semantic, host-delegated]        (skill-doctor-mcp)       <- via skill-doctor-neutralize
      -> [L3 behavioral process harness + replay]     (skill-doctor-sandbox, feature-gated)
      -> [L4 threat intel]                    (skill-doctor-core::l4, network opt-in)
      -> [L5 scoring/coverage/report]         (skill-doctor-core::l5 -> skill-doctor-cli::report)
```

### L0 — intake
Accepts dir / ZIP / tar.gz / single .md / Git URL / HTTP archive / stdin. Produces a normalized
flat bundle + a **SHA-256 canonical bundle digest** over sorted (path, content) pairs. Four-tier
cache: in-process Bloom filter → embedded KV store (digest→findings) → rule-generation fencing
(cache key includes ruleset hash + binary version) → optional remote intel on local miss.

### L1 — deterministic core (five engines, run concurrently via rayon)
1. **Pattern (YARA-X)** — embedded build-time compiled rule packs (`rules/*.yar`). Covers pattern-based indicators across:
   - SD-01 (Prompt Injection direct & override patterns)
   - SD-02 (Command Injection shell/process execution patterns)
   - SD-03 (Data Exfiltration credential & secret path patterns)
   - SD-05 (Supply-Chain Tampering hook & dependency patterns)
   - SD-06 (SSRF cloud metadata & internal loopback patterns)
   - SD-07 (Tool Poisoning command collision patterns)
   - SD-08 (Persistent Backdoors startup & autorun patterns)
   - SD-09 (Context-Window Flooding repetition patterns)
   - SD-10 (Obfuscation & Evasion known signature patterns)
   - SD-11 (Scanner-Mediated Injection override patterns)
2. **Taint (`taint.rs` / tree-sitter)** — companion script AST parsing & source→sink propagation (SD-02).
3. **Entropy (`entropy.rs`)** — native Rust Shannon entropy per block; high-entropy secret detection, base64/hex decode + **recursive rescan** (SD-03, SD-10).
4. **Unicode (`unicode.rs`)** — native Rust zero-width/bidi Trojan Source detection; UTS #39 confusables/mixed-script skeleton normalization (SD-10, SD-01).
5. **Capability differ (`capability.rs`)** — native Rust declared (frontmatter/manifest) vs observed (AST operations + permissions) set diff. Novel deterministic engine for SD-04 (Privilege Escalation / Scope Violation) with zero model calls.

### L2 — host-delegated semantic inference
Under MCP, the scanner performs **no inference**. It emits static findings + a neutralized envelope;
the host agent's own model returns a schema-constrained verdict. Modes: `none` (default CLI),
`host` (default MCP), `local` (Ollama/socket), `remote` (explicit key). Always additive-only.

### L3 — behavioral sandbox (feature `sandbox`)
Process harness with environment isolation, mock agent runtime snapshot, hard execution ceiling, host-injected
**canary credentials**. **Differential replay**: run under varied clock/hostname/CI-env/canary
conditions; behavioral divergence = conditional payload / logic bomb.

### L4/L5 — intel, scoring, coverage
L4: digest + sanitized summaries only, opt-in, local findings outrank remote. L5: merge/dedupe;
cross-layer corroboration raises confidence rather than duplicating; bounded risk score; computes
**structural coverage** (classes evaluable / 11) and exposes it as a CI threshold.

## 5. Data contracts
- **Finding**: `{ rule_id, class (SD-0x), severity, confidence, path, byte_span, evidence[], remediation }`.
- **Report**: `{ bundle_digest, findings[], coverage: {evaluable, total: 11, per_class}, verdict, deterministic: bool }`.
- **MCP `skill_doctor_scan`**: input `{ path|content, mode, fail_on }`; output = Report + neutralized
  envelope; verdict must echo the per-scan nonce or is discarded.
- SARIF 2.1.0 for CI; stable `rule_id`s map 1:1 to SARIF `ruleId`.

## 6. Build order for a first working product (MVP path)
1. `skill-doctor-core` L0 + Finding/Report types + `taxonomy.rs`.
2. `skill-doctor-rules` with a build.rs that compiles a starter YARA-X pack.
3. L1 engines in order: pattern → unicode → entropy → taint → capability differ.
4. `skill-doctor-cli`: `scan`, text + json + sarif reporters, `--deterministic`, exit codes.
5. L5 scoring + coverage; `scan-all`, `diff --baseline`, `watch`.
6. `skill-doctor-neutralize` + `skill-doctor-mcp` (`serve --mcp`, host-delegated L2).
7. `skill-doctor-sandbox` (feature-gated) + differential replay.
8. L4 intel (opt-in) + provenance (sigstore) + SBOM in CI.

## 7. Ethics / handling rules
Real malicious samples are access-gated, provenance-documented, excluded from default tests and
fork CI, executed only in the sandbox. Never persist secret values. Canary credentials are
host-generated and worthless outside the experiment. The project publishes its own supply chain
(reproducible builds, Sigstore attestation, SBOM, advisory scanning).
