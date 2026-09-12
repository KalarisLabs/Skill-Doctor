<p align="center">
  <img src="public/skill-doctor-banner.webp" alt="Skill Doctor Banner" width="100%" />
</p>

# Skill Doctor

**Deterministic, multi-layer security analysis for AI agent skill files.**
A single statically linked Rust binary. No interpreter, no API key, no network required.
Pre-registered target of sub-150 ms median scans, bit-reproducible verdicts, and host-delegated semantic analysis when
running inside an agent runtime.

> Skill files (`SKILL.md`, `AGENTS.md`, `.clauderules`, `.cursor/rules`, MCP manifests) are
> loaded into agents with full trust but arrive with none of the defenses code accumulated over
> decades. Skill Doctor is the security layer for that infrastructure. See the whitepaper for the
> full threat model (SDTM-v1) and architecture.

---

## Install

```bash
# Run directly via npx (downloads and verifies prebuilt binary on demand):
npx @kalarislabs/skill-doctor scan ./examples/hello-skill

# Or install globally via npm:
npm install -g @kalarislabs/skill-doctor

# Or build and install from local source with cargo:
cargo install --path crates/skill-doctor-cli --locked
```

The npm package is a thin installer that verifies SHA-256 digests against official release checksums and places the prebuilt static binary; there is no Node runtime dependency at scan time. Prebuilt standalone binaries are also downloadable directly from [GitHub Releases](https://github.com/KalarisLabs/Skill-Doctor/releases).

## Quick start (CLI)

```bash
skill-doctor scan ./examples/hello-skill          # scan one bundle, human-readable report
skill-doctor scan-all . --output sarif           # scan a whole tree -> SARIF
skill-doctor diff ./examples/hello-skill --baseline report.json # only newly introduced findings vs baseline report (--baseline takes a saved JSON report path, not a git ref)
skill-doctor watch ./examples/hello-skill         # live feedback while authoring
skill-doctor mcp                                 # run as an MCP server (host-delegated L2)
skill-doctor explain SD-04                       # describe a threat class and its detectors
```

### CI gate

GitHub Action (`@v0.1.0` or pinned SHA):

```yaml
- uses: KalarisLabs/Skill-Doctor@v0.1.0
  with:
    fail-on: HIGH
    fail-under-coverage: 0.8
```

CLI:

```bash
skill-doctor scan-all . \
  --output sarif \
  --fail-on HIGH \
  --fail-under-coverage 0.8 \
  --deterministic \
  --offline
# exit 0 clean & coverage ok | 2 findings >= --fail-on | 3 coverage below threshold
```

## Build from source

Requires Rust 1.93.0+ (MSRV):

```bash
rustup toolchain install stable             # requires Rust 1.93.0+ (MSRV)
git clone https://github.com/KalarisLabs/Skill-Doctor && cd Skill-Doctor
cargo build --release --locked --features mcp # produces target/release/skill-doctor
cargo test --workspace --locked              # unit + corpus tests (excludes real_malware)
cargo run -p skill-doctor --locked --features mcp -- scan ./examples/hello-skill
```

Static musl build (fully static binary):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Repository layout

```
skill-doctor/
├─ Cargo.toml                 # workspace root
├─ rust-toolchain.toml        # pinned toolchain
├─ AGENTS.md                  # how coding agents should work in this repo (build/test/invariants)
├─ CONTEXT.md                 # architecture + threat model context for humans and agents
├─ DEPENDENCIES.md            # every crate/package we use and why
├─ crates/
│  ├─ skill-doctor-cli/       # binary: argument parsing, reporters (text/JSON/SARIF), TUI (opt-in)
│  ├─ skill-doctor-core/      # L0 intake + L1 engines + L5 scoring/coverage (the product)
│  ├─ skill-doctor-rules/     # YARA-X rule packs, compiled at build time and embedded
│  ├─ skill-doctor-neutralize/# SD-11 neutralization protocol (isolated, auditable)
│  ├─ skill-doctor-mcp/       # MCP server + host-delegated L2 envelope/verdict contract
│  └─ skill-doctor-sandbox/   # L3 behavioral process harness + differential replay (feature: sandbox)
├─ rules/                     # source YARA-X rules (compiled into skill-doctor-rules)
├─ corpora/                   # seeded corpus generator + fixtures (real_malware/ is access-gated)
├─ sd-bench/                  # benchmark harness (pinned competitor images, RESULTS.md)
└─ .github/workflows/ci.yml   # build, test, self-scan gate, reproducibility check
```

## Layers (what runs, and what it needs)

| Layer | Function | Requires | Determinism |
|------|----------|----------|-------------|
| L0 | intake, normalize, canonical digest, cache | nothing | deterministic |
| L1 | static analysis (YARA-X, taint, entropy, Unicode, capability differ) | nothing | **deterministic** |
| L2 | semantic analysis | host agent / local model / key | additive-only, nondeterministic |
| L3 | behavioral process harness + differential replay | isolated process execution (`--features sandbox`) | mostly deterministic |
| L4 | threat intelligence | network (opt-in) | deterministic |
| L5 | scoring, coverage, reporting | nothing | deterministic |

**L1 alone is a complete, shippable product.** Every higher layer is elective and degrades to a
lower structural-coverage number instead of an error.

## License

Apache-2.0. The real-malware corpus is access-controlled research material and is **not**
in this repository. See `CONTEXT.md` § Ethics.
