# Whitepaper Reconciliation Report (Skill Doctor v0.1.0)

This document provides a factual, line-by-line reconciliation between the architectural assertions in the Skill Doctor academic whitepaper and the actual implementation in the repository as of `v0.1.0` (commit `6a17e68`).

Every finding reports **FACT** (what the code does, with file and line citations) and proposes an **exact replacement sentence** for the paper. Findings are presented without softening.

---

## D1. License

- **Paper claim**: Asserts the project is licensed under AGPL v3 in four places.
- **Fact**: 
  The repository is licensed exclusively under the **Apache License 2.0 (Apache-2.0)**:
  - Workspace root [Cargo.toml:16](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/Cargo.toml#L16) (`license = "Apache-2.0"`)
  - [LICENSE:1-201](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/LICENSE#L1-L201) (Apache License 2.0 text)
  - [package.json:5](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/package.json#L5) (`"license": "Apache-2.0"`)
  - [package-lock.json:15](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/package-lock.json#L15) (`"license": "Apache-2.0"`)
- **Contributor-clean assessment**:
  Inspection of the full git history (`git log --format='%an <%ae>' | sort -u`) confirms all code commits originated solely from Sayan Chowdhury (`sayan@kalarislabs.com` / `sayanshytech.20@gmail.com`) alongside Dependabot bot configuration updates. Zero outside third-party human contributions exist. The relicensing from AGPL-3.0 to Apache-2.0 was 100% contributor-clean.
- **Proposed replacement sentence**:
  > *"Skill Doctor is released under the permissive Apache License 2.0 (Apache-2.0)."*

---

## D2. Taint Engine

- **Paper claim**: Asserts companion scripts are parsed and taint is propagated using `tree-sitter`.
- **Fact**:
  `tree-sitter` is **not present** in `Cargo.lock` or `Cargo.toml`. 
  The taint engine in [crates/skill-doctor-core/src/l1.rs:543-587](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-core/src/l1.rs#L543-L587) (`run_taint_engine`) is **not AST-based**. It implements a lexical string-containment heuristic:
  1. Inspects companion files matching extension `.sh`, `.bash`, `.py`, `.js`, or `.ts`.
  2. Checks whether lowercased file content contains command argument sources (`$1`, `$@`, `sys.argv`, `process.argv`).
  3. Checks whether lowercased file content concurrently contains execution sinks (`eval`, `exec`, `system`).
- **Proposed replacement sentence**:
  > *"The L1 taint engine evaluates companion shell and scripting files using lightweight lexical source-to-sink pattern heuristics, flagging flows from script arguments (`$1`, `sys.argv`, `process.argv`) into command execution sinks (`eval`, `exec`, `system`) without requiring external AST parser runtimes."*

---

## D3. L0 Intake & Cache Tiers

- **Paper claim**: Claims a four-tier cache (in-process Bloom filter, embedded key-value store, rule-generation fencing, remote), achieving warm re-scans under 20 ms.
- **Fact**:
  **None of the four cache tiers exist in the codebase**:
  - No Bloom filter library (`fastbloom`, `bloomfilter`) exists in `Cargo.lock`.
  - No embedded key-value store crate (`sled`, `redb`) is active. `redb = "2"` is commented out in [Cargo.toml:79](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/Cargo.toml#L79).
  - L0 intake in [crates/skill-doctor-core/src/l0.rs:56-110](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-core/src/l0.rs#L56-L110) performs directory or archive traversal and computes a SHA-256 canonical bundle digest from scratch on every run.
  - The "warm re-scan under 20 ms" tier does not exist.
- **Proposed replacement sentence**:
  > *"L0 intake computes a canonical SHA-256 digest over normalized, sorted bundle entries on each scan; tiered in-process Bloom filtering and embedded key-value caching are planned for post-v0.1.0 releases."*

---

## D4. L3 Behavioral Sandbox

- **Paper claim**: Asserts microVM isolation with ~100 ms boot time and a native Rust hypervisor SDK.
- **Fact**:
  The L3 sandbox in [crates/skill-doctor-sandbox/src/lib.rs:1-100](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-sandbox/src/lib.rs#L1-L100) is **not a microVM** and does not use any hypervisor SDK (such as Firecracker or Cloud Hypervisor).
  It is a **host-level process execution harness**:
  - Spawns subprocesses via `std::process::Command` in a temporary directory (`mock_home`) with an isolated environment table ([runner.rs:1-60](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-sandbox/src/runner.rs#L1-L60)).
  - Host identity, cloud credentials, and CI variables are stripped ("HOME is a lie" policy).
  - Plants synthetic canary credentials in mock files ([canary.rs:1-80](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-sandbox/src/canary.rs#L1-L80)).
  - Terminates process trees on timeout (default 3,000 ms) via Windows Job Objects (`AssignProcessToJobObject`) or Unix process groups (`libc::killpg`).
  - **Differential replay** ([replay.rs:1-70](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-sandbox/src/replay.rs#L1-L70)) is implemented as sequential execution of companion scripts across up to 4 environment profiles (`Baseline`, `CI/Automation`, `TargetCloud`, `TimeShifted`), comparing exit codes and output to detect environment-triggered logic bombs.
- **Proposed replacement sentence**:
  > *"The elective L3 behavioral sandbox executes companion scripts in a hardened subprocess harness with environment variable isolation, synthetic canary credential planting, and differential replay across execution profiles (Baseline, CI, Cloud) with process tree containment enforced by OS job objects and process groups."*

---

## D5. L4 Threat Intelligence

- **Paper claim**: Claims shared community threat intelligence.
- **Fact**:
  - In [crates/skill-doctor-core/src/l4.rs:19](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-core/src/l4.rs#L19), `DEFAULT_INTEL_ENDPOINT = "https://intel.skilldoctor.io"`.
  - Under `#[cfg(feature = "intel")]` ([l4.rs:195-239](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-core/src/l4.rs#L195-L239)), `query_remote_intel` sends `GET /v1/digest/{sha256}` via `reqwest` with a 2,000 ms timeout.
  - The local database is a hardcoded static slice of exactly 3 test fixtures ([l4.rs:131-170](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-core/src/l4.rs#L131-L170), `LOCAL_KNOWN_MALICIOUS_FEED`).
  - No public or shared threat intelligence database is published, hosted, or active. `https://intel.skilldoctor.io` is an unpopulated placeholder endpoint.
- **Proposed replacement sentence**:
  > *"The opt-in L4 engine queries community threat intelligence by checking a 64-character SHA-256 bundle digest over HTTPS against an allowlisted feed endpoint, falling back to an embedded compile-time set of known malicious signatures."*

---

## D6. Evaluation Corpora

- **Paper claim**: Section 7.1 asserts evaluation over:
  - 1,000 public skills
  - 55 attack skills
  - 20 evasion skills
  - 15 adversarial-scanner skills
  - 100 hard negatives
  - ≥50 real-malware samples
- **Fact**:
  Inspection of the repository filesystem shows the actual fixture counts are:
  - `tests/fixtures/attack/`: **6 attack skills** ([tests/fixtures/attack](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/tests/fixtures/attack)):
    - `SD-01/encoded-injection`
    - `SD-02/malicious-skill`
    - `SD-03/canary-exfil`
    - `SD-04/undeclared-capability`
    - `SD-10/logic-bomb`
    - `SD-10/unicode-trojan`
  - `tests/fixtures/benign/`: **3 benign skills** ([tests/fixtures/benign](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/tests/fixtures/benign)):
    - `complex-declared-skill`
    - `hello-skill`
    - `script-skill`
  - `sd-bench/corpora/`: **4 benchmark skills** ([sd-bench/corpora](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/sd-bench/corpora)):
    - `clean-calculator-skill`
    - `clean-formatter-skill`
    - `cmd-inject-skill`
    - `prompt-inject-skill`
  - `examples/`: **1 skill** (`hello-skill`).
  - **Public corpus**: **0** in repository (no vendored public dataset).
  - **Adversarial-scanner corpus**: **0** directory fixtures (covered by unit tests in `crates/skill-doctor-neutralize/tests/`).
  - **Real-malware corpus**: **0** in repository. As stated in [SECURITY.md:27](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/SECURITY.md#L27), live malware is strictly prohibited from the repository.
- **Proposed replacement sentence**:
  > *"The v0.1.0 test and benchmark suite includes 14 curated skill fixtures: 6 attack fixtures covering threat classes SD-01, SD-02, SD-03, SD-04, and SD-10; 3 benign fixtures; 4 benchmark skills; and 1 example skill. No evaluation against external public repositories has been conducted."*

---

## D7. Subcommands & CLI Syntax

- **Paper claim**: Section 6.2 illustrates `npx ... init`, `cargo install skill-doctor`, `brew install kalarislabs/tap/skill-doctor`, and `skill-doctor diff --baseline main`.
- **Fact**:
  1. `init`: **Does not exist**. The CLI subcommands in [crates/skill-doctor-cli/src/main.rs:64-150](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-cli/src/main.rs#L64-L150) are `Scan`, `ScanAll`, `Diff`, `Watch`, `Mcp`, and `Explain`.
  2. `cargo install skill-doctor`: Valid once published to crates.io; locally requires `cargo install --path crates/skill-doctor-cli --locked --features mcp`.
  3. `brew install kalarislabs/tap/skill-doctor`: **Does not exist**. No Homebrew tap repository or formula exists.
  4. `skill-doctor diff --baseline main`: `--baseline` takes a `PathBuf` pointing to a **saved JSON report file** ([main.rs:145](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-cli/src/main.rs#L145)), **not a git reference**. Passing a git branch name fails with `PathNotFound`.
- **Proposed replacement code block**:
  ```bash
  # Run directly via npx (downloads and verifies prebuilt binary):
  npx @kalarislabsai/skill-doctor scan ./examples/hello-skill

  # Or install from source:
  cargo install --path crates/skill-doctor-cli --locked --features mcp

  # Scan a single skill:
  skill-doctor scan ./examples/hello-skill

  # Scan an entire directory tree and output SARIF:
  skill-doctor scan-all . --output sarif

  # Differential scan against a saved baseline JSON report:
  skill-doctor scan ./examples/hello-skill --output json > report.json
  skill-doctor diff ./examples/hello-skill --baseline report.json
  ```

---

## D8. MCP Analysis Mode Argument

- **Paper claim**: Uses both `"host"` and `"host-delegated"` interchangeably as argument values to `mode`.
- **Fact**:
  In [crates/skill-doctor-mcp/src/lib.rs:113-114](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-mcp/src/lib.rs#L113-L114) and [lines 239-242](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/crates/skill-doctor-mcp/src/lib.rs#L239-L242):
  - `ScanParams.mode` accepts `"host"` (default) for host-delegated L2 semantic evaluation.
  - The code explicitly checks: `if mode != "host" { /* static-only */ }`.
  - Passing `"host-delegated"` is **not recognized as activating host mode**; it evaluates to `true` in `mode != "host"`, causing the MCP server to skip the neutralized envelope and downgrade the scan to static-only mode.
- **Proposed replacement sentence**:
  > *"The MCP `skill_doctor_scan` tool accepts the `mode` parameter with valid values `'host'` (default, enabling host-delegated L2 semantic evaluation with neutralized fenced envelopes) or `'none'` (for deterministic static-only analysis)."*

---

## D9. Section 8.5 Infrastructure Claims

- **Paper claim**: Asserts an "author key registry", build reproducibility, and registry publish webhook contracts.
- **Fact**:
  - **Author key registry**: Does not exist in the codebase.
  - **Build reproducibility**: Is **not tested anywhere in CI**. The `determinism` job in [.github/workflows/ci.yml:351-365](file:///c:/Users/KalarisLabs/Desktop/SKILL%20DOCTOR/skill-doctor-repo/.github/workflows/ci.yml#L351-L365) validates **verdict reproducibility** (ensuring `--deterministic` emits identical JSON reports across repeated scans), not compiler or bit-for-bit binary build reproducibility.
  - **Registry publish webhook contract**: Neither implemented nor documented in the repository.
- **Proposed replacement sentence**:
  > *"Skill Doctor guarantees verdict reproducibility across runs in deterministic mode; bit-for-bit binary build reproducibility, author key registries, and automated registry publish webhooks are reserved for future releases."*

---

## D10. Binary Footprint & Cranelift Contribution

- **Paper claim**: Asserts a ~12 MB standalone binary footprint.
- **Fact**:
  CI benchmark measurements from `.github/workflows/bench.yml` run [34698953208](https://github.com/KalarisLabs/Skill-Doctor/actions/runs/34698953208) (Job `103567203315`):
  - **Binary footprint (stripped, --features mcp): 16934512 bytes (16.15 MiB, x86_64-unknown-linux-musl)**
  - **Stripped Linux host binary**: **16821056 bytes** (`16.04 MiB`, `x86_64-unknown-linux-gnu`)
  - **Windows PE release binary** (`target/release/skill-doctor.exe` with `--features mcp`): **17936896 bytes** (`17.11 MiB`, `x86_64-pc-windows-msvc, not CI-verified`)
  - **Peak RSS**: **15.10 MiB** (`15,456` KB, well within the < 40 MiB ceiling)
  - **Scan Latency**: **0.06 s** wall-clock time
- **Cranelift / Wasmtime Subsystem Analysis**:
  Running `cargo tree -i wasmtime --target x86_64-unknown-linux-musl` confirms:
  ```
  wasmtime v45.0.3
  └── yara-x v1.20.0
      [build-dependencies]
      └── skill-doctor-rules v0.1.0
  ```
  `yara-x` compiles YARA rules into WebAssembly bytecode and runs them via embedded Wasmtime, pulling in `cranelift-codegen v0.132.3`, `cranelift-frontend`, and the entire Cranelift JIT/AOT compiler backend. This single subsystem contributes ~14 MiB of the compiled binary footprint.
- **Recommendations for the ~12 MB Target**:
  - **Option A (Recommended)**: Restate the whitepaper target from "~12 MB" to the empirically measured value of **~16–18 MiB** across platforms, retaining a hard **20 MiB ceiling**.
  - **Option B (Feature Gate)**: Would require making `yara-x` an opt-in Cargo feature; the resulting footprint has not been measured.
- **Proposed replacement sentence**:
  > *"The standalone release binary with embedded YARA-X compiles to 16,934,512 bytes (16.15 MiB, x86_64-unknown-linux-musl) and 17,936,896 bytes (17.11 MiB, x86_64-pc-windows-msvc, not CI-verified), strictly within an upper ceiling of 20 MiB. This footprint is dominated (~14 MiB) by YARA-X's embedded Wasmtime/Cranelift compiler backend."*
