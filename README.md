<p align="center">
  <img src="public/skill-doctor-banner.webp" alt="Skill Doctor Banner" width="100%" />
</p>

# Skill Doctor

Deterministic security analysis for AI agent skill files.

[![CI](https://github.com/KalarisLabs/Skill-Doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/KalarisLabs/Skill-Doctor/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/skill-doctor.svg)](https://crates.io/crates/skill-doctor)
[![npm](https://img.shields.io/npm/v/%40security.kalarislabs%2Fskill-doctor)](https://www.npmjs.com/package/@security.kalarislabs/skill-doctor)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93.0-blue.svg)](Cargo.toml)

---

## Why this exists

AI agent skill files (`SKILL.md`, prompt instructions, `.clauderules`, `.cursor/rules`, MCP configurations) are executable-by-prompt instructions consumed directly by agent runtimes. Because skills run with full prompt execution context and tool access, installing them from untrusted registries exposes agents to prompt injection, companion script command execution, and credential exfiltration. Traditional static analysis tools inspect source code, but agent skill files lack static security verification. Skill Doctor provides deterministic, multi-layer static security analysis to inspect skill bundles before they reach an agent runtime.

---

## Quickstart

Run a scan against the example skill bundle (`./examples/hello-skill`):

### Option 1: npx (zero installation)
```bash
npx @security.kalarislabs/skill-doctor scan ./examples/hello-skill
# Expected exit code: 0 (clean)
```

### Option 2: npm global install
```bash
npm install -g @security.kalarislabs/skill-doctor
skill-doctor scan ./examples/hello-skill
# Expected exit code: 0 (clean)
```

### Option 3: cargo install (crates.io)
```bash
cargo install skill-doctor --locked --features mcp
skill-doctor scan ./examples/hello-skill
# Expected exit code: 0 (clean)
```

The npm package is a thin installer that downloads and verifies the official prebuilt standalone binary; there is no Node.js runtime dependency during scanning. Prebuilt standalone binaries are also published directly on [GitHub Releases](https://github.com/KalarisLabs/Skill-Doctor/releases).

### Build from source

Requires Rust 1.93.0+ (MSRV):

```bash
git clone https://github.com/KalarisLabs/Skill-Doctor && cd Skill-Doctor
cargo install --path crates/skill-doctor-cli --locked --features mcp
skill-doctor scan ./examples/hello-skill
```

---

## What it detects

Skill Doctor evaluates skill files and companion scripts against the 11 threat classes of the Skill Doctor Threat Model (SDTM-v1):

| ID | Threat Class | Description | Detection Layer |
|---|---|---|---|
| **SD-01** | Prompt Injection | Direct, indirect, ASCII smuggling, and encoded prompt injections | L1 Unicode & Shannon Entropy; L2 Semantic Inference |
| **SD-02** | Command Injection | Unsanitized execution in companion scripts (`eval`, `exec`, `system`) | L1 Lexical Source-to-Sink Taint; L3 Process Sandbox |
| **SD-03** | Data Exfiltration | Covert extraction of environment variables and sensitive file paths | L1 Secret Patterns; L3 Canary Leak Detection |
| **SD-04** | Privilege Escalation | Undeclared capabilities exceeding frontmatter permission declarations | L1 Capability Differ (declared vs observed operations) |
| **SD-05** | Supply-Chain Tampering | Checksum mismatches, bytecode cache pollution, typosquatting | L1 Package Hook Patterns; L4 Threat Intelligence |
| **SD-06** | SSRF | Outbound requests to cloud metadata services or internal networks | L1 Metadata & Loopback Address Patterns; L2 |
| **SD-07** | Tool Poisoning | Cross-skill tool name shadowing and parameter collisions | L1 Cross-Skill Namespace Collision Checks; L2 |
| **SD-08** | Persistent Backdoor | Auto-loaded context hooks (.clauderules, startup persistence) | L1 Context File Rule Patterns; L3 Sandbox |
| **SD-09** | Context-Window Flooding | Instruction washing and denial-of-service token floods | L1 Token Count & Repetition Detection; L3 |
| **SD-10** | Obfuscation & Evasion | UTS #39 confusables, bidi Trojan Source, deferred logic bombs | L1 Unicode Engine; L3 Differential Replay |
| **SD-11** | Scanner-Mediated Injection | Attacks attempting to exploit or hijack the host scanner/agent | skill-doctor-neutralize Fencing + Additive Invariant |

> [!NOTE]
> **Fixture coverage status**: Today, 14 curated fixtures exist in the repository test suite (6 attack fixtures across SD-01, SD-02, SD-03, SD-04, and SD-10; 3 benign fixtures; 4 benchmark fixtures; and 1 example fixture). The remaining threat classes (SD-05, SD-06, SD-07, SD-08, SD-09, and SD-11) are currently rule-only. We do not claim full fixture or empirical evaluation coverage across all 11 classes.

---

## Exit codes

The CLI emits standardized exit codes defined in `crates/skill-doctor-cli/src/main.rs`:

- `0` — clean (no findings at or above `--fail-on` threshold)
- `1` — usage error or internal error
- `2` — findings at or above `--fail-on` threshold
- `3` — structural coverage below `--fail-under-coverage` threshold

> [!IMPORTANT]
> **Notice for CI pipeline authors**: Exit code `1` denotes an invocation error or internal scanner failure. It does **NOT** denote detected findings. Security findings at or above `--fail-on` are signaled strictly via exit code `2`.

---

## Use it in CI

### GitHub Action

Use the official composite action to scan repositories and upload SARIF results to GitHub Code Scanning:

```yaml
- name: Run Skill Doctor
  id: scan
  uses: KalarisLabs/Skill-Doctor@v0.1.0
  with:
    path: .
    mode: scan-all
    fail-on: HIGH
    fail-under-coverage: 0.8
    output: sarif
    sarif-file: skill-doctor.sarif

- name: Upload SARIF report
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skill-doctor.sarif
```

> [!WARNING]
> **Trust-on-first-use note**: `action.yml` currently verifies downloaded binary archives against `SHA256SUMS.txt`, but does not yet perform Sigstore Cosign attestation verification inside the action step. This is tracked in [#41](https://github.com/KalarisLabs/Skill-Doctor/issues/41).

### Raw CLI in CI

```bash
skill-doctor scan-all . \
  --output sarif \
  --fail-on HIGH \
  --fail-under-coverage 0.8 \
  --deterministic \
  --offline
```

---

## Verify what you downloaded

Official release artifacts are accompanied by Sigstore Cosign OIDC keyless signatures and CycloneDX Software Bills of Materials (SBOM).

### 1. Verify checksum signature with Cosign
```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/KalarisLabs/Skill-Doctor/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

### 2. Verify binary digest
```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

### 3. Inspect CycloneDX SBOM
Inspect dependencies and component licenses in `skill-doctor.cdx.json`:
```bash
jq -r '.components[] | "\(.name) \(.version) (\(.licenses[0].license.id // "unknown"))"' skill-doctor.cdx.json
```

### OS security posture & code signing
- **macOS**: Binaries are **not Apple-notarized**. Archives downloaded directly via a web browser receive quarantine flags (`xattr -d com.apple.quarantine skill-doctor`). Installations via `npx`, `npm -g`, or `curl` do not set browser quarantine bits.
- **Windows**: Binaries are **unsigned** with Authenticode. Browser downloads may trigger Microsoft Defender SmartScreen warnings.

---

## Performance

All performance figures are reported with explicit provenance:

| Metric | Pre-registered target | Measured (with platform + provenance) |
|---|---|---|
| **Binary footprint (musl, stripped, `--features mcp`)** | ~12 MB target (**MISSED**: YARA-X embeds Wasmtime/Cranelift ~14 MiB; < 20 MiB ceiling) | **16,934,512 bytes** (16.15 MiB, `x86_64-unknown-linux-musl`, CI-measured) |
| **Binary footprint (MSVC, stripped, `--features mcp`)** | < 20 MiB ceiling | **17,936,896 bytes** (17.11 MiB, `x86_64-pc-windows-msvc`, not CI-verified) |
| **Peak RSS** | < 40 MiB | **14.67 MiB** (local measurement, `x86_64-pc-windows-msvc`, not CI-verified) |
| **Scan throughput** | ≥ 2,000 skills/min (warm cache off) | **660 skills/s** (~39,600 skills/min) (local measurement, `x86_64-pc-windows-msvc`, not CI-verified) |
| **Scan latency** | sub-150 ms (pre-registered target, never a measured result) | Not measured in CI |

---

## Design & determinism

- **Offline by default**: Skill Doctor operates with zero network access and zero telemetry in its default scan path.
- **Verdict determinism**: The `--deterministic` flag enforces byte-identical JSON and SARIF output across identical scan runs. This reproducibility invariant is verified on every pull request by the CI `determinism` job.
- **Opt-in threat intelligence (`--intel`)**: When explicitly enabled via `--intel`, the scanner queries `https://intel.skilldoctor.io/v1/digest/{sha256}` with a 2,000 ms timeout to verify bundle digests against known malicious feeds. No skill contents or file names are transmitted over the network.

---

## Limitations

- **Fixture count**: The current suite contains 14 curated skill fixtures; 6 threat classes remain rule-only.
- **No external corpus evaluation**: No evaluation on external, third-party public skill repositories has been completed.
- **L3 sandbox requirements**: The elective L3 behavioral sandbox is a process execution harness with temporary mock home directories and OS process group/Job Object termination; it does not use virtual machine or hypervisor isolation.
- **No OS code signing**: Release binaries are not Apple-notarized or Authenticode-signed.
- **Action TOFU**: `action.yml` verifies SHA-256 digests but does not yet verify Cosign signatures on downloaded binaries.
- **Prebuilt platform matrix**: Standalone release binaries are compiled for 6 platform targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`).

---

## Contributing, Security & License

- **Contributing**: Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for developer setup, the four-item detector requirement, and testing guidelines.
- **Security Policy**: Vulnerabilities should be reported privately via GitHub Security Advisories or `security@kalarislabs.com`. See [SECURITY.md](SECURITY.md).
- **License**: Skill Doctor is released under the [Apache License 2.0](LICENSE).
- **MSRV**: Requires Rust 1.93.0+ (MSRV), enforced in `Cargo.toml`.
