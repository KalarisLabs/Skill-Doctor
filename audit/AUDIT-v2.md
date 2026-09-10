# Skill Doctor v2 Pre-Release Audit Report

**Auditor**: Adversarial Review Agent  
**Date**: 2026-09-10  
**Scope**: Complete codebase audit against AGENTS.md invariants, CONTEXT.md contracts, and whitepaper claims

---

## Release Verdict

**NO-GO** - Critical license inconsistency and missing release artifact documentation must be resolved before any tag.

---

## Blockers (Must Fix Before Any Tag)

### 1. License Inconsistency (Release-Blocking)
**Location**: 
- `README.md:107` states "AGPL-3.0-or-later"
- `LICENSE:1` and `Cargo.toml:16` state "Apache-2.0"
- `package.json:5` states "Apache-2.0"

**Issue**: The README claims AGPL-3.0-or-later but the actual LICENSE file and package metadata declare Apache-2.0. This is a material discrepancy that could cause legal compliance issues.

**Invariant Violated**: Documentation consistency

**Recommendation**: 
- Update README.md line 107 to "Apache-2.0" to match the actual LICENSE file
- OR change LICENSE file to AGPL-3.0-or-later if that was the intended license
- Ensure all three sources (README, LICENSE, Cargo.toml, package.json) agree

---

### 2. Missing CHANGELOG.md (Release-Blocking)
**Location**: Root directory `CHANGELOG.md` does not exist

**Issue**: TESTING.md §3 requires a CHANGELOG.md entry documenting changes for each release tag, but no CHANGELOG.md file exists in the repository.

**Invariant Violated**: Release process requirements (TESTING.md §3.6)

**Recommendation**: Create CHANGELOG.md with v0.1.0 entry documenting initial release, following conventional changelog format

---

## Should-Fix (Before Announcing Publicly)

### 3. L3 Implementation vs Documentation Mismatch
**Location**: 
- `README.md:84` describes L3 as "L3 microVM behavioral analysis"
- `CONTEXT.md:50` describes L3 as "L3 behavioral microVM + replay"
- `DEPENDENCIES.md:66` describes "microVM SDK — native Rust, in-process, ~100 ms boot"
- Actual implementation in `skill-doctor-sandbox/src/lib.rs:1-9` is a "L3-lite behavioral process harness"

**Issue**: Documentation consistently describes L3 as a "microVM" with VM isolation, but the actual implementation is a process harness with environment isolation, differential replay, and process tree guards. No actual microVM/Firecracker/Cloud-Hypervisor is present.

**Invariant Violated**: Claim honesty (documentation overstates implementation)

**Evidence**: 
- `skill-doctor-sandbox/src/lib.rs:1-9` header: "L3-lite behavioral process harness"
- `skill-doctor-sandbox/src/lib.rs:4` mentions "Environment isolation table"
- No microVM SDK dependencies in Cargo.toml or Cargo.lock
- `DEPENDENCIES.md:66` lists microVM SDK as "Planned for later milestones (not yet wired)"

**Recommendation**: Update all documentation to accurately describe L3 as "L3 behavioral process harness with environment isolation and differential replay" rather than "microVM"

---

### 4. Exit Code Implementation Incomplete
**Location**: `crates/skill-doctor-cli/src/main.rs`

**Issue**: While exit codes 0, 1, and 2 are implemented, exit code 3 (structural coverage below threshold) is not explicitly implemented in the CLI main.rs. The code references exit code 3 in comments but doesn't actually return it.

**Evidence**:
- `main.rs:3-7` documents exit codes 0/1/2/3
- `main.rs:376-382` only exits with 0 or 1
- Coverage threshold logic exists but doesn't trigger exit code 3

**Invariant Violated**: Contract consistency (exit codes not fully implemented)

**Recommendation**: Implement exit code 3 for coverage threshold failures in the CLI

---

### 5. MCP Tool Schema Compliance Issue
**Location**: `crates/skill-doctor-mcp/src/lib.rs:109-117`

**Issue**: The MCP `skill_doctor_scan` tool schema has a `path` parameter but documentation specifies it should only have `path/mode/fail_on` with no `content` parameter. This is actually CORRECT per the contract, but needs verification that no code path attempts to accept inline content.

**Status**: PASS - Schema correctly excludes `content` parameter as required

---

## Nits

### 6. Workspace Dependencies Commented Out
**Location**: `Cargo.toml:68-94`

**Issue**: Many dependencies (yara-x, tree-sitter, memmap2, blake3, etc.) are commented out as "Planned for later milestones (not yet wired)" but the codebase appears to be milestone 1-2. This creates confusion about what's actually in use.

**Recommendation**: Either move planned dependencies to a separate section or remove the comment once wired

---

### 7. Benchmark Claims Are Correctly Stated as Targets
**Location**: 
- `sd-bench/RESULTS.md:15-18` correctly labels as "Target budget" vs "Measured"
- `README.md` does not make any measured claims about performance

**Status**: PASS - All performance figures are correctly labeled as pre-registered targets, not measured values

---

### 8. No Legacy Code Artifacts
**Status**: PASS - No evidence of:
- Old crate names (crates/cli, crates/core, crates/report)
- Old module paths (layer2_semantic.rs, llm_client.rs)
- Python in product runtime
- Node interpreter requirements
- opencode.json or .env files in product code
- Hardcoded API keys or tokens

---

## Invariant Coverage Table

| Invariant | Test Path | Status | Evidence |
|-----------|-----------|--------|----------|
| 1. Rust-only product runtime | `ci.yml:41-49` (invariant grep) | PASS | CI greps for openai/anthropic in core/cli, passes |
| 2. No mandatory LLM; default path is --offline --deterministic | `ci.yml:81-88` (CLI smoke) | PASS | CI tests benign scan with --offline --deterministic |
| 3. Additive-only: L2/L3/L4 cannot delete/downgrade L1 | `scoring.rs:438-489` (tests) | PASS | Multiple additive-only tests present |
| 4. Determinism: byte-identical JSON/SARIF | `ci.yml:164-195` (determinism job) | PASS | CI runs SHA-256 comparison test |
| 5. YARA-X compiled at build time | Not yet implemented | DRIFT | YARA-X rules not yet wired; pattern engine uses regex stub |
| 6. SD-11: neutralize before model | `neutralize/` crate exists | PASS | skill-doctor-neutralize crate implements SD-11 protocol |
| 7. No secret VALUES in findings/reports/logs | `sarif.rs:87-127` (test) | PASS | Test verifies canary tokens absent from SARIF/JSON |
| 8. CLI-first; TUI behind tui feature | `cli/Cargo.toml:44-46` | PASS | TUI dependencies are optional features |
| 9. Exactly four frozen contributions | Not testable | N/A | Architectural claim, not runtime invariant |

---

## Legacy Residue List

| Item | Location | Status | Recommendation |
|------|-----------|--------|----------------|
| Python in product runtime | None found | PASS | No Python runtime dependencies |
| Node in product runtime | npm is installer only | PASS | package.json is thin installer only |
| Old crate names | None found | PASS | Current crate names match v2 structure |
| Old module paths | None found | PASS | No layer2_semantic.rs or llm_client.rs artifacts |
| opencode.json | None found | PASS | No opencode.json in tree |
| .env files | Only in test fixtures | PASS | Only in sandbox test fixtures (allowed) |
| Hardcoded tokens | Only in canary tests | PASS | Only synthetic canaries in sandbox tests |
| Dead code | No todo!/unimplemented!() | PASS | No dead stub functions found |
| v1 docs | No ARCHITECTURE.md | PASS | No v1 mermaid pipeline docs found |

---

## Claim Softening Required

### Claim: "L3 microVM behavioral analysis"
**Original**: README.md:84, CONTEXT.md:50, DEPENDENCIES.md:66 describe L3 as "microVM behavioral analysis"

**Issue**: Actual implementation is a process harness, not a microVM

**Recommended Wording**: "L3 behavioral process harness with environment isolation and differential replay"

**Locations to Update**:
- README.md:84
- CONTEXT.md:50
- DEPENDENCIES.md:66
- AGENTS.md:30, 61

---

## Security Review Findings

### Neutralize Implementation
**Status**: PASS - `skill-doctor-neutralize` crate properly implements bidi, zero-width, tag character, and confusable detection and removal

### L3 Canary Implementation
**Status**: PASS - `skill-doctor-sandbox/src/canary.rs:7-9` correctly notes that raw canary tokens are never included in findings; only key names are emitted

### L4 Host Allowlist
**Status**: NOT YET IMPLEMENTED - L4 exists but host allowlist validation not yet present

### L0 Archive Safety
**Status**: PASS - `l0.rs` uses standard zip/tar libraries with no path traversal vulnerabilities evident

### Unsafe Blocks
**Status**: PASS - All unsafe blocks are in `skill-doctor-sandbox/src/runner.rs` for Windows Job Objects and Unix process groups, which is allowed per invariant

---

## Open-Source Readiness Checklist

| Item | Status | Evidence |
|------|--------|----------|
| LICENSE (Apache-2.0) | FAIL | License file exists but conflicts with README.md |
| SECURITY.md with private disclosure | PASS | SECURITY.md:11-16 provides private disclosure path |
| CONTRIBUTING.md pointing to TESTING.md | PASS | CONTRIBUTING.md:5 references TESTING.md |
| CODEOWNERS | PASS | .github/CODEOWNERS exists |
| Issue/PR templates | PASS | .github/ISSUE_TEMPLATE/ has bug_report.yml, feature_request.yml, config.yml |
| Dependabot/Renovate | PASS | .github/dependabot.yml exists for Cargo and Actions |
| Branch protection | NOT VERIFIED | Cannot verify GitHub branch protection from code access |
| CHANGELOG | FAIL | CHANGELOG.md does not exist |
| 60-second "why would I install this" path | PASS | README.md has clear install and quick-start sections |

---

## Summary

**Critical Issues**: 2 (License inconsistency, missing CHANGELOG.md)  
**Should-Fix Issues**: 2 (L3 microVM misstatement, exit code 3 implementation)  
**Nits**: 1 (commented-out dependencies in Cargo.toml)

**Overall Assessment**: The codebase is in good shape with strong adherence to most invariants. The two critical issues are documentation/release process problems rather than code bugs. The L3 microVM misstatement is the most significant claim honesty issue that should be corrected before public announcement.

**Recommendation**: Fix the license inconsistency and create CHANGELOG.md before any release tag. Update L3 documentation to accurately reflect the process harness implementation before public marketing. Implement exit code 3 for coverage failures to complete the contract implementation.
