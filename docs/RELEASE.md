# Skill Doctor Release & Publication Playbook

This document defines the strictly ordered procedure for cutting and publishing a release of Skill Doctor (e.g. `v0.1.0` -> `v0.1.1`).

---

## 1. Historical Record: v0.1.0 Execution Details

The initial canonical release `v0.1.0` was executed on 2026-09-12 / 2026-09-13:
- **GitHub Release Tag**: `v0.1.0` ([Releases](https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.1.0))
- **CI Benchmark Run**: [Run 34698953208](https://github.com/KalarisLabs/Skill-Doctor/actions/runs/34698953208) (Job `103567203315`)
- **Release Workflow Run**: [.github/workflows/release.yml](https://github.com/KalarisLabs/Skill-Doctor/actions/workflows/release.yml)
- **crates.io Published Crates (6 crates)**:
  1. `skill-doctor-neutralize` `0.1.0`
  2. `skill-doctor-rules` `0.1.0`
  3. `skill-doctor-core` `0.1.0`
  4. `skill-doctor-sandbox` `0.1.0`
  5. `skill-doctor-mcp` `0.1.0`
  6. `skill-doctor` `0.1.0`
- **npm Package**: `@security.kalarislabs/skill-doctor` `0.1.0` ([npm Registry](https://www.npmjs.com/package/@security.kalarislabs/skill-doctor))

---

## 2. Release Sequence & Pipeline Order

The exact, mandatory release sequence is:

```
crates.io name check + npm scope -> merge PR -> tag vX.Y.Z -> inspect DRAFT release -> un-draft release -> npm publish -> cargo publish x6 in topological order -> install-verify
```

### Critical Invariant: Never npm publish Against a Draft Release

> [!CAUTION]
> **Never npm publish against a draft release, because download-binary.js fetches SHA256SUMS.txt from the tag and draft assets 404 anonymously.**
>
> **Why?**
> The npm package (`@security.kalarislabs/skill-doctor`) is a thin installer. When a user runs `npx @security.kalarislabs/skill-doctor` or `npm install -g @security.kalarislabs/skill-doctor`, the postinstall hook (`scripts/download-binary.js`) anonymously fetches `SHA256SUMS.txt` and the platform archive directly from GitHub Releases:
> `https://github.com/KalarisLabs/Skill-Doctor/releases/download/v${VERSION}/...`
>
> Assets on **Draft** releases return **HTTP 404** for unauthenticated users. If npm is published before the release is un-drafted, all user installations will immediately fail with:
> `HTTP 404: Not Found (https://github.com/KalarisLabs/Skill-Doctor/releases/download/vX.Y.Z/SHA256SUMS.txt)`
>
> You must **un-draft** the GitHub release and verify anonymous HTTP access **before** publishing to npm!

---

## 3. Step-by-Step Publication Procedure

### Step 1: Pre-Release Registry & Scope Verification
Before merging or tagging, verify namespace availability and credentials:
```bash
# 1. Verify crates.io crate names / ownership
cargo search skill-doctor-neutralize
cargo search skill-doctor-rules
cargo search skill-doctor-core
cargo search skill-doctor-sandbox
cargo search skill-doctor-mcp
cargo search skill-doctor

# 2. Verify npm scope and token permissions
npm whoami
npm access ls-packages @security.kalarislabs
```

### Step 2: Merge PR into main
Ensure all 12 CI gates are green, branch protection passes, and merge PR into `main`.

### Step 3: Tag the Release Commit
Ensure the local `main` branch is clean, up to date with `origin/main`, and create an annotated signed tag:
```bash
git checkout main
git pull origin main
git tag -s v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1
```

### Step 4: Inspect the Draft Release (`release.yml`)
Pushing the `v0.1.1` tag triggers `.github/workflows/release.yml`. This workflow:
1. Builds release binaries for 6 matrix targets:
   - `x86_64-unknown-linux-musl`
   - `aarch64-unknown-linux-musl`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
   - `x86_64-pc-windows-msvc`
   - `aarch64-pc-windows-msvc`
2. Generates `SHA256SUMS.txt`
3. Signs `SHA256SUMS.txt` via Sigstore Cosign (OIDC keyless attestation -> `SHA256SUMS.txt.bundle`)
4. Generates CycloneDX SBOM (`skill-doctor.cdx.json`)
5. Runs dry-runs for leaf crates and npm package
6. Creates a **Draft** release containing all assets.

**Action**: Navigate to `https://github.com/KalarisLabs/Skill-Doctor/releases` and inspect the draft release:
- Confirm all 6 target archives (`.tar.gz` and `.zip`) are present.
- Confirm `SHA256SUMS.txt` and `SHA256SUMS.txt.bundle` are attached.
- Confirm `skill-doctor.cdx.json` is attached.

### Step 5: Un-draft the Release
Edit the draft release on GitHub:
- Check generated release notes.
- Uncheck "Set as a draft" and click **Publish release**.
- Verify the release is publicly visible and downloadable anonymously:
```bash
# Must return HTTP 200 / 302
curl -sIL https://github.com/KalarisLabs/Skill-Doctor/releases/download/v0.1.1/SHA256SUMS.txt | grep -E "HTTP/.* (200|302)"
curl -sIL https://github.com/KalarisLabs/Skill-Doctor/releases/download/v0.1.1/skill-doctor-v0.1.1-x86_64-unknown-linux-musl.tar.gz | grep -E "HTTP/.* (200|302)"
```

### Step 6: Publish to npm
With the GitHub release live and assets publicly accessible:
```bash
npm publish --access public
```

### Step 7: Publish Crates to crates.io (Dependency Order x6)
Crates must be published sequentially in strict topological dependency order so downstream crates can resolve workspace dependencies on the registry:

```bash
# 1. skill-doctor-neutralize (leaf crate, zero internal workspace dependencies)
cargo publish -p skill-doctor-neutralize
sleep 30 # wait for crates.io index update

# 2. skill-doctor-rules (leaf crate, embeds YARA-X rules, zero internal workspace dependencies)
cargo publish -p skill-doctor-rules
sleep 30

# 3. skill-doctor-sandbox (leaf crate, self-contained process runner, zero internal workspace dependencies)
cargo publish -p skill-doctor-sandbox
sleep 30

# 4. skill-doctor-core (engine, depends on neutralize, rules)
cargo publish -p skill-doctor-core
sleep 30

# 5. skill-doctor-mcp (server, depends on core, neutralize)
cargo publish -p skill-doctor-mcp
sleep 30

# 6. skill-doctor (CLI binary, depends on core, neutralize, rules, and optionally mcp, sandbox)
cargo publish -p skill-doctor
```

#### Packaging Dry-Run Architecture in CI (`release.yml`)
The pre-release CI packaging verification (`packaging-dry-run` job) runs on a clean checkout in parallel with binary builds and handles the 6 crates in two tiers:

1. **Tier 1 (Hard Gate — Leaf Crates)**:
   `skill-doctor-neutralize`, `skill-doctor-rules`, and `skill-doctor-sandbox` declare zero internal workspace dependencies. They must pass `cargo publish --dry-run` unconditionally without `--allow-dirty`. A failure in any Tier 1 crate halts the release immediately.

2. **Downstream Crates (Tolerant Advisory Loop)**:
   `skill-doctor-core`, `skill-doctor-mcp`, and `skill-doctor` declare path+version dependencies on workspace members. Prior to publishing a new tag (e.g. `v0.1.1`), the new version of those dependencies does not yet exist on crates.io, causing `cargo publish --dry-run` to output:
   ```
   error: no matching package found
   searched package name `skill-doctor-rules`
   ```
   The CI loop executes `cargo publish --dry-run` on each downstream crate and specifically checks for this condition. If `no matching package` is encountered, it logs a workflow warning (`::warning::$c dry-run deferred: workspace dep not yet on crates.io for this version`). If any other packaging error occurs (syntax errors, missing files, dirty tree), it exits with code 1.

### Step 8: Post-Release Installation Verification (`install-verify.yml`)
Trigger `.github/workflows/install-verify.yml` via GitHub Actions `workflow_dispatch` or wait for the release event:
1. Verifies clean `npx @security.kalarislabs/skill-doctor@0.1.1 scan ./examples/hello-skill` on Ubuntu, macOS, and Windows (exit 0).
2. Verifies `npm install -g @security.kalarislabs/skill-doctor@0.1.1` and `skill-doctor --version`.
3. Verifies `cargo install skill-doctor --locked --features mcp` from crates.io.
4. Verifies detection of attack fixture (`tests/fixtures/attack/SD-02/malicious-skill`) with exit code 2.
