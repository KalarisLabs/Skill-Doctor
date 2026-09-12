# Skill Doctor Release & Publication Playbook

This document defines the strictly ordered procedure for cutting and publishing a release of Skill Doctor (e.g. `v0.1.0`).

---

## 1. Release Order & Pipeline Overview

The exact, mandatory release sequence is:

```
crates.io name check + npm scope -> merge -> tag -> inspect DRAFT -> un-draft -> npm publish -> cargo publish x6 in dependency order (neutralize, rules, core, sandbox, mcp, skill-doctor) -> install-verify
```

### Critical Invariant: Never npm publish Against a Draft Release

> [!CAUTION]
> **Never npm publish against a draft release, because download-binary.js fetches SHA256SUMS.txt from the tag and draft assets 404 anonymously.**
>
> **Why?**
> The npm package (`@kalarislabs/skill-doctor`) is a thin installer. When a user runs `npx @kalarislabs/skill-doctor` or `npm install -g @kalarislabs/skill-doctor`, the postinstall hook (`scripts/download-binary.js`) anonymously fetches `SHA256SUMS.txt` and the platform archive directly from GitHub Releases:
> `https://github.com/KalarisLabs/Skill-Doctor/releases/download/v${VERSION}/...`
>
> Assets on **Draft** releases return **HTTP 404** for unauthenticated users. If npm is published before the release is un-drafted, all user installations will immediately crash with:
> `HTTP 404: Not Found (https://github.com/KalarisLabs/Skill-Doctor/releases/download/v0.1.0/SHA256SUMS.txt)`
>
> You must **un-draft** the GitHub release and verify anonymous HTTP access **before** publishing to npm!

---

## 2. Step-by-Step Publication Procedure

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
npm access ls-packages @kalarislabs
```

### Step 2: Merge PR into main
Ensure all 12 CI gates are green, branch protection passes, and merge PR into `main`.

### Step 3: Tag the Release Commit
Ensure the local `main` branch is clean, up to date with `origin/main`, and create an annotated signed tag:
```bash
git checkout main
git pull origin main
git tag -s v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Step 4: Inspect the Draft Release (`release.yml`)
Pushing the `v0.1.0` tag triggers `.github/workflows/release.yml`. This workflow:
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
curl -sIL https://github.com/KalarisLabs/Skill-Doctor/releases/download/v0.1.0/SHA256SUMS.txt | grep -E "HTTP/.* (200|302)"
curl -sIL https://github.com/KalarisLabs/Skill-Doctor/releases/download/v0.1.0/skill-doctor-v0.1.0-x86_64-unknown-linux-musl.tar.gz | grep -E "HTTP/.* (200|302)"
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

# 2. skill-doctor-rules (leaf crate, embeds YARA-X rules)
cargo publish -p skill-doctor-rules
sleep 30

# 3. skill-doctor-core (depends on neutralize, rules)
cargo publish -p skill-doctor-core
sleep 30

# 4. skill-doctor-sandbox (depends on core types, self-contained process runner)
cargo publish -p skill-doctor-sandbox
sleep 30

# 5. skill-doctor-mcp (depends on core, neutralize)
cargo publish -p skill-doctor-mcp
sleep 30

# 6. skill-doctor (CLI binary, depends on all workspace crates)
cargo publish -p skill-doctor
```

#### Why `cargo publish --dry-run` Cannot Pass for All 6 Crates Before Release
`cargo publish --dry-run` enforces that all path dependencies declare versions already published to crates.io. Because `core`, `mcp`, and `skill-doctor` declare path dependencies on unpublished workspace members (`skill-doctor-neutralize`, `skill-doctor-rules`), running `cargo publish --dry-run` on them prior to the initial release of those leaf crates fails with:
```
error: no matching package found
searched package name `skill-doctor-rules`
```
Only leaf crates with no workspace path dependencies (`skill-doctor-neutralize`, `skill-doctor-rules`, `skill-doctor-sandbox`) can pass `--dry-run` in pre-release CI. Downstream crates pass publish checks once their prerequisites are live on crates.io.

### Step 8: Install & Post-Release Verification (`install-verify.yml`)
The publication of the GitHub release automatically triggers `.github/workflows/install-verify.yml` (or run manually via `workflow_dispatch`):
1. Verifies clean `npx @kalarislabs/skill-doctor@0.1.0 scan <fixture>` across Ubuntu, macOS, and Windows.
2. Asserts the real download path and SHA-256 checksum verification actually executed (`skill-doctor: verifying SHA-256 digest...` and `skill-doctor: checksum OK`).
3. Verifies `npm install -g @kalarislabs/skill-doctor@0.1.0` and `skill-doctor --version`.
4. Verifies composite action `uses: KalarisLabs/Skill-Doctor@v0.1.0` on real runner environments.
