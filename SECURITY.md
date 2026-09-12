# Security Policy

Skill Doctor is a security scanner for AI agent skill files. We treat the security of this scanner, its analysis engines, and its supply chain with the highest priority.

## Reporting a Vulnerability

**DO NOT file public GitHub issues for security vulnerabilities, zero-days, or exploit payloads.**

If you discover a vulnerability in Skill Doctor, please report it privately:

1. **GitHub Security Advisory**: Submit a private report via [GitHub Security Advisories](https://github.com/KalarisLabs/Skill-Doctor/security/advisories/new).
2. **Direct Email**: If GitHub Advisories are unavailable, email **`security@kalarislabs.com`** with:
   - A clear description of the issue
   - Reproduction steps or proof of concept
   - Impact assessment
   - Your name and affiliation for disclosure credits (optional)

### Policy & Responsible Disclosure
- We acknowledge reports within **48 hours**.
- We aim to provide a remediation patch within **14 days** of confirmation.
- We request that you observe coordinated disclosure: please do not publicly discuss or publish details of the vulnerability until a patch has been released.

## Handling of Malicious Samples

Skill Doctor contains rules and detectors for 11 threat classes (SDTM-v1). 

- **Do NOT open issues or PRs containing active malware, live command-and-control URLs, or unredacted credentials.**
- To contribute detection rules or test fixtures, refer to [CONTRIBUTING.md](CONTRIBUTING.md). Attack test fixtures must follow the synthetic test fixture conventions and be quarantined in `tests/fixtures/attack/` using harmless mock endpoints.

## Verifying Release Artifacts

Every official release of Skill Doctor includes a cryptographic provenance chain and software bill of materials:

### 1. Sigstore Cosign Attestation
The release checksum manifest (`SHA256SUMS.txt`) is signed using keyless OIDC Cosign via GitHub Actions.
Verify `SHA256SUMS.txt` against its signature bundle:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/KalarisLabs/Skill-Doctor/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

### 2. Verifying Binary Checksums
After verifying `SHA256SUMS.txt`, confirm the SHA-256 digest of your downloaded binary:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

### 3. CycloneDX Software Bill of Materials (SBOM)
Every release publishes `skill-doctor.cdx.json` conforming to the CycloneDX JSON specification.
You can inspect all transitive dependencies, component hashes, and licenses:

```bash
# Validate the SBOM format
cyclonedx validate --input-file skill-doctor.cdx.json

# List components and licenses with jq
jq -r '.components[] | "\(.name) \(.version) (\(.licenses[0].license.id // "unknown"))"' skill-doctor.cdx.json
```

### 4. Binary Signing & OS Security Posture

We state our release binary signing posture explicitly:
- **Sigstore Attestation**: All release checksum manifests (`SHA256SUMS.txt`) are cryptographically signed using Sigstore Cosign via GitHub Actions OIDC keyless signing, establishing cryptographic provenance back to the official release workflow.
- **macOS (Gatekeeper & Notarization)**: macOS binaries are **not Apple-notarized**. If you download an archive directly via a web browser, macOS Gatekeeper will attach quarantine attributes (`com.apple.quarantine`). Installations via `npx @kalarislabsai/skill-doctor`, `npm install -g`, or `curl` do not set browser quarantine flags and are completely unaffected. To clear quarantine from a browser-downloaded archive manually: `xattr -d com.apple.quarantine skill-doctor`.
- **Windows (SmartScreen & Authenticode)**: Windows release binaries are **unsigned** with an Authenticode certificate. Running an executable downloaded via a web browser may prompt a Microsoft Defender SmartScreen untrusted publisher warning. Installations via `npx @kalarislabsai/skill-doctor`, npm, or `cargo install` are unaffected.
