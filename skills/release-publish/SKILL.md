---
name: release-publish
description: Pre-publish and publish path for crates.io, npm installer, GitHub Releases, SBOM. Use when cutting versions, editing release.yml, or adding publish steps. Never publish from a feature branch.
---

# Release

Only from a `v*` tag on `main` after required checks are green.

1. `./scripts/prepublish-check.sh --full`
2. CHANGELOG for the version
3. Single workspace version bump
4. PR → required checks → merge
5. `git tag vX.Y.Z && git push origin vX.Y.Z`
6. `release.yml`: musl/darwin/win, checksums, SBOM, Sigstore, GitHub Release
7. `cargo publish` order: neutralize → rules → core → sandbox → mcp → skill-doctor
8. `npm publish --access public` `@kalarislabs/skill-doctor` (installer only)
9. Homebrew tap follow-up

Never: publish from CI on a non-tag; npm without matching binary checksums; skip dry-run; publish if deny/gitleaks is red.
