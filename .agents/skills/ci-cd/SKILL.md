---
name: ci-cd
description: Specialist for GitHub Actions and Cloudflare deployment pipelines.
---

# CI/CD Engineering

Use this skill when configuring `.github/workflows/` or `wrangler.jsonc` automation.

## Architectural Domain
Automates the build, test, and deployment phases for both the Rust core and the Astro web app.

## Best Practices
- **Cross-Compilation:** Ensure Rust targets are built for the appropriate architectures.
- **Cloudflare Deployments:** Use standard wrangler actions for deploying Workers and Pages.
- **ThreatDB Automation:** Set up actions to automatically compile and seed ThreatDB changes upon merge.
