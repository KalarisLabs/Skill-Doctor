---
name: sandbox-security
description: Specialist for microsandbox, Linux namespaces, and eBPF network isolation.
---

# Sandbox Security

Use this skill when dealing with the Behavioral Sandbox layer (`crates/core/src/sandbox`).

## Architectural Domain
Skill Doctor uses `microsandbox` to execute untrusted agent payloads in heavily isolated native Linux environments.

## Best Practices
- **Isolation over Emulation:** Rely on actual Linux namespaces and eBPF syscall monitoring.
- **Avoid Conflicts:** Do not confuse this with Cloudflare Worker's V8 isolates. The behavioral sandbox runs natively in a container or bare metal.
- **Failure Mode:** If the sandbox cannot be initialized securely, the layer must explicitly fail and report "Unavailable" rather than running insecurely.
