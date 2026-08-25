# Skill Doctor Web Application — Full Implementation Plan

Build the complete hosted Skill Doctor experience: a real scanner UI backed by the existing Rust engine, deployed on Cloudflare Workers at `doctor.kalarislabs.com`.

## Resolved Decisions

- **Layer 2 LLM Architecture — Provider-Agnostic with BYOK.** Semantic analysis uses a provider-agnostic inference interface. Default hosted provider: **Cloudflare Workers AI**. Kalaris also offers **Groq** as a hosted option. Users may supply their own provider credentials. Provider keys must remain server-side and user-scoped, never exposed to the client. Provider, model, prompt, token, and cost metadata are recorded for reproducibility. LLM output is evidence for the aggregation engine, never the sole source of the final verdict.
- **Tailwind v4** confirmed.
- **Cloudflare account needs setup.** Plan includes provisioning D1, R2, Queues, Durable Objects (DO), and custom domain.

## Production Gates & Execution Rules

**Execution Mandate:** Complete all eight sprint areas in one session, but **do not mark a feature complete merely because its UI exists.** Every security-path feature must be backed by real execution, real persistence, and a verifiable integration test. If infrastructure prevents a capability from being safely deployed, fail explicitly rather than substituting mock behavior.

**Production Gate criteria before public launch:**
- No mocks
- No fake progress
- No unverified verdicts
- No automatic ThreatDB poisoning
- No raw sandbox output streamed to client
- No unbounded execution
- No secrets exposed to the client
- CLI / Web engine absolute parity
- Reproducible scan manifests
- SSRF protection
- Execution / resource limits

**Benchmark Independence:** The web app will link to the independent Agent-Security-Benchmark project. Skill Doctor's internal tests must *never* silently become the benchmark evaluation set.

## Architecture Overview

```
                    doctor.kalarislabs.com
                            │
                     Cloudflare CDN
                            │
                   ┌────────┴────────┐
                   │                 │
              Astro SSR          Worker API
           (on Workers)        /api/* routes
                   │                 │
                   │          ┌──────┴──────┬───────────────┐
                   │          │             │               │
                   │     D1 Database    R2 Storage    Durable Object
                   │     (ThreatDB +    (uploaded     (Live Scan State
                   │      scan meta)    artifacts)      SSE Fan-out)
                   │          │
                   │     Cloudflare Queue
                   │          │
                   │    ┌─────┴─────┐
                   │    │           │
                   │  WASM Worker  Container/Tunnel
                   │  (L1 Static   (L2 Semantic
                   │   L4 Threat   L3 Sandbox)
                   │   Scorer)      │
                   │    │           │
                   │    └─────┬─────┘
                   │          │
                   │    Result Aggregator
                   │          │
                   │     SSE → Browser (via DO)
                   │
              React Islands
           (Scanner, Report,
            ThreatDB, Progress)
```

## Proposed Changes

### Sprint 1 — Foundation
Set up the Astro project with Cloudflare Workers adapter, design system, routing, and layout.
- `web/`: Astro project root on Cloudflare Workers.
- `web/src/layouts/BaseLayout.astro`: Dark theme, security aesthetic.
- `web/src/pages/`: Routing for scan, report, threats, benchmarks, docs.

### Sprint 2 — Scanner UI
The core interactive experience: input → scan → progress.
- `web/src/components/scanner/ScannerApp.tsx`: Auto-detects URLs, handles uploads, submits to API.
- `web/src/components/scanner/ScanProgress.tsx`: Live pipeline visualization via SSE through DO. Sanitized events only.

### Sprint 3 — Scan API + Worker Backend
The Cloudflare Worker API that orchestrates scans.
- `POST /api/scans`: Store artifact in R2, create record in D1, enqueue to Queue, rate limited.
- `GET /api/scans/[scanId]/stream`: SSE endpoint via Durable Object.

### Sprint 4 — Scan Worker (Rust Engine Integration)
The Cloudflare Queue consumer running Skill Doctor.
- Update DO/D1 status.
- L1 Static: WASM-compiled core.
- L2 Semantic: Provider-agnostic inference (BYOK).
- L3 Sandbox: Isolated compute.
- L4 Threat Intel: D1 ThreatDB query.
- Scorer/Aggregator: Canonical Rust engine via WASM/Tunnel.

### Sprint 5 — Report Page
- `/report/:scanId` dynamic page with Verdict banner, Findings list, Layer results grid.

### Sprint 6 — ThreatDB Web UI & Canonical Source
- `threat-db/`: Canonical Git source (YAML files).
- Web UI: ThreatList, ThreatDetail components.

### Sprint 7 — Cloudflare Deployment
- `web/wrangler.toml`: D1, R2, Queue, DO, custom domain bindings.

### Sprint 8 — Security & Polish
- Implementation of Production Gates (SSRF protection, execution limits, rate limits, sandbox isolation).
