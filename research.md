<p align="center">
  <img src="public/skill%20doctor%20banner.png" alt="Skill Doctor" width="100%" />
</p>

# Skill Doctor: A High-Performance, Multi-Layer Security Framework for AI Agent Skill Files

**Author:** Sayan Chowdhury (sayan@kalarislabs.com)  
**Affiliation:** Kalaris Labs Research Team  
**Date:** August 2026 · Preprint

---

## Abstract

The proliferation of AI agent frameworks — Claude Code, OpenAI Codex CLI, Gemini CLI, Cursor, Windsurf, and their successors — has created a new and largely undefended attack surface: **skill files**. Skill files are structured instruction documents (`SKILL.md`, `.clauderules`, `AGENTS.md`, Model Context Protocol (MCP) server configs) that agent runtimes load from public registries, private repositories, and third-party ZIP archives at execution time. Once loaded, a skill file executes with the full trust context of the agent — access to tools, file systems, APIs, and downstream agents.

We identify ten distinct attack classes against skill files, synthesize the first unified threat taxonomy covering the OWASP Agentic Skills Top 10 and OWASP MCP Top 10, and present **Skill Doctor**: a multi-engine security platform built entirely in Rust. By combining static YARA-X analysis, native `tree-sitter` Abstract Syntax Tree (AST) scanning, and LLM-powered semantic reasoning, Skill Doctor detects malicious, deceptive, or non-compliant skill files before they are loaded by an agent runtime.

Unlike legacy Python-based tools, Skill Doctor introduces a native, single-binary architecture with sub-30ms static scan times, full bundle cross-file taint analysis, and community threat intelligence. We release Skill Doctor as open-source infrastructure under the AGPL v3 license to secure the foundation of the agentic web.

---

## 1. Introduction

In 2026, AI agents are no longer single-model systems running isolated prompts. They are orchestrated pipelines — composed of multiple models, dozens of tools, external API integrations, and dynamically loaded skill files that shape agent behavior at runtime. The trust model has fundamentally shifted: an agent does not just execute instructions from a user; it executes instructions from any skill file it loads.

Skill files are the new binary. In traditional software, a malicious binary requires execution permissions, sandboxing, and antivirus detection before it can do harm. A skill file requires only that an agent runtime load it — and that loading happens automatically, silently, and at scale across millions of agent sessions.

The scale of the problem is well-documented:
- **1,184 confirmed malicious skills** were discovered in ClawHub (the largest public skill registry) in the ClawHavoc Campaign of 2026.
- **36.7% of MCP servers** were found vulnerable to SSRF attacks in a survey of 7,000+ servers (BlueRock Security, 2026).
- Skills bundled with a companion Python script are **2.12× more likely to be vulnerable** to command injection than standalone `SKILL.md` files (NVIDIA SkillSpector research, 2026).

Despite this, available defenses remain immature. Existing scanners rely on slow Python runtimes, analyze files in isolation without cross-file context, and lack community threat intelligence sharing.

Skill Doctor solves this by introducing a lightning-fast Rust architecture designed specifically for integration directly into CI/CD pipelines, GitHub Actions, and Agent registries.

---

## 2. Background and Competitive Architecture Analysis

### 2.1 Cisco AI Defense — Skill Scanner

Cisco's Skill Scanner (open-source, Apache 2.0) is a comprehensive CLI tool combining YARA pattern matching and an LLM semantic analysis pass. 

**Limitations**: 
- **Performance bottleneck:** Built in Python, requiring heavy virtual environments. Startup times frequently exceed 1,200ms, making it prohibitively slow for real-time registry pre-commit hooks.
- **Isolation blindness:** It struggles with multi-file skill bundles, analyzing files in isolation rather than building a unified abstract syntax tree (AST) for the whole package.

### 2.2 NVIDIA SkillSpector

NVIDIA SkillSpector (open-source, MIT) is a static-first Python CLI scanner. It accepts `SKILL.md` files, ZIP archives, and Git URLs.

**Limitations**: 
- **Static-only rigidness:** Relies almost entirely on static regex/pattern matching, failing to catch semantically obfuscated prompt injections.
- **No Threat Intelligence:** Operates completely offline without consulting global threat databases for known hashes.

### 2.3 The Skill Doctor Advantage

Skill Doctor abandons the interpreted Python legacy entirely. Engineered in **Rust**, it compiles to a single, zero-dependency static binary. 

**Key Differentiators:**
1. **The Bundle vs. File Paradigm:** While competitors analyze a `SKILL.md` in isolation, Skill Doctor inherently assumes skills are *bundles*. A clean `SKILL.md` can easily mask a maliciously crafted `utils.py` sitting next to it. Skill Doctor seamlessly handles both: scanning a single file directly, or unpacking a ZIP/Tar/Git repo and performing **cross-file AST taint analysis** across the entire payload at once.
2. **Speed:** By using native `tree-sitter` and `yara-x` bindings in Rust, static analysis executes in under 30 milliseconds — fast enough to be a synchronous webhook.
3. **Registry-Native:** Built from day one to serve as the default GitHub Action and CLI gating mechanism for registries like Lobe Hub and Skills.sh.

---

## 3. Threat Model (SDTM-v1)

We define the Skill Doctor Threat Model (SDTM-v1) as a synthesis of the OWASP Agentic Skills Top 10 and real-world campaigns:

- **SD-01 · Prompt Injection**: Direct overrides, ASCII smuggling (zero-width Unicode payloads), and encoded payloads overriding agent system prompts.
- **SD-02 · Command Injection**: Unsanitized input passed to `subprocess.run()`, `eval()`, or `pickle.loads()` in companion Python scripts.
- **SD-03 · Data Exfiltration**: Reading sensitive paths (`~/.aws/credentials`) or environment variables, and leaking them via HTTP callbacks.
- **SD-04 · Privilege Escalation**: Tool scope violations, such as a code-formatting skill registering unauthorized file system read tools.
- **SD-05 · Supply Chain Tampering**: Hash mismatches, typosquatting, and `.pyc` cache poisoning in skill bundles.
- **SD-06 · SSRF via Tool Parameters**: Unvalidated URL parameters within the skill's declared tool schemas.
- **SD-07 · Tool Poisoning**: Shadow tool registration (e.g., registering a fake `git` tool that calls home before executing).
- **SD-08 · Persistent Backdoors**: Writing to auto-loaded context files like `.cursorrules` to survive skill deletion.
- **SD-09 · Context Window Flooding**: Excessively large outputs designed to crowd out security-relevant context.
- **SD-10 · Obfuscation and Evasion**: Homoglyph substitution and multi-layer encoding chains.

---

## 4. System Architecture

Skill Doctor runs a multi-layer analysis pipeline utilizing a highly concurrent Rust backend (`tokio`).

### Layer 1: Static Engine (< 30ms)
- **YARA-X Binding**: Memory-safe implementation of YARA matching 10 rulesets covering all SDTM-v1 classes.
- **Tree-sitter AST**: Parses all `.py`, `.js`, and `.ts` files in the bundle to construct a comprehensive taint graph, tracking variables from user inputs to dangerous sinks.
- **Entropy & Unicode Scanners**: Identifies base64 payload chunks and homoglyph evasion techniques natively.

### Layer 2: LLM Semantic Reasoner (~3–8s)
- Interfaces with an OpenAI-compatible REST API (defaults to Groq Llama-3.3-70b for speed).
- Ingests the unified bundle context alongside Layer 1's findings to audit for intent mismatch and hidden instruction extraction.

### Layer 3: Community Threat Database (< 5ms)
- Instantly checks the SHA-256 bundle hash against a community-maintained registry of known malicious skill signatures.

---

## 5. Benchmarks and Evaluation

Skill Doctor `v0.2.0` (Rust) was benchmarked against Cisco Skill Scanner (v1.4) and NVIDIA SkillSpector (v2.1) on a standardized corpus of 1,000 clean skills and 50 synthetically malicious skills. 

*Testing Environment: Ubuntu 24.04, 8-Core AMD EPYC, 16GB RAM.*

### 5.1 Performance (Execution Time)

| Metric | Skill Doctor (Rust) | NVIDIA SkillSpector | Cisco Skill Scanner |
|--------|---------------------|----------------------|---------------------|
| **Startup Overhead** | **~2 ms** | ~450 ms (Python init) | ~1,200 ms (heavy imports) |
| **Static Scan (Single File)** | **~12 ms** | ~85 ms | ~210 ms |
| **Static Scan (Bundle - 50 files)**| **~28 ms** | ~310 ms | ~890 ms |
| **LLM Inference Wait** | API Dependent | API Dependent | API Dependent |

*Conclusion:* Skill Doctor's native architecture is roughly **30x faster** than the Cisco baseline for complex bundles, making it the only viable choice for high-throughput registry webhooks and pre-commit GitHub Actions.

### 5.2 Detection Accuracy

| Metric | Skill Doctor | NVIDIA SkillSpector | Cisco Skill Scanner |
|--------|--------------|----------------------|---------------------|
| **True Positive Rate (TPR)** | **98.2%** | 84.0% | 91.5% |
| **False Positive Rate (FPR)** | **1.1%** | 3.8% | 2.4% |
| **Cross-file Injection Catch Rate**| **100%** | 0% (Isolated scans) | 40% (Partial support) |

*Conclusion:* By analyzing the entire bundle's Abstract Syntax Tree as a single unit, Skill Doctor successfully flagged 100% of command injection attacks hidden in companion scripts (`SD-02`) — a critical vector missed by single-file scanners.

---

## 6. Registry Gating and The GitHub Ecosystem

A standalone CLI is insufficient to secure an ecosystem; security must be enforced at the distribution layer. 

Skill Doctor is designed to natively integrate into skill registries (like Lobe Hub, Skills.sh, and MCPServers.org) through **GitHub Actions**. By distributing Skill Doctor as an official GitHub Action (`uses: KalarisLabs/skill-doctor-action@v1`), registries can enforce automated compliance checks on every Pull Request containing a new skill file. 

This model ensures that malicious payloads are caught before they ever reach the public marketplace, stopping supply chain attacks at the source.

---

## 7. Conclusion

Skill Doctor represents a generational leap in AI Agent security. By abandoning legacy interpreted languages in favor of a memory-safe, ultra-fast Rust architecture, it enables real-time security gating for the agentic web. With its bundle-first analysis philosophy and seamless integration paths via GitHub Actions, Skill Doctor provides the foundational infrastructure required to safely scale autonomous agent ecosystems.

---

## References

1. OWASP Foundation. *Agentic Skills Top 10*. 2026.
2. OWASP Foundation. *MCP Top 10*. 2026.
3. NVIDIA Research. *SkillSpector: Static and Semantic Analysis of AI Agent Skill Files.* arXiv, 2026.
4. Cisco AI Defense. *Skill Scanner: Open-Source Skill Security for AI Agents.* GitHub, 2026.
5. BlueRock Security. *SSRF in the Wild: A Survey of 7,000 MCP Servers.* 2026.