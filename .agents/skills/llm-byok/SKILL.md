---
name: llm-byok
description: Specialist for Provider-Agnostic Semantic Inference and Prompt Injection detection.
---

# LLM BYOK Engineering

Use this skill when configuring or routing Semantic Analysis (Layer 2) requests.

## Architectural Domain
Semantic inference uses LLMs to detect obfuscated intent. It operates on a Bring-Your-Own-Key (BYOK) model.

## Best Practices
- **Provider Agnosticism:** Route requests through generic interfaces (e.g., standard OpenAI format) so users can supply their own Groq, Anthropic, or OpenAI keys.
- **Fallback:** Use Cloudflare Workers AI natively when no API key is provided, if configured.
- **Data Privacy:** Ensure BYOK tokens are handled strictly server-side and never exposed to the client.
