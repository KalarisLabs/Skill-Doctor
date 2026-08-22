# Skill Doctor Malicious Corpus Dataset

This dataset is specifically designed as a test corpus for validating the Skill Doctor engine via the MuLamBDA (TestMu AI / Kane CLI) CI pipeline.

### Definitions
- **TestMu AI**: An autonomous QA agent platform capable of parsing visual and structured test artifacts.
- **MuLamBDA**: The underlying AI model architecture powering TestMu AI's visual reasoning.
- **Kane CLI**: The command-line interface used to trigger TestMu AI test suites within CI/CD pipelines (e.g., GitHub Actions).

It contains a journaled collection of intentionally vulnerable and malicious AI skills spanning all ten SDTM-v1 threat categories (SD-01 through SD-10), plus a clean benign baseline. The CI pipeline scans these skills and outputs the structured results into the `tests/results/` directory.

## Corpus Structure

- **SD-01-Prompt-Injection**: Skills demonstrating system prompt overrides and stochastic manipulation.
- **SD-02-Command-Injection**: Skills bundled with companion `.py` or `.js` files containing unvalidated execution sinks (`eval`, `exec`, `subprocess`).
- **SD-03-Data-Exfiltration**: Skills programmed to scrape honeypot credentials and attempt outbound network requests.
- **SD-04-Privilege-Escalation**: Skills that silently escalate tool permissions beyond declared scope.
- **SD-05-Supply-Chain-Tampering**: Skills with hash mismatches, typosquatting, or `.pyc` cache poisoning.
- **SD-06-SSRF**: Skills using unvalidated URL schemas to scan internal network architectures.
- **SD-07-Tool-Poisoning**: Skills that shadow-register proxy tools masquerading as system utilities.
- **SD-08-Persistent-Backdoors**: Skills injecting persistence into auto-loaded environment files.
- **SD-09-Context-Flooding**: Skills generating excessive output to overflow the agent's context window.
- **SD-10-Obfuscation**: Skills using homoglyph substitution, base64 encoding, deferred execution, and logic bombs.
- **benign-clean-skill**: A completely safe skill that must produce zero findings (negative test case).

*(This dataset is completely isolated and open-sourced for community security research and continuous integration validation).*
