# Skill Doctor Malicious Corpus Dataset

This dataset is specifically designed as a test corpus for validating the Skill Doctor engine via the MuLamBDA (TestMu AI / Kane CLI) CI pipeline.

It contains a journaled collection of intentionally vulnerable and malicious AI skills spanning multiple threat categories (SD-01 through SD-10). The CI pipeline scans these skills and outputs the structured results into the `tests/results/` directory, which is then parsed and visually validated by the TestMu AI agents.

## Corpus Structure

- **SD-01-Prompt-Injection**: Skills demonstrating system prompt overrides and stochastic manipulation.
- **SD-02-Command-Injection**: Skills bundled with companion `.py` or `.js` files containing unvalidated execution sinks (`eval`, `exec`, `subprocess`).
- **SD-03-Data-Exfiltration**: Skills programmed to scrape honeypot credentials and attempt outbound network requests.

*(This dataset is completely isolated and open-sourced for community security research and continuous integration validation).*
