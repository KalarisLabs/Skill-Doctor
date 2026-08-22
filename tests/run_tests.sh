#!/bin/bash
# Skill Doctor - MuLamBDA E2E Testing Script

echo "Starting Skill Doctor Corpus Scan..."

# Ensure results directory exists
mkdir -p ./tests/results

# Scan all threat categories (SD-01 through SD-10) and benign baseline
CATEGORIES=(
  "SD-01-Prompt-Injection"
  "SD-02-Command-Injection"
  "SD-03-Data-Exfiltration"
  "SD-04-Privilege-Escalation"
  "SD-05-Supply-Chain-Tampering"
  "SD-06-SSRF"
  "SD-07-Tool-Poisoning"
  "SD-08-Persistent-Backdoors"
  "SD-09-Context-Flooding"
  "SD-10-Obfuscation"
  "benign-clean-skill"
)

for cat in "${CATEGORIES[@]}"; do
  echo "Scanning $cat..."
  cargo run --release -- scan "./tests/corpus/$cat/" --output html > "./tests/results/report_${cat}.html" 2>&1 || true
  cargo run --release -- scan "./tests/corpus/$cat/" --output json > "./tests/results/report_${cat}.json" 2>&1 || true
done

echo "Scan complete. All reports generated in ./tests/results/"

