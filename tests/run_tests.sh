#!/bin/bash
# Skill Doctor - MuLamBDA E2E Testing Script

echo "Starting Skill Doctor Corpus Scan..."

# Ensure results directory exists
mkdir -p ./tests/results

# Scan SD-01 Prompt Injection
cargo run --release -- scan ./tests/corpus/SD-01-Prompt-Injection/ --output html > ./tests/results/report_sd01.html
cargo run --release -- scan ./tests/corpus/SD-01-Prompt-Injection/ --output json > ./tests/results/report_sd01.json

# Scan SD-02 Command Injection
cargo run --release -- scan ./tests/corpus/SD-02-Command-Injection/ --output html > ./tests/results/report_sd02.html
cargo run --release -- scan ./tests/corpus/SD-02-Command-Injection/ --output json > ./tests/results/report_sd02.json

# Scan SD-03 Data Exfiltration
cargo run --release -- scan ./tests/corpus/SD-03-Data-Exfiltration/ --output html > ./tests/results/report_sd03.html
cargo run --release -- scan ./tests/corpus/SD-03-Data-Exfiltration/ --output json > ./tests/results/report_sd03.json

echo "Scan complete. Reports generated in ./tests/results/"
