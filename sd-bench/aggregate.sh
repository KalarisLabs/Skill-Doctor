#!/usr/bin/env bash
# sd-bench/aggregate.sh — Aggregate HyperExecute benchmark results

set -euo pipefail

RESULTS_DIR="sd-bench/results-raw"
mkdir -p "$RESULTS_DIR"

echo "Aggregating HyperExecute benchmark run..."
if [ -d "target/criterion" ]; then
    echo "Archiving Criterion benchmark outputs..."
    tar -czf "$RESULTS_DIR/criterion-reports.tar.gz" target/criterion 2>/dev/null || true
fi

echo "Benchmark aggregation complete."
