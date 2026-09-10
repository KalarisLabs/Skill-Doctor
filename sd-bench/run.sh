#!/usr/bin/env bash
# sd-bench/run.sh — Skill Doctor benchmark harness
#
# Usage:
#   ./sd-bench/run.sh [--pinned]

set -euo pipefail

MODE="${1:---default}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$ROOT_DIR/target/release/skill-doctor"

echo "=========================================================="
echo "          Skill Doctor v2 — Performance Benchmark         "
echo "=========================================================="
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Mode: $MODE"
echo ""

# 1. Build optimized binary
echo "==> Building release binary..."
cargo build --release -p skill-doctor

if [[ ! -x "$BIN" ]] && [[ -f "${BIN}.exe" ]]; then
    BIN="${BIN}.exe"
fi

# 2. Run Criterion micro-benchmarks
echo ""
echo "==> Running Criterion micro-benchmarks (skill-doctor-core)..."
cargo bench -p skill-doctor-core

# 3. Measure corpus scanning throughput
echo ""
echo "==> Measuring corpus scanning throughput..."
CORPORA_DIR="$SCRIPT_DIR/corpora"
TOTAL_SKILLS=0
TOTAL_BYTES=0

for skill in "$CORPORA_DIR"/*/; do
    if [ -d "$skill" ]; then
        TOTAL_SKILLS=$((TOTAL_SKILLS + 1))
        for f in "$skill"/*; do
            if [ -f "$f" ]; then
                BYTES=$(wc -c < "$f")
                TOTAL_BYTES=$((TOTAL_BYTES + BYTES))
            fi
        done
    fi
done

echo "Corpus: $TOTAL_SKILLS skills, $TOTAL_BYTES bytes total."

START_TIME=$(date +%s%N 2>/dev/null || date +%s)
for skill in "$CORPORA_DIR"/*/; do
    if [ -d "$skill" ]; then
        "$BIN" scan "$skill" --fail-on CRITICAL --output json --offline --deterministic > /dev/null 2>&1 || true
    fi
done
END_TIME=$(date +%s%N 2>/dev/null || date +%s)

# Nanosecond math if supported, otherwise second math
if [ "${#START_TIME}" -gt 10 ]; then
    ELAPSED_NS=$((END_TIME - START_TIME))
    ELAPSED_MS=$((ELAPSED_NS / 1000000))
else
    ELAPSED_S=$((END_TIME - START_TIME))
    ELAPSED_MS=$((ELAPSED_S * 1000))
fi

if [ "$ELAPSED_MS" -le 0 ]; then
    ELAPSED_MS=1
fi

THROUGHPUT_SKILLS=$(awk "BEGIN {printf \"%.1f\", ($TOTAL_SKILLS * 1000) / $ELAPSED_MS}")
THROUGHPUT_KB=$(awk "BEGIN {printf \"%.1f\", ($TOTAL_BYTES / 1024) / ($ELAPSED_MS / 1000)}")

echo ""
echo "==================== Benchmark Summary ===================="
echo "Total Skills Scanned: $TOTAL_SKILLS"
echo "Total Bytes Scanned:  $TOTAL_BYTES B"
echo "Total Time Elapsed:   ${ELAPSED_MS} ms"
echo "Scan Throughput:      $THROUGHPUT_SKILLS skills/sec"
echo "Data Throughput:      $THROUGHPUT_KB KB/sec"
echo "=========================================================="
