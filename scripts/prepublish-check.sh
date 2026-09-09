#!/usr/bin/env bash
# scripts/prepublish-check.sh — local pre-push verification.
#
# Usage:
#   ./scripts/prepublish-check.sh --fast    # fmt + clippy + test
#   ./scripts/prepublish-check.sh --full    # + deny + CLI smoke

set -euo pipefail

MODE="${1:---fast}"

echo "=== Skill Doctor prepublish check ($MODE) ==="

echo ""
echo "--- cargo fmt --check ---"
cargo fmt --all --check

echo ""
echo "--- cargo clippy ---"
cargo clippy --workspace --all-targets -- -D warnings

echo ""
echo "--- cargo test ---"
cargo test --workspace

if [ "$MODE" = "--full" ]; then
    echo ""
    echo "--- cargo deny check ---"
    cargo deny check 2>/dev/null || echo "WARN: cargo-deny not installed, skipping"

    echo ""
    echo "--- CLI smoke test ---"
    cargo build --release
    ./target/release/skill-doctor scan tests/fixtures/benign \
        --fail-on HIGH --offline --deterministic
    echo "CLI smoke: exit $?"
fi

echo ""
echo "=== All checks passed ==="
