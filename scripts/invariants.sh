#!/usr/bin/env bash
set -euo pipefail
fail=0
chk() { # name, pattern, paths...
  local name="$1" pat="$2"; shift 2
  if grep -rInE --exclude-dir={target,.git,node_modules,fixtures} --exclude="PAPER-RECONCILIATION.md" "$pat" "$@" 2>/dev/null; then
    echo "::error::INVARIANT VIOLATION: $name"; fail=1
  fi
}

chk "Inv1: no Python/Node in product runtime" \
    '\.py"|python3?|node |require\(' crates/
chk "Inv5: rules crate must be on the scan path" \
    'TODO.*compiled_rules|#\[allow\(dead_code\)\].*rules' crates/
chk "Inv9: taxonomy stops at SD-11" \
    'SD-1[2-9]|SD-[2-9][0-9]' crates/ docs/ README.md
chk "Claim honesty: no microVM/network-jail language" \
    '[Mm]icro-?VM|network jail|fully sandboxed|air-?gapped' README.md docs/ crates/
chk "Claim honesty: perf numbers must not be called measured" \
    '(measured|achieves|delivers).{0,40}(2,?000 skills|40 ?MB|12 ?MB|15 ?s)' README.md docs/
chk "Hardcoded version outside manifests" \
    '0\.1\.0' crates/*/src/ scripts/
chk "Secrets" \
    'sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}' . 

# Presence checks
grep -q 'AWS_SECRET_ACCESS_KEY' crates/skill-doctor-sandbox/src/canary.rs \
  || { echo "::error::canary secret_name constants missing"; fail=1; }

exit $fail
