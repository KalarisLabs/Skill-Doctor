#!/usr/bin/env python3
"""
scripts/check-deps.py — Validate DEPENDENCIES.md against cargo metadata.

Guarantees:
1. Exact version equality for all documented crates (no loose prefix matching).
2. Complete coverage: every direct workspace dependency must be present in DEPENDENCIES.md.
3. Proper classification: crates documented in Section 1 ("Shipped in Default Binary")
   must be reachable in the default/mcp binary graph and cannot include feature-only crates.
4. Correct multi-version handling: duplicate crate versions in the graph are preserved.
"""

import json
import re
import subprocess
import sys

def main():
    # 1. Full metadata across all features for version resolution
    meta_all = json.loads(subprocess.check_output(["cargo", "metadata", "--all-features", "--format-version", "1"]))
    
    # Map crate name to set of all resolved versions
    packages_by_name = {}
    for p in meta_all["packages"]:
        packages_by_name.setdefault(p["name"], set()).add(p["version"])

    # 2. Metadata for default/mcp binary reachability (Section 1 validation)
    meta_mcp = json.loads(subprocess.check_output(["cargo", "metadata", "--no-default-features", "--features", "mcp", "--format-version", "1"]))
    mcp_resolve_nodes = {n["id"]: n for n in meta_mcp["resolve"]["nodes"]}
    cli_nodes = [n for n in meta_mcp["resolve"]["nodes"] if "skill-doctor " in n["id"] or n["id"].startswith("skill-doctor#") or "skill-doctor-cli" in n["id"]]
    
    mcp_reachable_ids = set()
    def visit_mcp(node_id):
        if node_id in mcp_reachable_ids:
            return
        mcp_reachable_ids.add(node_id)
        node = mcp_resolve_nodes.get(node_id)
        if node:
            for dep in node["deps"]:
                visit_mcp(dep["pkg"])
    if cli_nodes:
        visit_mcp(cli_nodes[0]["id"])
    mcp_reachable_names = {p["name"] for p in meta_mcp["packages"] if p["id"] in mcp_reachable_ids}

    # 3. Direct workspace dependencies (must all be documented)
    meta_no_deps = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
    workspace_direct_deps = set()
    for p in meta_no_deps["packages"]:
        for d in p["dependencies"]:
            if not d.get("path"):
                workspace_direct_deps.add(d["name"])

    with open("DEPENDENCIES.md", "r", encoding="utf-8") as f:
        content = f.read()

    sec1_match = re.search(r"## 1\. Shipped in Default Binary(.*?)(?=## 2\.|\Z)", content, re.DOTALL)
    sec1_text = sec1_match.group(1) if sec1_match else ""

    row_pattern = re.compile(r"\|\s*`([a-zA-Z0-9_\-]+)`\s*\|\s*`([^`]+)`\s*\|")
    all_rows = row_pattern.findall(content)
    sec1_rows = row_pattern.findall(sec1_text)

    tool_exclusions = {"cargo-deny", "gitleaks", "semgrep"}
    errors = []
    checked = 0
    documented_crates = set()

    # Verify exact version equality and phantom crate detection
    for name, ver in all_rows:
        if name in tool_exclusions:
            continue
        checked += 1
        documented_crates.add(name)
        if name not in packages_by_name:
            errors.append(f"Phantom crate in DEPENDENCIES.md: '{name}'")
        elif ver not in packages_by_name[name]:
            available = ", ".join(sorted(packages_by_name[name]))
            errors.append(f"Version mismatch for '{name}': DEPENDENCIES.md has '{ver}', lockfile has '{available}'")

    # Verify no workspace dependency is missing
    missing_deps = workspace_direct_deps - documented_crates
    if missing_deps:
        for missing in sorted(missing_deps):
            errors.append(f"Missing workspace dependency in DEPENDENCIES.md: '{missing}'")

    # Verify Section 1 ("Shipped in Default Binary")
    feature_only_crates = {"ratatui", "crossterm", "reqwest"}
    for name, _ in sec1_rows:
        if name in tool_exclusions:
            continue
        if name in feature_only_crates:
            errors.append(f"Crate '{name}' is feature-gated but documented under Section 1 ('Shipped in Default Binary')")
        if name not in mcp_reachable_names:
            errors.append(f"Crate '{name}' is documented under Section 1 ('Shipped in Default Binary') but not reachable in default/mcp binary graph")

    if errors:
        print("DEPENDENCIES.md verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print(f"deps-check passed: verified {checked} crates (exact versions, graph reachability, complete coverage).")

if __name__ == "__main__":
    main()
