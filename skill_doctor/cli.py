"""
Skill Doctor CLI - Command-line interface for skill file scanning.
"""

import sys
import time
from pathlib import Path
from typing import Optional

import click

from skill_doctor import __version__
from skill_doctor.scanner.intake import normalize_bundle
from skill_doctor.scanner.layer1_static import scan_static
from skill_doctor.scanner.layer2_semantic import scan_semantic
from skill_doctor.scanner.layer4_threat_db import scan_threat_db, add_to_threat_db
from skill_doctor.scanner.scorer import score_findings
from skill_doctor.report.json_report import generate_json
from skill_doctor.report.html_report import generate_html
from skill_doctor.report.sarif import generate_sarif


@click.group()
@click.version_option(version=__version__)
def main():
    """Skill Doctor - Multi-layer security platform for AI agent skill files."""
    pass


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output",
    type=click.Choice(["sarif", "json", "html", "pdf"]),
    default=None,
    help="Output format (default: pretty terminal)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    default=None,
    help="Exit with code 1 if findings at this level or above",
)
@click.option("--no-llm", is_flag=True, help="Skip LLM semantic pass")
@click.option("--no-sandbox", is_flag=True, help="Skip E2B behavioral sandbox")
@click.option(
    "--rule-pack",
    default="core",
    help="Select specific rule packs (comma-separated)",
)
def scan(
    target: str,
    output: Optional[str],
    fail_on: Optional[str],
    no_llm: bool,
    no_sandbox: bool,
    rule_pack: str,
):
    """Scan a skill file, directory, or bundle."""
    print(f"SKILL DOCTOR v{__version__}")
    print(f"by Kalaris Labs")
    print()

    target_path = Path(target)
    print(f"[TARGET] {target_path}")

    start_time = time.time()

    try:
        # Layer 0: Intake and normalization
        print(f"[NORMALIZE] Normalizing bundle...")
        bundle_dir, bundle_hash = normalize_bundle(target_path)
        print(f"[HASH] Bundle hash: {bundle_hash[:16]}...")

        # Check threat database first
        print(f"[THREAT DB] Checking threat database...")
        cached_findings = scan_threat_db(bundle_hash)
        if cached_findings:
            print(f"[CACHE] Found cached results in threat database")
            all_findings = cached_findings
            layers_run = ["threat_db"]
        else:
            # Layer 1: Static analysis
            print(f"[STATIC] Running static analysis...")
            static_findings = scan_static(bundle_dir)
            print(f"[STATIC] Found {len(static_findings)} static findings")

            all_findings = static_findings
            layers_run = ["static"]

            # Layer 2: LLM semantic analysis (if not disabled)
            if not no_llm:
                print(f"[LLM] Running LLM semantic analysis...")
                semantic_findings = scan_semantic(bundle_dir, static_findings)
                all_findings.extend(semantic_findings)
                layers_run.append("semantic")
                print(f"   Found {len(semantic_findings)} semantic findings")

            # Layer 3: Behavioral sandbox (deferred to Week 2)
            if not no_sandbox:
                print(f"[SANDBOX] Behavioral sandbox deferred to Week 2")

            # Layer 4: Add to threat database if CRITICAL/HIGH findings
            critical_high = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH")]
            if critical_high:
                print(f"[THREAT DB] Adding {len(critical_high)} findings to threat database...")
                add_to_threat_db(bundle_hash, all_findings)

        # Score findings
        duration_ms = int((time.time() - start_time) * 1000)
        print(f"[TIME] Scanning completed in {duration_ms / 1000:.2f}s")

        scan_result = score_findings(all_findings, bundle_hash, layers_run, duration_ms)

        # Display results
        _display_results(scan_result)

        # Generate output file if requested
        if output:
            output_path = Path(f"skill-doctor-report-{scan_result.scan_id[:8]}.{output}")
            print(f"[OUTPUT] Generating {output.upper()} report...")

            if output == "json":
                generate_json(scan_result, output_path)
            elif output == "html":
                generate_html(scan_result, output_path)
            elif output == "sarif":
                generate_sarif(scan_result, output_path)
            elif output == "pdf":
                print(f"[WARN] PDF output not yet implemented")

            print(f"[DONE] Report saved to {output_path}")

        # Check fail-on condition
        if fail_on:
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            fail_threshold = severity_order.get(fail_on, 0)

            for finding in scan_result.findings:
                if severity_order.get(finding.severity, 0) >= fail_threshold:
                    print(f"\n[FAIL] Exiting with code 1 (findings at or above {fail_on})")
                    sys.exit(1)

    except Exception as e:
        print(f"\n[ERROR] Error during scanning: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument("directory", type=click.Path(exists=True))
def scan_all(directory: str):
    """Scan all skills in a directory tree."""
    print(f"[SCAN ALL] Scanning all skills in: {directory}")
    # TODO: Implement recursive scanning


@main.command()
@click.argument("v1", type=click.Path(exists=True))
@click.argument("v2", type=click.Path(exists=True))
def diff(v1: str, v2: str):
    """Diff scan two versions of a skill."""
    print(f"[DIFF] Comparing: {v1} vs {v2}")
    # TODO: Implement diff scanning


@main.command()
def mcp():
    """Run as MCP server for runtime gating."""
    print("[MCP] Starting MCP server...")
    # TODO: Implement MCP server mode


@main.command()
def rules():
    """List loaded rule packs."""
    print("[RULES] Loaded rule packs:")
    print("   - core (OWASP + ClawHavoc)")
    print("   - supply_chain (hash verification, typosquatting)")
    print("   - obfuscation (encoding, homoglyphs)")
    print("   - mcp (SSRF, tool poisoning)")
    # TODO: Dynamically list loaded rules


@main.command()
def version():
    """Print version information."""
    print(f"Skill Doctor v{__version__}")
    print("Copyright (C) 2026 Kalaris Labs")
    print("Licensed under GNU Affero General Public License v3")


def _display_results(scan_result):
    """Display scan results in a formatted way."""
    print()
    print("=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Risk Level: {scan_result.risk_level}")
    print(f"Risk Score: {scan_result.risk_score:.1f} / 10.0")
    print(f"Layers Run: {', '.join(scan_result.layers_run)}")
    print(f"Duration: {scan_result.duration_ms / 1000:.2f}s")
    print()

    # Count findings by severity
    severity_counts = {}
    for f in scan_result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    print(f"[SUMMARY] {len(scan_result.findings)} findings total:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"   {severity}: {count}")

    # Display findings
    if scan_result.findings:
        print()
        print("[FINDINGS]:")

        for finding in scan_result.findings:
            print()
            print(f"--- {finding.category} ---")
            print(f"Severity: {finding.severity}")
            print(f"File: {finding.file}" + (f" :{finding.line}" if finding.line else ""))
            print(f"Description: {finding.description}")
            print(f"Remediation: {finding.remediation}")
            print(f"Engine: {finding.engine} | Confidence: {finding.confidence:.0%}")
    else:
        print()
        print("[SAFE] No findings detected. Skill appears safe.")


if __name__ == "__main__":
    main()
