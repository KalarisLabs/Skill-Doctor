"""
Layer 4: Threat Database - Hash lookup and CVE matching.
"""

from pathlib import Path
from typing import List, Optional

from skill_doctor.models import Finding


def scan_threat_db(bundle_hash: str) -> Optional[List[Finding]]:
    """
    Check bundle hash against threat database.

    Args:
        bundle_hash: SHA-256 hash of the skill bundle

    Returns:
        Cached findings if hash exists in database, None otherwise
    """
    # TODO: Implement Cloudflare D1 lookup
    # For now, return None (no cached findings)
    return None


def add_to_threat_db(bundle_hash: str, findings: List[Finding]) -> None:
    """
    Add CRITICAL/HIGH findings to community threat database.

    Args:
        bundle_hash: SHA-256 hash of the skill bundle
        findings: List of findings from scan
    """
    # Only add CRITICAL or HIGH findings
    critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    if not critical_high:
        return

    # TODO: Implement Cloudflare D1 insertion
    # For now, just log
    print(f"Would add {len(critical_high)} findings to threat DB for hash {bundle_hash}")


def query_cve_registry(file_content: str) -> List[Finding]:
    """
    Query CVE registry for known vulnerabilities in dependencies.

    Args:
        file_content: Content of requirements.txt or similar

    Returns:
        List of CVE-related findings
    """
    # TODO: Implement CVE registry lookup
    # For now, return empty list
    return []
