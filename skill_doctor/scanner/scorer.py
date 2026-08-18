"""
Scoring module - merge and score findings from all layers.
"""

from typing import List
from collections import Counter

from skill_doctor.models import Finding, ScanResult
import time


def score_findings(
    all_findings: List[Finding],
    bundle_hash: str,
    layers_run: List[str],
    duration_ms: int,
) -> ScanResult:
    """
    Merge, deduplicate, and score findings from all layers.

    Args:
        all_findings: Findings from all scan layers
        bundle_hash: SHA-256 hash of the skill bundle
        layers_run: List of layer names that were executed
        duration_ms: Total scan duration in milliseconds

    Returns:
        Complete ScanResult with risk level and score
    """
    # Deduplicate findings (same category + file ≈ same issue)
    deduplicated = _deduplicate_findings(all_findings)

    # Calculate risk score
    risk_score = _calculate_risk_score(deduplicated, layers_run)

    # Determine risk level
    risk_level = _determine_risk_level(deduplicated, risk_score)

    return ScanResult(
        bundle_hash=bundle_hash,
        duration_ms=duration_ms,
        findings=deduplicated,
        risk_level=risk_level,
        risk_score=risk_score,
        layers_run=layers_run,
    )


def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate findings based on category and file."""
    seen = set()
    deduplicated = []

    for finding in findings:
        key = (finding.category, finding.file, finding.line)
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
        else:
            # If duplicate, keep the one with higher confidence
            existing = next(f for f in deduplicated if (f.category, f.file, f.line) == key)
            if finding.confidence > existing.confidence:
                deduplicated.remove(existing)
                deduplicated.append(finding)

    return deduplicated


def _calculate_risk_score(findings: List[Finding], layers_run: List[str]) -> float:
    """
    Calculate overall risk score (0.0–10.0).

    Scoring factors:
    - Severity weights: CRITICAL=9.0, HIGH=7.0, MEDIUM=4.0, LOW=1.0, INFO=0.0
    - Confidence multiplier
    - Cross-layer corroboration bonus
    """
    if not findings:
        return 0.0

    severity_weights = {
        "CRITICAL": 9.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 1.0,
        "INFO": 0.0,
    }

    # Base score from severity weights
    base_score = sum(severity_weights.get(f.severity, 0.0) * f.confidence for f in findings)

    # Normalize to 0-10 range (cap at 10.0)
    normalized_score = min(base_score, 10.0)

    # Cross-layer corroboration bonus
    # If same finding type appears from multiple engines, boost confidence
    engine_counts = Counter(f.engine for f in findings)
    corroboration_bonus = sum(count - 1 for count in engine_counts.values() if count > 1) * 0.5

    return min(normalized_score + corroboration_bonus, 10.0)


def _determine_risk_level(findings: List[Finding], risk_score: float) -> str:
    """Determine risk level based on findings and score."""
    # Check for CRITICAL findings
    if any(f.severity == "CRITICAL" for f in findings):
        return "DANGEROUS"

    # Check for HIGH findings
    if any(f.severity == "HIGH" for f in findings):
        return "CAUTION"

    # Use risk score thresholds
    if risk_score >= 7.0:
        return "DANGEROUS"
    elif risk_score >= 4.0:
        return "CAUTION"
    else:
        return "SAFE"
