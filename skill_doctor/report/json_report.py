"""
JSON report generation.
"""

import json
from pathlib import Path
from typing import Optional

from skill_doctor.models import ScanResult


def generate_json(result: ScanResult, output_path: Optional[Path] = None) -> str:
    """
    Generate JSON report from scan result.

    Args:
        result: ScanResult to convert to JSON
        output_path: Optional path to write JSON file

    Returns:
        JSON string
    """
    report = {
        "scan_id": result.scan_id,
        "bundle_hash": result.bundle_hash,
        "scanned_at": result.scanned_at.isoformat(),
        "duration_ms": result.duration_ms,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "layers_run": result.layers_run,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "category": f.category,
                "file": f.file,
                "line": f.line,
                "description": f.description,
                "remediation": f.remediation,
                "engine": f.engine,
                "confidence": f.confidence,
            }
            for f in result.findings
        ],
    }

    json_str = json.dumps(report, indent=2)

    if output_path:
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
