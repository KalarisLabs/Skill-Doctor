"""
SARIF 2.1 report generation.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from skill_doctor.models import ScanResult


def generate_sarif(result: ScanResult, output_path: Optional[Path] = None) -> str:
    """
    Generate SARIF 2.1 report from scan result.

    Args:
        result: ScanResult to convert to SARIF
        output_path: Optional path to write SARIF file

    Returns:
        SARIF JSON string
    """
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Skill Doctor",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/KalarisLabs/Skill-Doctor",
                        "rules": [
                            {
                                "id": f.category,
                                "name": f.category,
                                "shortDescription": {"text": f.description},
                                "help": {"text": f.remediation},
                            }
                            for f in result.findings
                        ],
                    }
                },
                "invocations": [
                    {
                        "startTimeUtc": result.scanned_at.isoformat(),
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        "exitCode": 0 if result.risk_level == "SAFE" else 1,
                    }
                ],
                "results": [
                    {
                        "ruleId": finding.category,
                        "level": _map_severity_to_level(finding.severity),
                        "message": {"text": finding.description},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.file},
                                    "region": (
                                        {"startLine": finding.line} if finding.line else {}
                                    ),
                                }
                            }
                        ],
                        "properties": {
                            "confidence": finding.confidence,
                            "engine": finding.engine,
                        },
                    }
                    for finding in result.findings
                ],
            }
        ],
    }

    sarif_json = json.dumps(sarif, indent=2)

    if output_path:
        output_path.write_text(sarif_json, encoding="utf-8")

    return sarif_json


def _map_severity_to_level(severity: str) -> str:
    """Map Finding severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity, "note")
