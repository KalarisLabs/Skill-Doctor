"""
HTML report generation.
"""

from pathlib import Path
from typing import Optional

from skill_doctor.models import ScanResult


def generate_html(result: ScanResult, output_path: Optional[Path] = None) -> str:
    """
    Generate HTML report from scan result.

    Args:
        result: ScanResult to convert to HTML
        output_path: Optional path to write HTML file

    Returns:
        HTML string
    """
    severity_colors = {
        "CRITICAL": "#dc2626",  # red
        "HIGH": "#ea580c",  # orange
        "MEDIUM": "#ca8a04",  # yellow
        "LOW": "#2563eb",  # blue
        "INFO": "#6b7280",  # gray
    }

    risk_colors = {
        "DANGEROUS": "#dc2626",
        "CAUTION": "#ca8a04",
        "SAFE": "#16a34a",
    }

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Skill Doctor Scan Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f9fafb;
        }}
        .header {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .risk-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 24px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid #ccc;
        }}
        .finding.CRITICAL {{ border-left-color: {severity_colors['CRITICAL']}; }}
        .finding.HIGH {{ border-left-color: {severity_colors['HIGH']}; }}
        .finding.MEDIUM {{ border-left-color: {severity_colors['MEDIUM']}; }}
        .finding.LOW {{ border-left-color: {severity_colors['LOW']}; }}
        .finding.INFO {{ border-left-color: {severity_colors['INFO']}; }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }}
        .remediation {{
            background: #f3f4f6;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🩺 Skill Doctor Scan Report</h1>
        <p>Bundle Hash: <code>{result.bundle_hash[:16]}...</code></p>
        <p>Scanned: {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p>Duration: {result.duration_ms / 1000:.2f}s</p>
        <p>Layers Run: {', '.join(result.layers_run)}</p>
        <p>
            Risk Level: <span class="risk-badge" style="background: {risk_colors[result.risk_level]}">{result.risk_level}</span>
        </p>
        <p>Risk Score: {result.risk_score:.1f} / 10.0</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Total Findings</h3>
            <p style="font-size: 32px; font-weight: bold;">{len(result.findings)}</p>
        </div>
"""

    # Add severity counts
    severity_counts = {}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            html += f"""
        <div class="summary-card">
            <h3>{severity}</h3>
            <p style="font-size: 32px; font-weight: bold; color: {severity_colors[severity]};">{count}</p>
        </div>
"""

    html += """
    </div>

    <h2>Findings</h2>
"""

    for finding in result.findings:
        html += f"""
    <div class="finding {finding.severity}">
        <span class="severity-badge" style="background: {severity_colors[finding.severity]}">{finding.severity}</span>
        <strong>{finding.category}</strong>
        <p style="margin: 10px 0;">
            <strong>File:</strong> {finding.file}
            {f' <strong>Line:</strong> {finding.line}' if finding.line else ''}
        </p>
        <p>{finding.description}</p>
        <p style="font-size: 12px; color: #6b7280;">
            Engine: {finding.engine} | Confidence: {finding.confidence:.0%}
        </p>
        <div class="remediation">
            <strong>Fix:</strong> {finding.remediation}
        </div>
    </div>
"""

    html += """
</body>
</html>
"""

    if output_path:
        output_path.write_text(html, encoding="utf-8")

    return html
