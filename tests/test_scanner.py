"""
Tests for Skill Doctor scanner modules.
"""

import pytest
from pathlib import Path

from skill_doctor.scanner.intake import normalize_bundle
from skill_doctor.scanner.layer1_static import scan_static
from skill_doctor.models import Finding


def test_normalize_single_file():
    """Test normalizing a single skill file."""
    fixture_path = Path(__file__).parent / "fixtures" / "clean_formatter.md"
    bundle_dir, bundle_hash = normalize_bundle(fixture_path)

    assert bundle_dir.exists()
    assert len(bundle_hash) == 64  # SHA-256 hex length


def test_scan_static_clean_skill():
    """Test static analysis on a clean skill."""
    fixture_path = Path(__file__).parent / "fixtures" / "clean_formatter.md"
    bundle_dir, _ = normalize_bundle(fixture_path)

    findings = scan_static(bundle_dir)

    # Clean skill should have minimal findings (maybe INFO level)
    critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(critical_high) == 0, f"Clean skill should have no CRITICAL/HIGH findings, got {critical_high}"


def test_scan_static_evil_exfil():
    """Test static analysis on skill with data exfiltration pattern."""
    fixture_path = Path(__file__).parent / "fixtures" / "evil_exfil.md"
    bundle_dir, _ = normalize_bundle(fixture_path)

    findings = scan_static(bundle_dir)

    # Should detect sensitive path access
    sensitive_path_findings = [f for f in findings if "credential" in f.description.lower() or "aws" in f.description.lower()]
    assert len(sensitive_path_findings) > 0, "Should detect credential references"


def test_scan_static_evil_inject():
    """Test static analysis on skill with Unicode smuggling."""
    fixture_path = Path(__file__).parent / "fixtures" / "evil_inject.md"
    bundle_dir, _ = normalize_bundle(fixture_path)

    findings = scan_static(bundle_dir)

    # Should detect zero-width characters
    unicode_findings = [f for f in findings if "unicode" in f.category.lower() or "zero-width" in f.description.lower()]
    assert len(unicode_findings) > 0, "Should detect zero-width Unicode characters"


def test_scan_static_evil_companion():
    """Test static analysis on skill with malicious companion script."""
    fixture_path = Path(__file__).parent / "fixtures" / "evil_companion.py"
    bundle_dir, _ = normalize_bundle(fixture_path)

    findings = scan_static(bundle_dir)

    # Should detect dangerous functions (subprocess, os.environ, requests)
    dangerous_findings = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(dangerous_findings) > 0, "Should detect dangerous patterns in companion script"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
