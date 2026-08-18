"""
Layer 1: Static Analysis - YARA-X + Python AST + Entropy + Unicode.
"""

from pathlib import Path
from typing import List
import math
import re

from skill_doctor.models import Finding


def scan_static(bundle_dir: Path) -> List[Finding]:
    """
    Run static analysis on skill bundle.

    Args:
        bundle_dir: Path to normalized skill bundle

    Returns:
        List of findings from static analysis
    """
    findings = []

    # YARA-X pattern matching
    findings.extend(_scan_yara(bundle_dir))

    # Python AST analysis
    findings.extend(_scan_python_ast(bundle_dir))

    # Entropy analysis
    findings.extend(_scan_entropy(bundle_dir))

    # Unicode analysis
    findings.extend(_scan_unicode(bundle_dir))

    return findings


def _scan_yara(bundle_dir: Path) -> List[Finding]:
    """Scan with YARA-X rules."""
    # TODO: Implement YARA-X rule loading and scanning
    # For now, return empty list
    return []


def _scan_python_ast(bundle_dir: Path) -> List[Finding]:
    """Scan Python files with tree-sitter AST analysis."""
    # TODO: Implement tree-sitter Python grammar and taint analysis
    # For now, return empty list
    return []


def _scan_entropy(bundle_dir: Path) -> List[Finding]:
    """Scan for high-entropy regions indicating encoded payloads."""
    findings = []
    entropy_threshold = 5.5

    for file_path in bundle_dir.rglob("*"):
        if file_path.is_file() and _is_text_file(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Check entropy in chunks
                for i in range(0, len(content), 1024):
                    chunk = content[i : i + 1024]
                    if len(chunk) < 64:  # Skip very small chunks
                        continue

                    entropy = _calculate_entropy(chunk)
                    if entropy > entropy_threshold:
                        findings.append(
                            Finding(
                                severity="MEDIUM",
                                category="SD-10 · Obfuscation and Evasion",
                                file=str(file_path.relative_to(bundle_dir)),
                                line=None,
                                description=f"High entropy ({entropy:.2f}) detected, possibly indicating encoded content",
                                remediation="Review this section for base64, hex, or other encoded payloads",
                                engine="entropy",
                                confidence=0.7,
                            )
                        )
                        break  # One finding per file is sufficient
            except Exception:
                continue

    return findings


def _scan_unicode(bundle_dir: Path) -> List[Finding]:
    """Scan for suspicious Unicode characters."""
    findings = []

    # Zero-width characters
    zero_width_pattern = re.compile(
        r"[\u200B\u200C\u200D\uFEFF]"
    )  # Zero-width space, non-joiner, joiner, BOM

    # RTL override
    rtl_pattern = re.compile(r"\u202E")  # Right-to-left override

    for file_path in bundle_dir.rglob("*"):
        if file_path.is_file() and _is_text_file(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.split("\n")

                for line_num, line in enumerate(lines, 1):
                    # Check for zero-width characters
                    zero_width_matches = zero_width_pattern.findall(line)
                    if zero_width_matches:
                        findings.append(
                            Finding(
                                severity="HIGH",
                                category="SD-01 · Prompt Injection (ASCII Smuggling)",
                                file=str(file_path.relative_to(bundle_dir)),
                                line=line_num,
                                description=f"Zero-width Unicode characters detected: {len(zero_width_matches)} instances",
                                remediation="Strip all non-printable Unicode characters from skill content",
                                engine="unicode",
                                confidence=0.9,
                            )
                        )

                    # Check for RTL override
                    rtl_matches = rtl_pattern.findall(line)
                    if rtl_matches:
                        findings.append(
                            Finding(
                                severity="MEDIUM",
                                category="SD-10 · Obfuscation and Evasion",
                                file=str(file_path.relative_to(bundle_dir)),
                                line=line_num,
                                description="RTL override character detected, can be used for obfuscation",
                                remediation="Remove RTL override characters or verify they are legitimate",
                                engine="unicode",
                                confidence=0.6,
                            )
                        )
            except Exception:
                continue

    return findings


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0

    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)

    return entropy


def _is_text_file(file_path: Path) -> bool:
    """Check if file is likely a text file."""
    text_extensions = {
        ".md",
        ".txt",
        ".py",
        ".js",
        ".ts",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".sh",
        ".bash",
        ".zsh",
    }
    return file_path.suffix.lower() in text_extensions
