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
    findings = []

    # Locate rules directory relative to this package
    rules_dir = Path(__file__).parent.parent / "rules" / "core"
    if not rules_dir.exists():
        return findings

    try:
        import yara_x

        # Compile all YARA rule files
        compiler = yara_x.Compiler()
        rule_files = sorted(rules_dir.glob("*.yar"))
        if not rule_files:
            return findings

        for rule_file in rule_files:
            try:
                compiler.add_source(rule_file.read_text(encoding="utf-8"))
            except Exception:
                continue

        rules = compiler.build()

        # Scan each text file in the bundle
        for file_path in bundle_dir.rglob("*"):
            if file_path.is_file() and _is_text_file(file_path):
                try:
                    data = file_path.read_bytes()
                    scan_results = rules.scan(data)

                    for matching_rule in scan_results.matching_rules:
                        # Extract metadata from rule — yara_x returns tuples (key, value)
                        metadata = {k: v for k, v in matching_rule.metadata}
                        severity = metadata.get("severity", "MEDIUM")
                        category = metadata.get("category", matching_rule.identifier)
                        description = metadata.get("description", f"YARA rule matched: {matching_rule.identifier}")

                        findings.append(
                            Finding(
                                severity=severity,
                                category=category,
                                file=str(file_path.relative_to(bundle_dir)),
                                line=None,
                                description=description,
                                remediation=f"Review content flagged by rule '{matching_rule.identifier}'",
                                engine="yara",
                                confidence=0.85,
                            )
                        )
                except Exception:
                    continue

    except ImportError:
        # yara_x not available — skip silently
        pass

    return findings


def _scan_python_ast(bundle_dir: Path) -> List[Finding]:
    """Scan Python files with AST analysis for dangerous patterns."""
    import ast as python_ast

    findings = []

    # Dangerous function patterns to detect
    dangerous_calls = {
        "subprocess.run": ("HIGH", "SD-02 · Command Injection", "Command execution via subprocess.run"),
        "subprocess.call": ("HIGH", "SD-02 · Command Injection", "Command execution via subprocess.call"),
        "subprocess.Popen": ("HIGH", "SD-02 · Command Injection", "Command execution via subprocess.Popen"),
        "os.system": ("CRITICAL", "SD-02 · Command Injection", "Shell command execution via os.system"),
        "os.popen": ("HIGH", "SD-02 · Command Injection", "Shell command execution via os.popen"),
        "eval": ("CRITICAL", "SD-02 · Command Injection", "Dynamic code execution via eval()"),
        "exec": ("CRITICAL", "SD-02 · Command Injection", "Dynamic code execution via exec()"),
        "pickle.loads": ("HIGH", "SD-02 · Command Injection", "Arbitrary code execution via pickle deserialization"),
        "requests.post": ("MEDIUM", "SD-03 · Data Exfiltration", "Outbound HTTP POST — potential data exfiltration"),
        "requests.get": ("LOW", "SD-03 · Data Exfiltration", "Outbound HTTP GET — review for data leakage"),
        "httpx.post": ("MEDIUM", "SD-03 · Data Exfiltration", "Outbound HTTP POST — potential data exfiltration"),
        "urllib.request.urlopen": ("MEDIUM", "SD-03 · Data Exfiltration", "Outbound HTTP request — potential data exfiltration"),
    }

    # Dangerous attribute access patterns
    dangerous_attrs = {
        "os.environ": ("MEDIUM", "SD-03 · Data Exfiltration", "Environment variable access — may harvest secrets"),
    }

    for file_path in bundle_dir.rglob("*.py"):
        if not file_path.is_file():
            continue
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = python_ast.parse(source, filename=str(file_path))
        except (SyntaxError, Exception):
            continue

        rel_path = str(file_path.relative_to(bundle_dir))

        for node in python_ast.walk(tree):
            # Check function calls
            if isinstance(node, python_ast.Call):
                func_name = _get_call_name(node)
                if func_name in dangerous_calls:
                    severity, category, desc = dangerous_calls[func_name]

                    # Boost severity if shell=True is used
                    if func_name.startswith("subprocess."):
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, python_ast.Constant) and kw.value.value is True:
                                severity = "CRITICAL"
                                desc += " with shell=True"

                    findings.append(
                        Finding(
                            severity=severity,
                            category=category,
                            file=rel_path,
                            line=node.lineno,
                            description=desc,
                            remediation=f"Avoid {func_name} or sanitize inputs; use allowlists for commands",
                            engine="ast",
                            confidence=0.9,
                        )
                    )

            # Check attribute access (e.g., os.environ.get)
            if isinstance(node, python_ast.Attribute):
                attr_chain = _get_attr_chain(node)
                for pattern, (severity, category, desc) in dangerous_attrs.items():
                    if attr_chain.startswith(pattern):
                        findings.append(
                            Finding(
                                severity=severity,
                                category=category,
                                file=rel_path,
                                line=node.lineno,
                                description=desc,
                                remediation="Do not access environment variables unless strictly necessary for the skill's stated purpose",
                                engine="ast",
                                confidence=0.8,
                            )
                        )
                        break

    return findings


def _get_call_name(node) -> str:
    """Extract dotted function name from a Call node."""
    import ast as python_ast

    if isinstance(node.func, python_ast.Name):
        return node.func.id
    elif isinstance(node.func, python_ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, python_ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, python_ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _get_attr_chain(node) -> str:
    """Extract dotted attribute chain from an Attribute node."""
    import ast as python_ast

    parts = []
    current = node
    while isinstance(current, python_ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, python_ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


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
