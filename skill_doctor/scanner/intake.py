"""
Intake and normalization module for skill bundles.
"""

import os
from pathlib import Path
from typing import Union
import hashlib
import tempfile
import shutil
import zipfile
import tarfile
from urllib.parse import urlparse
import httpx


def normalize_bundle(source: Union[str, Path]) -> tuple[Path, str]:
    """
    Normalize various input formats into a flat bundle directory.

    Args:
        source: Path to file/directory, Git URL, or HTTP URL

    Returns:
        Tuple of (normalized directory path, SHA-256 bundle hash)
    """
    source_str = str(source)

    # Handle URLs
    if source_str.startswith(("http://", "https://", "git://", "github.com/")) or ("/" in source_str and not Path(source_str).exists() and not source_str.startswith((".", "/", "\\")) and ":" not in source_str[2:]):
        if not source_str.startswith(("http://", "https://", "git://")):
            source_str = "https://" + source_str
        return _normalize_from_url(source_str)

    # Handle local paths
    source_path = Path(source_str)
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source_str}")

    if source_path.is_file():
        if source_path.suffix == ".zip":
            return _normalize_zip(source_path)
        elif source_path.suffix in (".tar.gz", ".tgz"):
            return _normalize_tar(source_path)
        elif source_path.suffix in (
            ".md", ".txt", ".py", ".js", ".ts", ".json",
            ".yaml", ".yml", ".toml", ".cfg", ".ini",
            ".sh", ".bash", ".zsh", ".clauderules",
        ):
            return _normalize_single_file(source_path)
        else:
            raise ValueError(f"Unsupported file type: {source_path.suffix}")
    elif source_path.is_dir():
        return _normalize_directory(source_path)
    else:
        raise ValueError(f"Unsupported source type: {source_str}")


def _normalize_zip(zip_path: Path) -> tuple[Path, str]:
    """Extract and normalize a ZIP archive (with zip-slip protection)."""
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_doctor_"))
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            # Resolve the target path and verify it stays within temp_dir
            target_path = (temp_dir / member).resolve()
            if not str(target_path).startswith(str(temp_dir.resolve())):
                raise ValueError(
                    f"Zip-slip detected: '{member}' would extract outside the target directory. "
                    "This archive may be malicious."
                )
        zf.extractall(temp_dir)
    return temp_dir, _compute_hash(temp_dir)


def _normalize_tar(tar_path: Path) -> tuple[Path, str]:
    """Extract and normalize a tar.gz archive (with tar-slip protection)."""
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_doctor_"))
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            # Resolve the target path and verify it stays within temp_dir
            target_path = (temp_dir / member.name).resolve()
            if not str(target_path).startswith(str(temp_dir.resolve())):
                raise ValueError(
                    f"Tar-slip detected: '{member.name}' would extract outside the target directory. "
                    "This archive may be malicious."
                )
            # Block symlinks pointing outside temp_dir
            if member.issym() or member.islnk():
                link_target = (temp_dir / member.linkname).resolve()
                if not str(link_target).startswith(str(temp_dir.resolve())):
                    raise ValueError(
                        f"Tar-slip via symlink detected: '{member.name}' -> '{member.linkname}'. "
                        "This archive may be malicious."
                    )
        tf.extractall(temp_dir)
    return temp_dir, _compute_hash(temp_dir)


def _normalize_single_file(file_path: Path) -> tuple[Path, str]:
    """Normalize a single skill file into a bundle."""
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_doctor_"))
    dest = temp_dir / file_path.name
    shutil.copy2(file_path, dest)
    return temp_dir, _compute_hash(temp_dir)


def _normalize_directory(dir_path: Path) -> tuple[Path, str]:
    """Normalize a directory (use as-is, just compute hash)."""
    return dir_path, _compute_hash(dir_path)


def _normalize_from_url(url: str) -> tuple[Path, str]:
    """Download and normalize from a URL."""
    try:
        response = httpx.get(url, follow_redirects=True)
        response.raise_for_status()
    except Exception as e:
        raise ValueError(f"Failed to download URL: {url}\n{e}")

    filename = Path(urlparse(url).path).name
    if not filename:
        filename = "downloaded_skill.txt"

    # Write directly into the bundle temp directory (no leaked temp file)
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_doctor_"))
    dest = temp_dir / filename
    dest.write_bytes(response.content)

    return temp_dir, _compute_hash(temp_dir)


def _compute_hash(directory: Path) -> str:
    """Compute SHA-256 hash of all files in directory."""
    sha256 = hashlib.sha256()
    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file():
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
    return sha256.hexdigest()
