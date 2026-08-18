"""
Intake and normalization module for skill bundles.
"""

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
    if source_str.startswith(("http://", "https://", "git://", "github.com/")):
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
        elif source_path.suffix in (".md", ".txt"):
            return _normalize_single_file(source_path)
        else:
            raise ValueError(f"Unsupported file type: {source_path.suffix}")
    elif source_path.is_dir():
        return _normalize_directory(source_path)
    else:
        raise ValueError(f"Unsupported source type: {source_str}")


def _normalize_zip(zip_path: Path) -> tuple[Path, str]:
    """Extract and normalize a ZIP archive."""
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_doctor_"))
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(temp_dir)
    return temp_dir, _compute_hash(temp_dir)


def _normalize_tar(tar_path: Path) -> tuple[Path, str]:
    """Extract and normalize a tar.gz archive."""
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_doctor_"))
    with tarfile.open(tar_path, "r:gz") as tf:
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
    # TODO: Implement Git URL cloning and HTTP URL downloading
    raise NotImplementedError("URL normalization not yet implemented")


def _compute_hash(directory: Path) -> str:
    """Compute SHA-256 hash of all files in directory."""
    sha256 = hashlib.sha256()
    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file():
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
    return sha256.hexdigest()
