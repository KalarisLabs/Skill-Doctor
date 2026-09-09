//! L0 — intake, normalization, and canonical bundle digest.
//!
//! Accepts a directory path and produces:
//! 1. A sorted list of (relative_path, content) pairs.
//! 2. A SHA-256 canonical bundle digest over those sorted pairs.
//!
//! The digest is deterministic: files are visited in sorted order by path,
//! and the hash covers both paths and contents.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

/// Errors from L0 intake.
#[derive(Debug, Error)]
pub enum L0Error {
    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("walkdir error: {0}")]
    WalkDir(#[from] walkdir::Error),
}

/// A file entry in the normalized bundle.
#[derive(Debug, Clone)]
pub struct BundleEntry {
    /// Path relative to the scan root.
    pub relative_path: PathBuf,
    /// File contents.
    pub content: Vec<u8>,
}

/// The result of L0 intake: a normalized bundle with a canonical digest.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Sorted list of files in the bundle.
    pub entries: Vec<BundleEntry>,
    /// SHA-256 canonical bundle digest.
    pub digest: String,
}

/// Perform L0 intake on a directory.
///
/// Walks the directory, reads all files, sorts by relative path,
/// and computes a canonical SHA-256 digest.
pub fn intake(root: &Path) -> Result<Bundle, L0Error> {
    if !root.exists() {
        return Err(L0Error::PathNotFound(root.to_path_buf()));
    }

    let mut entries = Vec::new();

    if root.is_file() {
        let content = std::fs::read(root)?;
        entries.push(BundleEntry {
            relative_path: root
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("file")),
            content,
        });
    } else {
        for entry in WalkDir::new(root).sort_by_file_name().into_iter() {
            let entry = entry?;
            if entry.file_type().is_file() {
                let relative_path = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(entry.path())
                    .to_path_buf();
                let content = std::fs::read(entry.path())?;
                entries.push(BundleEntry {
                    relative_path,
                    content,
                });
            }
        }
    }

    // Sort by relative path for determinism (walkdir sort_by_file_name
    // handles this per-directory, but we sort the full list to be safe).
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    // Compute canonical SHA-256 digest over sorted (path, content) pairs.
    let digest = compute_digest(&entries);

    Ok(Bundle { entries, digest })
}

/// Compute the canonical SHA-256 digest of a sorted bundle.
fn compute_digest(entries: &[BundleEntry]) -> String {
    let mut hasher = Sha256::new();
    for entry in entries {
        // Hash the path as UTF-8 with forward slashes for cross-platform determinism.
        let normalized_path = entry.relative_path.to_string_lossy().replace('\\', "/");
        hasher.update(normalized_path.as_bytes());
        hasher.update(b"\x00"); // null separator
                                // Hash the content length as a fixed-size prefix to prevent ambiguity.
        hasher.update(entry.content.len().to_le_bytes());
        hasher.update(&entry.content);
    }
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn digest_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.md"), "hello").unwrap();
        fs::write(dir.path().join("b.txt"), "world").unwrap();

        let bundle1 = intake(dir.path()).unwrap();
        let bundle2 = intake(dir.path()).unwrap();

        assert_eq!(bundle1.digest, bundle2.digest);
        assert!(!bundle1.digest.is_empty());
    }

    #[test]
    fn digest_changes_with_content() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.md"), "hello").unwrap();
        let bundle1 = intake(dir.path()).unwrap();

        fs::write(dir.path().join("a.md"), "world").unwrap();
        let bundle2 = intake(dir.path()).unwrap();

        assert_ne!(bundle1.digest, bundle2.digest);
    }

    #[test]
    fn single_file_intake() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.md");
        fs::write(&file, "# Hello").unwrap();

        let bundle = intake(&file).unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(!bundle.digest.is_empty());
    }

    #[test]
    fn nonexistent_path_errors() {
        let result = intake(Path::new("/nonexistent/path/xyz"));
        assert!(result.is_err());
    }
}
