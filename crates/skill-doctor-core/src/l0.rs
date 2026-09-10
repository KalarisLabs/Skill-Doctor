//! L0 — intake, normalization, and canonical bundle digest.
//!
//! Accepts a directory path and produces:
//! 1. A sorted list of (relative_path, content) pairs.
//! 2. A SHA-256 canonical bundle digest over those sorted pairs.
//!
//! The digest is deterministic: files are visited in sorted order by path,
//! and the hash covers both paths and contents.

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive as TarArchive;
use thiserror::Error;
use walkdir::WalkDir;
use zip::ZipArchive;

/// Errors from L0 intake.
#[derive(Debug, Error)]
pub enum L0Error {
    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("walkdir error: {0}")]
    WalkDir(#[from] walkdir::Error),
    #[error("zip archive error: {0}")]
    Zip(String),
    #[error("tar archive error: {0}")]
    Tar(String),
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

/// Perform L0 intake on a directory, file, or archive (.zip / .tar.gz).
///
/// Walks the directory or unpacks the archive, sorts by relative path,
/// and computes a canonical SHA-256 digest.
pub fn intake(root: &Path) -> Result<Bundle, L0Error> {
    if !root.exists() {
        return Err(L0Error::PathNotFound(root.to_path_buf()));
    }

    let mut entries = Vec::new();

    if root.is_file() {
        let path_str = root.to_string_lossy().to_lowercase();
        if path_str.ends_with(".zip") {
            entries = read_zip_archive(root)?;
        } else if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            entries = read_tar_gz_archive(root)?;
        } else {
            let content = std::fs::read(root)?;
            entries.push(BundleEntry {
                relative_path: root
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("file")),
                content,
            });
        }
    } else {
        for entry in WalkDir::new(root)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !name.starts_with(".git")
                    && name != "target"
                    && name != "node_modules"
                    && name != "dist"
                    && name != ".DS_Store"
            })
        {
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

/// Maximum number of files allowed in an archive.
const MAX_ARCHIVE_FILES: usize = 1_000;

/// Maximum single uncompressed file size (10 MB).
const MAX_ARCHIVE_FILE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum total uncompressed archive size (50 MB).
const MAX_ARCHIVE_TOTAL_BYTES: usize = 50 * 1024 * 1024;

/// Maximum directory depth in archive path.
const MAX_PATH_DEPTH: usize = 10;

/// Validate archive path: reject absolute paths, `..` path traversal, drive letters, and excessive depth.
/// Returns normalized forward-slash PathBuf.
fn validate_archive_path(raw_name: &str) -> Result<PathBuf, L0Error> {
    let normalized = raw_name.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');

    if trimmed.is_empty() {
        return Err(L0Error::Zip("empty file path in archive".to_string()));
    }

    let components: Vec<&str> = trimmed.split('/').collect();

    if components.len() > MAX_PATH_DEPTH {
        return Err(L0Error::Zip(format!(
            "archive path exceeds max depth of {}: {}",
            MAX_PATH_DEPTH, raw_name
        )));
    }

    for comp in &components {
        if *comp == ".." || comp.contains(':') {
            return Err(L0Error::Zip(format!(
                "path traversal detected in archive entry: {}",
                raw_name
            )));
        }
    }

    Ok(PathBuf::from(trimmed))
}

/// Read all files from a ZIP archive with zip-bomb and path traversal defenses.
fn read_zip_archive(path: &Path) -> Result<Vec<BundleEntry>, L0Error> {
    let file = std::fs::File::open(path)?;
    let mut archive = ZipArchive::new(file).map_err(|e| L0Error::Zip(e.to_string()))?;
    let mut entries = Vec::new();
    let mut total_bytes: usize = 0;

    for i in 0..archive.len() {
        if entries.len() >= MAX_ARCHIVE_FILES {
            return Err(L0Error::Zip(format!(
                "archive exceeds max file count ({})",
                MAX_ARCHIVE_FILES
            )));
        }

        let mut file = archive
            .by_index(i)
            .map_err(|e| L0Error::Zip(e.to_string()))?;

        if file.is_file() {
            let relative_path = validate_archive_path(file.name())?;

            let mut content = Vec::new();
            let mut handle = std::io::Read::take(&mut file, (MAX_ARCHIVE_FILE_BYTES + 1) as u64);
            handle.read_to_end(&mut content)?;

            if content.len() > MAX_ARCHIVE_FILE_BYTES {
                return Err(L0Error::Zip(format!(
                    "archive entry '{}' exceeds max file size ({} bytes)",
                    relative_path.display(),
                    MAX_ARCHIVE_FILE_BYTES
                )));
            }

            total_bytes += content.len();
            if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
                return Err(L0Error::Zip(format!(
                    "archive exceeds total uncompressed byte limit ({} bytes)",
                    MAX_ARCHIVE_TOTAL_BYTES
                )));
            }

            entries.push(BundleEntry {
                relative_path,
                content,
            });
        }
    }
    Ok(entries)
}

/// Read all files from a tar.gz archive with zip-bomb and path traversal defenses.
fn read_tar_gz_archive(path: &Path) -> Result<Vec<BundleEntry>, L0Error> {
    let file = std::fs::File::open(path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = TarArchive::new(decoder);
    let mut entries = Vec::new();
    let mut total_bytes: usize = 0;

    for entry in archive.entries().map_err(|e| L0Error::Tar(e.to_string()))? {
        if entries.len() >= MAX_ARCHIVE_FILES {
            return Err(L0Error::Tar(format!(
                "archive exceeds max file count ({})",
                MAX_ARCHIVE_FILES
            )));
        }

        let mut entry = entry.map_err(|e| L0Error::Tar(e.to_string()))?;
        let header = entry.header();
        if header.entry_type().is_file() {
            let raw_path = entry
                .path()
                .map_err(|e| L0Error::Tar(e.to_string()))?
                .to_string_lossy()
                .into_owned();

            let relative_path =
                validate_archive_path(&raw_path).map_err(|e| L0Error::Tar(e.to_string()))?;

            let mut content = Vec::new();
            let mut handle = std::io::Read::take(&mut entry, (MAX_ARCHIVE_FILE_BYTES + 1) as u64);
            handle.read_to_end(&mut content)?;

            if content.len() > MAX_ARCHIVE_FILE_BYTES {
                return Err(L0Error::Tar(format!(
                    "archive entry '{}' exceeds max file size ({} bytes)",
                    relative_path.display(),
                    MAX_ARCHIVE_FILE_BYTES
                )));
            }

            total_bytes += content.len();
            if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
                return Err(L0Error::Tar(format!(
                    "archive exceeds total uncompressed byte limit ({} bytes)",
                    MAX_ARCHIVE_TOTAL_BYTES
                )));
            }

            entries.push(BundleEntry {
                relative_path,
                content,
            });
        }
    }
    Ok(entries)
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

    #[test]
    fn zip_archive_intake() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("skill.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("SKILL.md", options).unwrap();
        zip.write_all(b"# Test Skill in Zip").unwrap();
        zip.finish().unwrap();

        let bundle = intake(&zip_path).unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert_eq!(bundle.entries[0].relative_path, PathBuf::from("SKILL.md"));
        assert_eq!(bundle.entries[0].content, b"# Test Skill in Zip");
    }

    #[test]
    fn tar_gz_archive_intake() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("skill.tar.gz");
        let file = std::fs::File::create(&tar_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);

        let mut header = tar::Header::new_gnu();
        header.set_size(19);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "SKILL.md", &b"# Test Skill in Tar"[..])
            .unwrap();
        let enc = tar.into_inner().unwrap();
        enc.finish().unwrap();

        let bundle = intake(&tar_path).unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert_eq!(bundle.entries[0].relative_path, PathBuf::from("SKILL.md"));
        assert_eq!(bundle.entries[0].content, b"# Test Skill in Tar");
    }
}
